"""
REST client for the separate "Real-Time Phishing URL Collection & Threat
Intelligence API" service (referred to here as the threat-intel API).

This module only talks HTTP, validates responses and normalises them into
ThreatIntelRecord objects. It contains no scoring logic (see api_provider.py)
and no collection logic (that lives in the other service).

Contract used (from the threat-intel API's own implementation):

    GET /api/health                       {"success": true, "data": {"status", "database", ...}}
    GET /api/urls/lookup?url=<url>        {"success": true, "data": {"found", "normalized_url", "record"}}
    GET /api/urls?hostname=<h>&limit=<n>  {"success": true, "count", "pagination", "data": [url, ...]}
    GET /api/urls/latest?limit=&page=     same list envelope
    errors                                {"success": false, "error": {"code", "message"}}

Authentication: optional `X-API-Key` header (the service's READ_API_KEYS).

Every failure is raised as a ThreatIntelError subclass with a message that is
safe to show to users: it never contains the API key.
"""

import json
import logging
from dataclasses import asdict, dataclass, field

import requests

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 5 * 1024 * 1024


# ── Errors ───────────────────────────────────────────────────────────────

class ThreatIntelError(Exception):
    """Base class. `kind` is a stable short code for the API/UI."""
    kind = "error"


class ThreatIntelUnavailable(ThreatIntelError):
    kind = "unavailable"


class ThreatIntelTimeout(ThreatIntelUnavailable):
    kind = "timeout"


class ThreatIntelAuthError(ThreatIntelError):
    kind = "auth_failed"


class ThreatIntelRateLimited(ThreatIntelError):
    kind = "rate_limited"


class ThreatIntelInvalidResponse(ThreatIntelError):
    kind = "invalid_response"


class ThreatIntelHTTPError(ThreatIntelError):
    kind = "http_error"

    def __init__(self, message, status_code=None, code=None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


# ── Normalised data ──────────────────────────────────────────────────────

@dataclass
class Sighting:
    """What one upstream feed reported about the URL (only fields it provided)."""
    source: str
    threat_type: str | None = None
    confidence: float | None = None
    status: str | None = None
    tags: list = field(default_factory=list)
    source_first_seen: str | None = None
    last_collected_at: str | None = None
    source_reference: str | None = None


@dataclass
class ThreatIntelRecord:
    id: int
    url: str
    hostname: str
    domain: str | None = None
    sources: list = field(default_factory=list)
    threat_type: str | None = None
    threat_types: list = field(default_factory=list)
    confidence: float | None = None       # only if a feed published one
    status: str | None = None
    tags: list = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    created_at: str | None = None
    sightings: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class LookupResult:
    found: bool
    normalized_url: str | None
    record: ThreatIntelRecord | None
    # Set when the service could not check this URL (it rejects e.g. private IPs).
    not_checkable_reason: str | None = None


@dataclass
class Page:
    items: list
    total: int
    page: int
    limit: int
    has_next: bool
    skipped_invalid: int = 0


# ── Validation helpers ───────────────────────────────────────────────────

def _opt_str(v):
    return v if isinstance(v, str) and v else None


def _str_list(v):
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _opt_conf(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v) if 0.0 <= v <= 1.0 else None


def parse_record(obj):
    """Validate one URL object from the API. Raises ThreatIntelInvalidResponse."""
    if not isinstance(obj, dict):
        raise ThreatIntelInvalidResponse("URL record is not a JSON object")
    rid, url, host = obj.get("id"), obj.get("url"), obj.get("hostname")
    if isinstance(rid, bool) or not isinstance(rid, int) or not isinstance(url, str) or not url \
            or not isinstance(host, str) or not host:
        raise ThreatIntelInvalidResponse("URL record is missing id, url or hostname")
    sightings = []
    for s in obj.get("sightings") or []:
        if isinstance(s, dict) and isinstance(s.get("source"), str):
            sightings.append(Sighting(
                source=s["source"], threat_type=_opt_str(s.get("threat_type")),
                confidence=_opt_conf(s.get("confidence")), status=_opt_str(s.get("status")),
                tags=_str_list(s.get("tags")), source_first_seen=_opt_str(s.get("source_first_seen")),
                last_collected_at=_opt_str(s.get("last_collected_at")),
                source_reference=_opt_str(s.get("source_reference"))))
    return ThreatIntelRecord(
        id=rid, url=url, hostname=host, domain=_opt_str(obj.get("domain")),
        sources=_str_list(obj.get("sources")), threat_type=_opt_str(obj.get("threat_type")),
        threat_types=_str_list(obj.get("threat_types")), confidence=_opt_conf(obj.get("confidence")),
        status=_opt_str(obj.get("status")), tags=_str_list(obj.get("tags")),
        first_seen=_opt_str(obj.get("first_seen")), last_seen=_opt_str(obj.get("last_seen")),
        created_at=_opt_str(obj.get("created_at")), sightings=sightings,
    )


def _parse_page(body):
    data, pag = body.get("data"), body.get("pagination")
    if not isinstance(data, list) or not isinstance(pag, dict):
        raise ThreatIntelInvalidResponse("List response is missing 'data' or 'pagination'")
    items, skipped = [], 0
    for obj in data:
        try:
            items.append(parse_record(obj))
        except ThreatIntelInvalidResponse:
            skipped += 1
    if skipped:
        log.warning("Threat-intel API returned %d malformed record(s); they were ignored", skipped)

    def _int(k, default):
        v = pag.get(k)
        return v if isinstance(v, int) and not isinstance(v, bool) else default

    return Page(items=items, total=_int("total", len(items)), page=_int("page", 1),
                limit=_int("limit", len(items)), has_next=pag.get("has_next") is True, skipped_invalid=skipped)


# ── Client ───────────────────────────────────────────────────────────────

class ThreatIntelClient:
    def __init__(self, base_url, api_key=None, timeout=5.0, session=None):
        if not base_url or not base_url.startswith(("http://", "https://")):
            raise ValueError("THREAT_INTEL_API_URL must start with http:// or https://")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session or requests.Session()
        self._headers = {"Accept": "application/json", "User-Agent": "PhishShield-X/2.1 threat-intel-client"}
        if api_key:
            self._headers["X-API-Key"] = api_key

    def _get(self, path, params=None):
        """GET a path and return the decoded success envelope (a dict)."""
        url = self.base_url + path
        try:
            resp = self._session.get(url, params=params, headers=self._headers, timeout=self.timeout,
                                     allow_redirects=False, stream=True)
        except requests.Timeout:
            raise ThreatIntelTimeout(f"Threat-intel API did not respond within {self.timeout:g} s") from None
        except requests.ConnectionError:
            raise ThreatIntelUnavailable("Threat-intel API is not reachable (connection failed)") from None
        except requests.RequestException as e:
            raise ThreatIntelUnavailable(f"Threat-intel API request failed ({type(e).__name__})") from None

        chunks, size = [], 0
        try:
            for chunk in resp.iter_content(65536):
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ThreatIntelInvalidResponse("Threat-intel API response is too large")
                chunks.append(chunk)
        except requests.Timeout:
            raise ThreatIntelTimeout(f"Threat-intel API did not finish responding within {self.timeout:g} s") from None
        except (requests.RequestException, OSError):
            raise ThreatIntelUnavailable("Threat-intel API connection broke while reading the response") from None
        finally:
            resp.close()
        raw = b"".join(chunks)

        status = resp.status_code
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = None
        err = body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), dict) else {}
        code, message = err.get("code"), err.get("message")

        if status in (401, 403):
            raise ThreatIntelAuthError("Threat-intel API rejected the request; check THREAT_INTEL_API_KEY")
        if status == 429:
            raise ThreatIntelRateLimited("Threat-intel API rate limit reached; retry later")
        if status >= 500:
            raise ThreatIntelUnavailable(f"Threat-intel API error (HTTP {status}"
                                         f"{', ' + code if isinstance(code, str) else ''})")
        if 300 <= status < 400:
            raise ThreatIntelInvalidResponse(f"Threat-intel API answered with a redirect (HTTP {status})")
        if status >= 400:
            raise ThreatIntelHTTPError(f"Threat-intel API returned HTTP {status}"
                                       f"{': ' + message if isinstance(message, str) else ''}",
                                       status_code=status, code=code if isinstance(code, str) else None)
        if not isinstance(body, dict):
            raise ThreatIntelInvalidResponse("Threat-intel API returned a non-JSON or non-object response")
        if body.get("success") is not True or "data" not in body:
            raise ThreatIntelInvalidResponse("Threat-intel API response is missing 'success: true' / 'data'")
        return body

    # ── Endpoints ────────────────────────────────────────────────────────

    def health(self):
        data = self._get("/api/health")["data"]
        if not isinstance(data, dict) or not isinstance(data.get("status"), str):
            raise ThreatIntelInvalidResponse("Health response has no status")
        return data

    def lookup_url(self, url):
        """Exact lookup (the service normalises the URL itself)."""
        try:
            data = self._get("/api/urls/lookup", {"url": url})["data"]
        except ThreatIntelHTTPError as e:
            if e.status_code == 422 and e.code == "invalid_url":
                # The service only stores public http(s) URLs; this one cannot be listed there.
                return LookupResult(found=False, normalized_url=None, record=None, not_checkable_reason=str(e))
            raise
        if not isinstance(data, dict) or not isinstance(data.get("found"), bool):
            raise ThreatIntelInvalidResponse("Lookup response has no 'found' flag")
        record = parse_record(data["record"]) if data["found"] else None
        if data["found"] and record is None:
            raise ThreatIntelInvalidResponse("Lookup says found but has no record")
        return LookupResult(found=data["found"], normalized_url=_opt_str(data.get("normalized_url")), record=record)

    def urls_for_hostname(self, hostname, limit=5):
        try:
            return _parse_page(self._get("/api/urls", {"hostname": hostname, "limit": limit, "sort": "-last_seen"}))
        except ThreatIntelHTTPError as e:
            if e.status_code == 422:  # hostname the service does not accept (e.g. private IP)
                return Page(items=[], total=0, page=1, limit=limit, has_next=False)
            raise

    def latest(self, limit=20, page=1, source=None, threat_type=None, since=None):
        params = {"limit": limit, "page": page}
        for k, v in (("source", source), ("threat_type", threat_type), ("since", since)):
            if v:
                params[k] = v
        return _parse_page(self._get("/api/urls/latest", params))
