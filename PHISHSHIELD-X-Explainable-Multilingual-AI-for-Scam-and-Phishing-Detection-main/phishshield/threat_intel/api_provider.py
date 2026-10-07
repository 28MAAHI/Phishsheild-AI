"""
ThreatIntelProvider backed by the threat-intel API service (see threat_intel_client.py).

Evidence policy: how a threat-intel API record becomes a ThreatIndicator
------------------------------------------------------------------------
1. Exact URL match (the service's /api/urls/lookup found the URL)
     verdict     = "malicious" (the service only stores URLs that phishing /
                   malware feeds reported)
     confidence  = the highest confidence a feed published, if any feed did;
                   otherwise a PhishShield policy value, because the current
                   feeds publish none:
                       listed by 1 feed   -> 0.85
                       listed by 2+ feeds -> 0.95  (independent corroboration)
     staleness   = if the URL was last seen in a feed more than 30 days ago,
                   confidence x 0.75 (phishing pages are short-lived and
                   compromised sites get cleaned up)
2. Host match (URL itself not listed, but other URLs on the same hostname are)
     verdict     = "suspicious", confidence = 0.60 (policy value). Weaker,
                   because one page on a host being malicious says less about
                   other pages on it.
3. No match -> no indicator. Absence from the feeds never lowers the score.

`confidence_basis` on every indicator states which rule produced the number,
so the UI never presents a policy value as if a feed had reported it.
"""

import logging
from datetime import datetime, timedelta, timezone

from .base import LookupOutcome, ThreatIndicator, ThreatIntelProvider
from .threat_intel_client import ThreatIntelClient, ThreatIntelError

log = logging.getLogger(__name__)

PROVIDER_NAME = "threat-intel-api"
CONFIDENCE_SINGLE_FEED = 0.85
CONFIDENCE_MULTI_FEED = 0.95
CONFIDENCE_HOST_MATCH = 0.60
STALE_AFTER_DAYS = 30
STALE_FACTOR = 0.75
HOST_SAMPLE_SIZE = 5


def _parse_ts(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def url_match_indicator(record, now=None):
    """ThreatIndicator for an exact URL match, following the policy above."""
    now = now or datetime.now(timezone.utc)
    reported = [s.confidence for s in record.sightings if s.confidence is not None]
    if record.confidence is not None:
        reported.append(record.confidence)
    sources = record.sources or sorted({s.source for s in record.sightings})
    n = len(sources)

    if reported:
        confidence = max(reported)
        basis = "Highest confidence published by a reporting feed."
    else:
        confidence = CONFIDENCE_MULTI_FEED if n >= 2 else CONFIDENCE_SINGLE_FEED
        basis = (f"PhishShield policy value for a URL listed by {n} feed{'s' if n != 1 else ''} "
                 f"({'2+ feeds' if n >= 2 else '1 feed'} -> {confidence:.2f}); "
                 "the feeds do not publish a confidence.")

    last_seen = _parse_ts(record.last_seen)
    age_days = (now - last_seen).days if last_seen else None
    if age_days is not None and age_days > STALE_AFTER_DAYS:
        confidence = round(confidence * STALE_FACTOR, 4)
        basis += f" Reduced x{STALE_FACTOR} because the URL was last seen in a feed {age_days} days ago."

    types = record.threat_types or ([record.threat_type] if record.threat_type else [])
    desc = (f"Listed by {', '.join(sources) or 'the threat-intel service'}"
            f"{' as ' + ', '.join(types) if types else ''}")
    if record.status:
        desc += f"; last reported status: {record.status}"
    if age_days is not None:
        desc += f"; last seen in a feed {'today' if age_days == 0 else f'{age_days} day(s) ago'}"
    return ThreatIndicator(
        source=PROVIDER_NAME, indicator_type="url", value=record.url, verdict="malicious",
        confidence=confidence, description=desc + ".", observed_at=record.first_seen or "",
        reference=f"record {record.id}", confidence_basis=basis,
        details={"record_id": record.id, "sources": sources, "threat_types": types,
                 "feed_status": record.status, "first_seen": record.first_seen,
                 "last_seen": record.last_seen, "tags": record.tags, "age_days": age_days},
    )


def host_match_indicator(hostname, page):
    sample_sources = sorted({s for r in page.items for s in r.sources})
    return ThreatIndicator(
        source=PROVIDER_NAME, indicator_type="host", value=hostname, verdict="suspicious",
        confidence=CONFIDENCE_HOST_MATCH,
        description=(f"This exact URL is not listed, but {page.total} other URL(s) on host "
                     f"{hostname} were reported{' by ' + ', '.join(sample_sources) if sample_sources else ''}."),
        observed_at=page.items[0].last_seen or "" if page.items else "",
        confidence_basis=(f"PhishShield policy value for a host-level match ({CONFIDENCE_HOST_MATCH:.2f}); "
                          "weaker than an exact URL match."),
        details={"host_url_count": page.total, "sources": sample_sources},
    )


class ThreatIntelAPIProvider(ThreatIntelProvider):
    name = PROVIDER_NAME

    def __init__(self, client: ThreatIntelClient, check_host=True):
        self.client = client
        self.check_host = check_host

    def lookup_url(self, parsed_url):
        return self.lookup(parsed_url).indicators

    def lookup(self, parsed_url):
        # The service normalises URLs itself, so send what the user entered
        # (including any userinfo, which ParsedURL.normalized drops).
        result = self.client.lookup_url(parsed_url.original)
        details = {"available": True, "checked": True, "match": None, "records": [],
                   "normalized_by_service": result.normalized_url}

        if result.not_checkable_reason:
            details.update(checked=False, message=(
                "The threat-intel service only tracks public http(s) URLs, so this URL could not be "
                "checked against it."))
            return LookupOutcome(indicators=[], details=details)

        if result.found:
            details.update(match="url", records=[result.record.to_dict()],
                           message="URL found in live threat intelligence.")
            return LookupOutcome(indicators=[url_match_indicator(result.record)], details=details)

        if self.check_host and parsed_url.host:
            try:
                page = self.client.urls_for_hostname(parsed_url.host, limit=HOST_SAMPLE_SIZE)
            except ThreatIntelError as e:
                log.warning("Host-level threat-intel check failed: %s", e)
                details["message"] = ("URL not found in live threat intelligence. "
                                      f"(Host-level check failed: {e})")
                return LookupOutcome(indicators=[], details=details)
            if page.total:
                details.update(match="host", records=[r.to_dict() for r in page.items],
                               host_url_count=page.total,
                               message="URL not listed, but other URLs on the same host are.")
                return LookupOutcome(indicators=[host_match_indicator(parsed_url.host, page)], details=details)

        details["message"] = "URL not found in live threat intelligence."
        return LookupOutcome(indicators=[], details=details)

    def outcome_for_record(self, record):
        """Outcome for a record already fetched (e.g. from the latest feed), without another request."""
        return LookupOutcome(indicators=[url_match_indicator(record)], details={
            "available": True, "checked": True, "match": "url", "records": [record.to_dict()],
            "message": "URL taken from the live threat-intelligence feed."})
