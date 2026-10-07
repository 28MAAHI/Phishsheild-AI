"""
URL parsing and normalisation.

Everything here is offline: domain splitting uses tldextract's bundled
Public Suffix List snapshot and never fetches an updated list.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import tldextract

DEFAULT_MAX_URL_LENGTH = 2048

# suffix_list_urls=() -> use the bundled snapshot only (no network access).
# Private PSL domains are included so that user sub-sites on hosting
# platforms (x.firebaseapp.com, x.github.io, ...) are treated as their own
# registered domain rather than as the platform's domain.
_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class InvalidURLError(ValueError):
    """Raised when input cannot be analysed as an http(s) URL."""


@dataclass
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    scheme_provided: bool
    host: str                 # ASCII (IDNA) form, lowercase
    host_unicode: str         # Unicode form (differs from host for IDNs)
    port: int | None
    path: str
    query: str
    fragment: str
    subdomain: str
    domain: str               # registered-domain label, e.g. "paypal"
    suffix: str               # public suffix, e.g. "com" or "co.in"
    registered_domain: str    # e.g. "paypal.com" (empty for IPs)
    is_ip: bool
    has_userinfo: bool
    notes: list = field(default_factory=list)

    def to_dict(self):
        return {
            "original": self.original, "normalized": self.normalized,
            "scheme": self.scheme, "scheme_provided": self.scheme_provided,
            "host": self.host, "host_unicode": self.host_unicode, "port": self.port,
            "path": self.path, "query": self.query,
            "subdomain": self.subdomain, "domain": self.domain, "suffix": self.suffix,
            "registered_domain": self.registered_domain, "is_ip": self.is_ip,
            "has_userinfo": self.has_userinfo, "notes": list(self.notes),
        }


def _refang(url, notes):
    """Undo common 'defanging' used when URLs are shared in security reports."""
    out = re.sub(r"^hxxp", "http", url, flags=re.IGNORECASE)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if out != url:
        notes.append("Defanged notation (hxxp / [.]) was converted back to a normal URL.")
    return out


def _is_ip_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Obfuscated IPv4 forms browsers still accept: decimal (3232235777) or hex (0xc0a80101)
    if re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]{8}", host):
        return True
    return False


def _idna_forms(host):
    """Return (ascii_host, unicode_host)."""
    try:
        if any(ord(c) > 127 for c in host):
            return host.encode("idna").decode("ascii"), host
        if "xn--" in host:
            return host, host.encode("ascii").decode("idna")
    except UnicodeError:
        pass
    return host, host


def parse_url(raw, max_length=DEFAULT_MAX_URL_LENGTH):
    """Parse and normalise a URL string. Raises InvalidURLError on bad input."""
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string.")
    url = raw.strip()
    if not url:
        raise InvalidURLError("URL is empty.")
    if len(url) > max_length:
        raise InvalidURLError(f"URL is longer than the {max_length}-character limit.")
    if _CONTROL_RE.search(url):
        raise InvalidURLError("URL contains control characters.")
    if any(c.isspace() for c in url):
        raise InvalidURLError("URL contains whitespace; submit a single URL.")

    notes = []
    url = _refang(url, notes)

    scheme_provided = bool(_SCHEME_RE.match(url))
    if not scheme_provided:
        url = "http://" + url
        notes.append("No scheme was given; http:// was assumed for analysis.")

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as e:
        raise InvalidURLError(f"URL could not be parsed: {e}") from None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURLError(f"Only http and https URLs are supported (got '{scheme}').")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise InvalidURLError("URL has no host name.")

    is_ip = _is_ip_host(host)
    host_ascii, host_unicode = (host, host) if is_ip else _idna_forms(host)
    if not is_ip and "." not in host_ascii and host_ascii != "localhost":
        raise InvalidURLError(f"'{host}' is not a valid domain name.")

    if is_ip:
        sub, dom, suf, reg = "", host_ascii, "", ""
    else:
        ext = _EXTRACTOR(host_ascii)
        sub, dom, suf = ext.subdomain, ext.domain, ext.suffix
        reg = f"{dom}.{suf}" if dom and suf else ""
        if not suf:
            notes.append("Host does not end in a recognised public suffix.")

    netloc = host_ascii if port is None else f"{host_ascii}:{port}"
    normalized = f"{scheme}://{netloc}{parts.path or '/'}"
    if parts.query:
        normalized += "?" + parts.query

    return ParsedURL(
        original=raw.strip(), normalized=normalized, scheme=scheme,
        scheme_provided=scheme_provided, host=host_ascii, host_unicode=host_unicode,
        port=port, path=parts.path or "", query=parts.query or "",
        fragment=parts.fragment or "", subdomain=sub, domain=dom, suffix=suf,
        registered_domain=reg, is_ip=is_ip,
        has_userinfo=parts.username is not None or "@" in parts.netloc,
        notes=notes,
    )
