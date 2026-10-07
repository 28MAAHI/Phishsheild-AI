"""
Rule-based URL indicators.

Each rule is independent of the ML model and carries a fixed, documented
number of points. The points are expert-assigned weights, not values learned
or calibrated on data, and are reported as such in every explanation.

The heuristic score is the sum of points from fired indicators, capped at 100.
"""

import unicodedata
from dataclasses import dataclass, field, asdict

from .features import (
    brand_tokens_outside_registered_domain, has_embedded_url, sensitive_words_in,
)
from .reference_data import (
    BRAND_OFFICIAL_DOMAINS, EXECUTABLE_EXTENSIONS, OFFICIAL_DOMAINS,
    SUSPICIOUS_TLDS, TYPOSQUAT_TARGETS, URL_SHORTENERS,
)

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Indicator:
    id: str
    title: str
    detail: str
    severity: str        # "high" | "medium" | "low" | "info"
    points: int          # contribution to the heuristic score
    source: str = "heuristic"

    def to_dict(self):
        return asdict(self)


@dataclass
class HeuristicResult:
    indicators: list = field(default_factory=list)   # fired risk indicators
    passed_checks: list = field(default_factory=list)  # checks that found nothing
    trusted_domain: bool = False
    trusted_domain_detail: str = ""

    @property
    def score(self):
        return min(100, sum(i.points for i in self.indicators))

    @property
    def max_severity(self):
        if not self.indicators:
            return "info"
        return max((i.severity for i in self.indicators), key=SEVERITY_ORDER.get)

    def to_dict(self):
        return {
            "score": self.score,
            "max_severity": self.max_severity,
            "indicators": [i.to_dict() for i in self.indicators],
            "passed_checks": list(self.passed_checks),
            "trusted_domain": self.trusted_domain,
            "trusted_domain_detail": self.trusted_domain_detail,
        }


# ── helpers ──────────────────────────────────────────────────────────
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _edit_distance(a, b):
    """Optimal-string-alignment distance (Levenshtein + adjacent transpositions)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def find_typosquat(label):
    """Return the brand label that `label` imitates, or None.

    Short brand names (< 7 chars) only match after undoing character
    substitutions (paypa1 -> paypal, arnazon -> amazon); plain one-letter
    edits of short names hit too many real words (apply ~ apple).
    Longer names also match within edit distance 1 (2 for >= 10 chars).
    """
    if not label or len(label) < 4 or label in TYPOSQUAT_TARGETS:
        return None
    normalized = {label.translate(_LEET), label.replace("rn", "m"),
                  label.replace("vv", "w"), label.translate(_LEET).replace("rn", "m")}
    for target in TYPOSQUAT_TARGETS:
        if target in normalized:
            return target
        if len(target) >= 7:
            max_dist = 2 if len(target) >= 10 else 1
            for cand in normalized | {label}:
                if abs(len(cand) - len(target)) <= max_dist and _edit_distance(cand, target) <= max_dist:
                    return target
    return None


def _scripts(text):
    scripts = set()
    for ch in text:
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split(" ")[0])
            except ValueError:
                pass
    return scripts


# ── rules ────────────────────────────────────────────────────────────
def run_heuristics(parsed):
    """Evaluate every rule against a ParsedURL and return a HeuristicResult."""
    res = HeuristicResult()
    fire = res.indicators.append
    ok = res.passed_checks.append

    reg = parsed.registered_domain
    if reg and reg in OFFICIAL_DOMAINS:
        res.trusted_domain = True
        res.trusted_domain_detail = (
            f"Registered domain '{reg}' is on the configured list of official brand domains. "
            "This lowers risk but does not rule out abuse of open redirects or user-hosted content."
        )

    # 1. IP address instead of a domain name
    if parsed.is_ip:
        fire(Indicator("ip_host", "IP address used as host",
                       f"The link points to the raw IP address '{parsed.host}' instead of a domain name, "
                       "which hides who operates the site.", "high", 25))
    else:
        ok("Uses a domain name, not a raw IP address")

    # 2. '@' in the authority section: browser ignores everything before it
    if parsed.has_userinfo:
        fire(Indicator("userinfo_at", "'@' symbol hides the real destination",
                       f"Browsers ignore everything before '@' in the address, so the real host is "
                       f"'{parsed.host}'.", "high", 25))
    else:
        ok("No '@' trick in the address")

    # 3. Mixed-script (homoglyph) host
    labels = [l for l in parsed.host_unicode.split(".") if l]
    mixed = [l for l in labels if len(_scripts(l)) > 1]
    if mixed:
        fire(Indicator("mixed_script_host", "Mixed-alphabet (homoglyph) domain",
                       f"The host label '{mixed[0]}' mixes characters from different alphabets "
                       f"({', '.join(sorted(_scripts(mixed[0])))}), a common way to imitate a real domain.",
                       "high", 30))
    elif "xn--" in parsed.host:
        fire(Indicator("punycode_host", "Internationalised (punycode) domain",
                       f"The host is an internationalised domain shown to users as '{parsed.host_unicode}'. "
                       "Legitimate in many languages, but also used for lookalike domains.", "medium", 15))
    else:
        ok("No lookalike (homoglyph) characters in the domain")

    # 4. Brand name used outside its official domain
    brands = brand_tokens_outside_registered_domain(parsed)
    if brands:
        b = brands[0]
        official = ", ".join(sorted(BRAND_OFFICIAL_DOMAINS[b]))
        where = f"registered domain '{reg}'" if reg else f"host '{parsed.host}'"
        fire(Indicator("brand_impersonation", f"Brand name '{b}' outside its official domain",
                       f"'{b}' appears in the host, but the {where} is not one of the brand's "
                       f"configured official domains ({official}).", "high", 30))
    else:
        ok("No brand name used outside its official domain")

    # 5. Typosquatting of a brand domain
    squat = None if (parsed.is_ip or res.trusted_domain) else find_typosquat(parsed.domain.lower())
    if squat:
        fire(Indicator("typosquat", f"Lookalike of '{squat}'",
                       f"The domain label '{parsed.domain}' is a near-spelling of '{squat}' "
                       f"(brand: {TYPOSQUAT_TARGETS[squat]}), a typical typosquatting pattern.", "high", 30))
    else:
        ok("Domain is not a near-spelling of a monitored brand")

    # 6. URL shortener
    if reg in URL_SHORTENERS or parsed.host in URL_SHORTENERS:
        fire(Indicator("shortener", "Link shortener hides the destination",
                       f"'{parsed.host}' is a URL-shortening service; the final destination cannot be "
                       "seen without following the link.", "medium", 15))

    # 7. Embedded redirect
    if has_embedded_url(parsed):
        fire(Indicator("embedded_redirect", "Another URL embedded in the link",
                       "The path or query contains a second URL, which is how open-redirect and "
                       "tracking-wrapper abuse forwards victims to another site.", "medium", 12))

    # 8. Executable download
    if parsed.path.lower().endswith(EXECUTABLE_EXTENSIONS):
        fire(Indicator("executable_download", "Direct link to an executable file",
                       f"The path ends in '{parsed.path.rsplit('.', 1)[-1]}', a file type that can run code "
                       "on the device.", "medium", 15))

    # 9. Non-standard port
    if parsed.port not in (None, 80, 443):
        fire(Indicator("nonstandard_port", "Non-standard port",
                       f"The link uses port {parsed.port}; public websites almost always use 80 or 443.",
                       "medium", 10))

    # 10. Credential-related words
    words = sensitive_words_in(parsed)
    if len(words) >= 2:
        fire(Indicator("sensitive_words", "Several credential-related words",
                       f"The URL contains {', '.join(repr(w) for w in words[:5])}, words typical of "
                       "credential-harvesting pages.", "medium", 12))
    elif words:
        fire(Indicator("sensitive_words", "Credential-related word",
                       f"The URL contains '{words[0]}'. Common on real login pages too, so this is a weak signal.",
                       "low", 5))
    else:
        ok("No credential-related words (login, verify, ...) in the URL")

    # 11. Deep subdomain nesting
    depth = len([s for s in parsed.subdomain.split(".") if s])
    if depth >= 4:
        fire(Indicator("deep_subdomains", "Many subdomain levels",
                       f"The host has {depth} subdomain levels, often used to push the real domain "
                       "out of view on mobile screens.", "low", 8))

    # 12. Hyphen-heavy registered domain
    label = parsed.domain if not parsed.domain.startswith("xn--") else ""  # punycode has its own "--"
    if label.count("-") >= 3:
        fire(Indicator("hyphenated_domain", "Hyphen-heavy domain name",
                       f"'{label}' contains {label.count('-')} hyphens, typical of "
                       "keyword-stuffed throwaway domains.", "low", 6))

    # 13. TLD frequently abused
    tld = parsed.suffix.split(".")[-1] if parsed.suffix else ""
    if tld in SUSPICIOUS_TLDS:
        fire(Indicator("suspicious_tld", f"Top-level domain '.{tld}'",
                       f"'.{tld}' is over-represented in public phishing-abuse reports. Most sites under it "
                       "are harmless; this is a weak signal.", "low", 8))

    # 14. No encryption (only judged when the user actually supplied a scheme)
    if parsed.scheme_provided and parsed.scheme == "http":
        fire(Indicator("no_https", "Not encrypted (HTTP)",
                       "Data sent to this page is not encrypted. Note that HTTPS alone does not mean a "
                       "site is safe; most phishing sites now use it.", "low", 5))

    # 15. Very long URL
    if len(parsed.normalized) > 100:
        fire(Indicator("long_url", "Unusually long URL",
                       f"The URL is {len(parsed.normalized)} characters long, which can hide the real "
                       "destination or carry encoded tracking data.", "low", 5))

    res.indicators.sort(key=lambda i: (-SEVERITY_ORDER[i.severity], -i.points))
    return res
