"""
Lexical URL features for the phishing model.

This module is the single source of truth for what the model sees: the
training script and the live app both call extract_features(), so there is
no train/serve skew. Features are computed from the URL string alone (no
DNS, WHOIS or page fetches), which keeps analysis offline and fast but also
limits what the model can know (see README "Limitations").

Bump FEATURE_VERSION whenever a feature is added, removed or changed; the
model loader refuses artifacts trained with a different version.

Overall URL length, path length and the host's dot count are left out
because they nearly duplicate other features (host/query length, path
depth, subdomain depth). With them in, the linear model splits weight
between collinear copies and the per-feature explanations get
contradictory signs.

Count features are log-transformed so a single extreme value (say, five
credential words) cannot push the linear model to an overconfident 100%.

A leading "www." is ignored by every host feature. In the training data
"www." is far more common on legitimate URLs, which mostly reflects how the
dataset was collected; letting the model learn it would penalise legitimate
hosts such as github.com.
"""

import math
from collections import Counter
from dataclasses import dataclass

from .reference_data import (
    BRAND_OFFICIAL_DOMAINS, EXECUTABLE_EXTENSIONS, SENSITIVE_WORDS,
    SHORT_BRAND_LEN, URL_SHORTENERS,
)

FEATURE_VERSION = "1"


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    label: str        # human-readable name used in explanations
    unit: str = ""    # how to describe the raw value ("chars", "bool", ...)
    log: bool = False # model input is log1p(value); explanations show the raw value


FEATURE_SPECS = (
    FeatureSpec("host_length", "Host name length", "chars", log=True),
    FeatureSpec("query_length", "Query string length", "chars", log=True),
    FeatureSpec("subdomain_depth", "Number of subdomain levels (excluding www)", "count", log=True),
    FeatureSpec("host_hyphen_count", "Hyphens in host name", "count", log=True),
    FeatureSpec("host_digit_ratio", "Share of digits in host name", "ratio"),
    FeatureSpec("url_digit_ratio", "Share of digits in URL", "ratio"),
    FeatureSpec("special_char_count", "Special characters (@ ~ _ % = & !)", "count", log=True),
    FeatureSpec("path_depth", "Path depth (directory levels)", "count", log=True),
    FeatureSpec("query_param_count", "Number of query parameters", "count", log=True),
    FeatureSpec("host_entropy", "Character randomness (entropy) of host name", "bits"),
    FeatureSpec("longest_host_token", "Longest word in host name", "chars"),
    FeatureSpec("sensitive_word_count", "Credential-related words (login, verify, ...)", "count", log=True),
    FeatureSpec("brand_outside_domain", "Brand name outside the registered domain", "bool"),
    FeatureSpec("uses_https", "Uses HTTPS", "bool"),
    FeatureSpec("has_ip_host", "IP address used as host", "bool"),
    FeatureSpec("has_at_symbol", "Contains '@'", "bool"),
    FeatureSpec("has_nonstandard_port", "Non-standard port", "bool"),
    FeatureSpec("has_punycode", "Internationalised (punycode) host", "bool"),
    FeatureSpec("is_shortener", "Known URL-shortening service", "bool"),
    FeatureSpec("has_embedded_url", "Another URL embedded in path or query", "bool"),
    FeatureSpec("has_executable_ext", "Links to an executable file", "bool"),
    FeatureSpec("tld_length", "Top-level domain length", "chars"),
)

FEATURE_NAMES = tuple(s.name for s in FEATURE_SPECS)
SPEC_BY_NAME = {s.name: s for s in FEATURE_SPECS}


def _entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _host_tokens(host):
    return [t for t in host.replace("-", ".").split(".") if t]


def brand_tokens_outside_registered_domain(parsed):
    """Brand keywords found in the subdomain, or in the domain label when the
    registered domain is not an official one for that brand."""
    if parsed.is_ip:
        hay_host = ""
    else:
        hay_host = f"{parsed.subdomain}.{parsed.domain}".lower()
    tokens = set(_host_tokens(hay_host))
    found = []
    for brand, official in BRAND_OFFICIAL_DOMAINS.items():
        if parsed.registered_domain in official:
            continue
        if len(brand) < SHORT_BRAND_LEN:
            hit = brand in tokens
        else:
            hit = brand in hay_host
        if hit:
            found.append(brand)
    return found


def sensitive_words_in(parsed):
    text = f"{parsed.host}{parsed.path}?{parsed.query}".lower()
    return [w for w in SENSITIVE_WORDS if w in text]


def has_embedded_url(parsed):
    rest = f"{parsed.path}?{parsed.query}".lower()
    return "http://" in rest or "https://" in rest or "http%3a" in rest or "https%3a" in rest or "//" in parsed.path[1:]


def _strip_www(name):
    return name[4:] if name.startswith("www.") else ("" if name == "www" else name)


def raw_feature_values(parsed):
    """Feature values as a dict, before the log transform (used for display)."""
    url = parsed.normalized
    host = parsed.host if parsed.is_ip else _strip_www(parsed.host)
    digits_host = sum(c.isdigit() for c in host)
    digits_url = sum(c.isdigit() for c in url)
    tokens = _host_tokens(host)
    path_segments = [p for p in parsed.path.split("/") if p]
    tld = parsed.suffix.split(".")[-1] if parsed.suffix else ""

    return {
        "host_length": len(host),
        "query_length": len(parsed.query),
        "subdomain_depth": len([s for s in _strip_www(parsed.subdomain).split(".") if s]),
        "host_hyphen_count": host.count("-"),
        "host_digit_ratio": round(digits_host / len(host), 4) if host and not parsed.is_ip else 0.0,
        "url_digit_ratio": round(digits_url / len(url), 4) if url else 0.0,
        "special_char_count": sum(url.count(c) for c in "@~_%=&!"),
        "path_depth": len(path_segments),
        "query_param_count": len([q for q in parsed.query.split("&") if q]),
        "host_entropy": round(_entropy(host), 4),
        "longest_host_token": max((len(t) for t in tokens), default=0),
        "sensitive_word_count": len(sensitive_words_in(parsed)),
        "brand_outside_domain": int(bool(brand_tokens_outside_registered_domain(parsed))),
        "uses_https": int(parsed.scheme == "https"),
        "has_ip_host": int(parsed.is_ip),
        "has_at_symbol": int(parsed.has_userinfo or "@" in url),
        "has_nonstandard_port": int(parsed.port not in (None, 80, 443)),
        "has_punycode": int("xn--" in host),
        "is_shortener": int(parsed.registered_domain in URL_SHORTENERS or host in URL_SHORTENERS),
        "has_embedded_url": int(has_embedded_url(parsed)),
        "has_executable_ext": int(parsed.path.lower().endswith(EXECUTABLE_EXTENSIONS)),
        "tld_length": len(tld),
    }


def extract_features(parsed):
    """Model-ready feature vector (list of floats, ordered as FEATURE_NAMES)."""
    raw = raw_feature_values(parsed)
    vec = []
    for spec in FEATURE_SPECS:
        v = float(raw[spec.name])
        vec.append(math.log1p(v) if spec.log else v)
    return vec
