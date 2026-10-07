import math

from phishshield.url_analysis import FEATURE_NAMES, extract_features, parse_url
from phishshield.url_analysis.features import FEATURE_SPECS, raw_feature_values


def test_vector_matches_feature_names():
    vec = extract_features(parse_url("https://example.com/a/b?x=1"))
    assert len(vec) == len(FEATURE_NAMES) == len(FEATURE_SPECS)
    assert all(isinstance(v, float) and math.isfinite(v) for v in vec)


def test_feature_extraction_is_deterministic():
    p = parse_url("http://login-secure.example.xyz/verify/account?id=42")
    assert extract_features(p) == extract_features(p)


def test_log_transform_applied():
    p = parse_url("https://example.com/" + "a" * 50)
    raw = raw_feature_values(p)
    vec = dict(zip(FEATURE_NAMES, extract_features(p)))
    assert raw["host_length"] == len("example.com")
    assert vec["host_length"] == math.log1p(raw["host_length"])


def test_www_is_ignored_by_host_features():
    a = raw_feature_values(parse_url("https://www.example.com/"))
    b = raw_feature_values(parse_url("https://example.com/"))
    for name in ("host_length", "subdomain_depth", "host_entropy", "host_hyphen_count"):
        assert a[name] == b[name], name


def test_expected_values_for_phishing_like_url():
    raw = raw_feature_values(parse_url("http://paypal.secure-login.example.com:8080/webscr/verify?cmd=login"))
    assert raw["uses_https"] == 0
    assert raw["has_nonstandard_port"] == 1
    assert raw["brand_outside_domain"] == 1
    assert raw["sensitive_word_count"] >= 3
    assert raw["subdomain_depth"] == 2
    assert raw["path_depth"] == 2
    assert raw["query_param_count"] == 1


def test_official_brand_domain_not_flagged_as_brand_outside_domain():
    raw = raw_feature_values(parse_url("https://www.paypal.com/signin"))
    assert raw["brand_outside_domain"] == 0
