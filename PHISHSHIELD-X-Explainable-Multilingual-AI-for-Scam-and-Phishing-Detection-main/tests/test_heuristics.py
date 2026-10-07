import pytest

from phishshield.url_analysis import parse_url, run_heuristics
from phishshield.url_analysis.heuristics import find_typosquat


def ids(url):
    return {i.id for i in run_heuristics(parse_url(url)).indicators}


def test_regression_lookalike_prefix_is_not_trusted():
    # The original app used `"google.com" in url`, which marked this URL as
    # a known legitimate domain with risk 0.
    res = run_heuristics(parse_url("http://google.com.evil.xyz/login"))
    assert not res.trusted_domain
    assert "brand_impersonation" in {i.id for i in res.indicators}


def test_official_domain_is_trusted_and_clean():
    res = run_heuristics(parse_url("https://www.hdfcbank.com/personal"))
    assert res.trusted_domain
    assert res.indicators == []
    assert res.score == 0


@pytest.mark.parametrize("url,expected", [
    ("http://192.168.4.2/bank/login.php", "ip_host"),
    ("http://paypal.com@evil.example/", "userinfo_at"),
    ("https://xn--pypal-4ve.com/", "mixed_script_host"),
    ("https://sbi-kyc-update.example/verify", "brand_impersonation"),
    ("http://paypa1.com/", "typosquat"),
    ("http://arnazon.com/", "typosquat"),
    ("https://bit.ly/abc", "shortener"),
    ("https://example.com/redirect?to=http://evil.example", "embedded_redirect"),
    ("https://example.com/files/setup.exe", "executable_download"),
    ("http://example.com:8443/", "nonstandard_port"),
    ("https://a.b.c.d.example.com/", "deep_subdomains"),
    ("https://free-gift-card-winner.com/", "hyphenated_domain"),
    ("https://example.xyz/", "suspicious_tld"),
    ("http://example.com/", "no_https"),
])
def test_rule_fires(url, expected):
    assert expected in ids(url)


def test_no_https_not_judged_when_scheme_missing():
    assert "no_https" not in ids("example.com/")


def test_punycode_hyphens_do_not_trigger_hyphen_rule():
    assert "hyphenated_domain" not in ids("https://xn--pypal-4ve.com/")


def test_sensitive_words_severity_scales():
    one = run_heuristics(parse_url("https://example.com/login"))
    two = run_heuristics(parse_url("https://example.com/login/verify"))
    s1 = [i for i in one.indicators if i.id == "sensitive_words"][0]
    s2 = [i for i in two.indicators if i.id == "sensitive_words"][0]
    assert s1.severity == "low" and s2.severity == "medium"


def test_score_is_sum_of_points_capped():
    res = run_heuristics(parse_url(
        "http://paypal.secure.login.verify.example.xyz:8080/webscr/login?next=http://x.example/a.exe"))
    assert res.score == min(100, sum(i.points for i in res.indicators))
    assert res.score <= 100


def test_indicators_sorted_by_severity():
    res = run_heuristics(parse_url("http://192.168.1.1/login"))
    order = {"high": 3, "medium": 2, "low": 1}
    sev = [order[i.severity] for i in res.indicators]
    assert sev == sorted(sev, reverse=True)


def test_all_indicators_are_labelled_as_heuristic():
    res = run_heuristics(parse_url("http://192.168.1.1/login"))
    assert all(i.source == "heuristic" for i in res.indicators)


@pytest.mark.parametrize("label,target", [
    ("paypa1", "paypal"), ("g00gle", "google"), ("arnazon", "amazon"),
    ("micros0ft", "microsoft"), ("mircosoft", "microsoft"), ("netfllx", "netflix"),
])
def test_typosquat_detected(label, target):
    assert find_typosquat(label) == target


@pytest.mark.parametrize("label", ["apply", "paypal", "google", "example", "amazing", "wikipedia", "goo"])
def test_typosquat_not_detected_for_real_words(label):
    assert find_typosquat(label) is None
