import pytest

from phishshield.url_analysis import InvalidURLError, parse_url


def test_basic_https_url():
    p = parse_url("https://www.Example.com/Path?a=1")
    assert p.scheme == "https"
    assert p.scheme_provided
    assert p.host == "www.example.com"
    assert p.registered_domain == "example.com"
    assert p.subdomain == "www"
    assert p.path == "/Path"
    assert p.query == "a=1"
    assert not p.is_ip


def test_missing_scheme_is_assumed_http_and_noted():
    p = parse_url("example.org/login")
    assert p.scheme == "http"
    assert not p.scheme_provided
    assert any("No scheme" in n for n in p.notes)


def test_multi_part_public_suffix():
    p = parse_url("https://onlinesbi.sbi.co.in/")
    assert p.registered_domain == "sbi.co.in"
    assert p.subdomain == "onlinesbi"


def test_lookalike_subdomain_does_not_become_registered_domain():
    p = parse_url("http://google.com.evil.xyz/login")
    assert p.registered_domain == "evil.xyz"
    assert p.subdomain == "google.com"


def test_hosting_platform_subsite_is_its_own_domain():
    # PSL private domains: user sites must not inherit the platform's identity.
    p = parse_url("https://paypal-login.firebaseapp.com/")
    assert p.registered_domain == "paypal-login.firebaseapp.com"


@pytest.mark.parametrize("url", ["http://192.168.0.1/a", "http://[2001:db8::1]/", "http://3232235777/"])
def test_ip_hosts_detected(url):
    assert parse_url(url).is_ip


def test_userinfo_detected():
    p = parse_url("http://paypal.com@evil.example/")
    assert p.has_userinfo
    assert p.host == "evil.example"


def test_idn_host_has_ascii_and_unicode_forms():
    p = parse_url("https://xn--pypal-4ve.com/")
    assert p.host == "xn--pypal-4ve.com"
    assert p.host_unicode != p.host
    assert "а" in p.host_unicode  # Cyrillic small a


def test_defanged_url_is_refanged():
    p = parse_url("hxxp://evil[.]example/x")
    assert p.host == "evil.example"
    assert any("Defanged" in n for n in p.notes)


def test_port_is_parsed():
    assert parse_url("http://example.com:8080/").port == 8080


@pytest.mark.parametrize("bad", [
    "", "   ", "ftp://example.com/file", "javascript:alert(1)", "http://", "not a url",
    "http://example.com:99999/", "http://exa\x00mple.com", "localhostonly",
])
def test_invalid_input_raises(bad):
    with pytest.raises(InvalidURLError):
        parse_url(bad)


def test_non_string_raises():
    with pytest.raises(InvalidURLError):
        parse_url(None)


def test_length_limit():
    with pytest.raises(InvalidURLError):
        parse_url("http://example.com/" + "a" * 3000, max_length=2048)
