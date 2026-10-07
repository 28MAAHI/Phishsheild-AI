"""
Integration with the threat-intel API service, tested against a local stub
server (threat_intel_stub.py) that speaks the service's real JSON contract.
No test depends on the real service running.
"""

from datetime import datetime, timedelta, timezone

import pytest

from phishshield.service import URLAnalysisService
from phishshield.threat_intel import NullThreatIntelProvider, ThreatIntelAPIProvider, ThreatIntelClient
from phishshield.threat_intel.api_provider import (CONFIDENCE_HOST_MATCH, CONFIDENCE_MULTI_FEED,
                                                   CONFIDENCE_SINGLE_FEED, url_match_indicator)
from phishshield.threat_intel.threat_intel_client import (
    ThreatIntelAuthError, ThreatIntelHTTPError, ThreatIntelInvalidResponse, ThreatIntelRateLimited,
    ThreatIntelTimeout, ThreatIntelUnavailable, parse_record,
)
from threat_intel_stub import LISTED, ThreatIntelStub, make_record, unused_port_url

LISTED_URL = LISTED["url"]
CLEAN_URL = "https://www.example.org/welcome"


@pytest.fixture
def stub():
    with ThreatIntelStub() as s:
        yield s


@pytest.fixture
def ti_client(stub):
    return ThreatIntelClient(stub.url, timeout=2)


def service_for(base_url, model=None, timeout=2):
    provider = ThreatIntelAPIProvider(ThreatIntelClient(base_url, timeout=timeout))
    return URLAnalysisService(model=model, threat_intel=provider)


# ── 1. Successful responses ──────────────────────────────────────────────

def test_lookup_found_is_parsed(ti_client, stub):
    res = ti_client.lookup_url(LISTED_URL)
    assert res.found is True and res.record.id == 1
    assert res.record.sources == ["openphish"] and res.record.threat_types == ["phishing"]
    assert res.record.confidence is None  # the feed publishes none; nothing invented
    assert res.record.sightings[0].source == "openphish"
    assert stub.state.requests[-1]["query"] == {"url": LISTED_URL}


def test_lookup_not_found(ti_client):
    res = ti_client.lookup_url(CLEAN_URL)
    assert res.found is False and res.record is None and res.not_checkable_reason is None


def test_latest_and_health(ti_client):
    pg = ti_client.latest(limit=5)
    assert [r.id for r in pg.items] == [1, 2] and pg.total == 2 and pg.has_next is False
    assert ti_client.health()["status"] == "ok"


def test_api_key_header_sent_and_required(stub):
    stub.state.required_key = "reader-key-1"
    with pytest.raises(ThreatIntelAuthError) as e:
        ThreatIntelClient(stub.url, timeout=2).lookup_url(LISTED_URL)
    assert "THREAT_INTEL_API_KEY" in str(e.value)
    res = ThreatIntelClient(stub.url, api_key="reader-key-1", timeout=2).lookup_url(LISTED_URL)
    assert res.found and stub.state.requests[-1]["headers"]["X-API-Key"] == "reader-key-1"


def test_private_ip_is_not_checkable_not_an_error(ti_client):
    res = ti_client.lookup_url("http://192.168.1.1/login")
    assert res.found is False and res.not_checkable_reason


# ── 2-3. Timeout / unavailable ───────────────────────────────────────────

def test_timeout(stub):
    stub.state.delay = 1.5
    with pytest.raises(ThreatIntelTimeout):
        ThreatIntelClient(stub.url, timeout=0.5).lookup_url(LISTED_URL)


def test_connection_refused():
    with pytest.raises(ThreatIntelUnavailable):
        ThreatIntelClient(unused_port_url(), timeout=2).lookup_url(LISTED_URL)


@pytest.mark.parametrize("status, code, exc", [
    (503, "database_unavailable", ThreatIntelUnavailable),
    (500, "internal_error", ThreatIntelUnavailable),
    (429, "rate_limited", ThreatIntelRateLimited),
    (403, "forbidden", ThreatIntelAuthError),
    (404, "not_found", ThreatIntelHTTPError),
])
def test_http_errors(stub, ti_client, status, code, exc):
    stub.state.override = (status, {"success": False, "error": {"code": code, "message": "x"}})
    with pytest.raises(exc):
        ti_client.lookup_url(LISTED_URL)


# ── 4. Invalid responses ─────────────────────────────────────────────────

@pytest.mark.parametrize("body", [
    b"<html>proxy error</html>",
    b"",
    {"success": False},
    {"data": {"found": True}},
    {"success": True, "data": {"found": "yes"}},
    {"success": True, "data": {"found": True, "record": {"url": "http://x.example.com/"}}},
    {"success": True, "data": ["not", "an", "object"]},
])
def test_invalid_lookup_responses(stub, ti_client, body):
    stub.state.override = (200, body)
    with pytest.raises(ThreatIntelInvalidResponse):
        ti_client.lookup_url(LISTED_URL)


def test_redirect_is_rejected_and_not_followed(stub):
    stub.state.override = (302, b"", {"Location": "http://elsewhere.example.com/"})
    with pytest.raises(ThreatIntelInvalidResponse):
        ThreatIntelClient(stub.url, api_key="k", timeout=2).lookup_url(LISTED_URL)
    assert len(stub.state.requests) == 1


def test_malformed_list_items_skipped(stub, ti_client):
    stub.state.latest = [LISTED, {"id": "bad"}, "junk"]
    pg = ti_client.latest()
    assert len(pg.items) == 1 and pg.skipped_invalid == 2


def test_list_missing_pagination_is_invalid(stub, ti_client):
    stub.state.override = (200, {"success": True, "data": []})
    with pytest.raises(ThreatIntelInvalidResponse):
        ti_client.latest()


def test_api_key_never_in_error_messages(stub):
    stub.state.override = (401, {"success": False, "error": {"code": "unauthorized", "message": "no"}})
    with pytest.raises(ThreatIntelAuthError) as e:
        ThreatIntelClient(stub.url, api_key="SECRET-KEY-XYZ", timeout=2).lookup_url(LISTED_URL)
    assert "SECRET-KEY-XYZ" not in str(e.value)


# ── 5. Empty results ─────────────────────────────────────────────────────

def test_empty_latest(stub, ti_client):
    stub.state.latest = []
    pg = ti_client.latest()
    assert pg.items == [] and pg.total == 0


# ── Evidence policy ──────────────────────────────────────────────────────

def test_policy_confidence_single_and_multi_feed():
    now = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)
    one = url_match_indicator(parse_record(LISTED), now=now)
    assert one.verdict == "malicious" and one.confidence == CONFIDENCE_SINGLE_FEED
    assert "policy" in one.confidence_basis.lower()
    two = url_match_indicator(parse_record(make_record(3, "http://a.example.com/", "a.example.com",
                                                       sources=("openphish", "phishstats"))), now=now)
    assert two.confidence == CONFIDENCE_MULTI_FEED


def test_reported_confidence_is_used_when_present():
    rec = parse_record(make_record(4, "http://b.example.com/", "b.example.com", confidence=0.42))
    ind = url_match_indicator(rec, now=datetime(2026, 10, 7, tzinfo=timezone.utc))
    assert ind.confidence == 0.42 and "published by a reporting feed" in ind.confidence_basis


def test_stale_listing_reduces_confidence():
    rec = parse_record(LISTED)
    ind = url_match_indicator(rec, now=datetime(2026, 10, 7, tzinfo=timezone.utc) + timedelta(days=60))
    assert ind.confidence < CONFIDENCE_SINGLE_FEED and "days ago" in ind.confidence_basis


# ── 6-7. Found / not found through the analysis service ──────────────────

def test_url_found_in_threat_intelligence(stub):
    r = service_for(stub.url).analyze(LISTED_URL)
    v = r["verdict"]
    assert v["threat_intelligence"]["status"] == "match" and v["threat_intelligence"]["match"] is True
    assert v["threat_intelligence"]["sources"] == ["openphish"]
    assert v["threat_intelligence"]["confidence"] == CONFIDENCE_SINGLE_FEED
    assert any(x["category"] == "threat_intelligence" and x["effect"] == "raises" for x in v["reasons"])
    ext = r["explanation"]["external_evidence"]
    assert ext["available"] and ext["checked"] and ext["match"] == "url" and ext["records"][0]["id"] == 1
    assert "Threat intelligence:" in r["explanation"]["summary"]


def test_url_not_found_in_threat_intelligence(stub):
    r = service_for(stub.url).analyze(CLEAN_URL)
    ti = r["verdict"]["threat_intelligence"]
    assert ti["status"] == "no_match" and ti["match"] is False
    assert "external" not in [c["source"] for c in r["explanation"]["score_breakdown"]["components"]]
    assert any("Not listed" in x["text"] for x in r["verdict"]["reasons"])
    # the URL itself and then its host were checked
    assert [q["path"] for q in stub.state.requests] == ["/api/urls/lookup", "/api/urls"]


def test_host_level_match(stub):
    r = service_for(stub.url).analyze("http://shared.example.net/other-page")
    ti = r["verdict"]["threat_intelligence"]
    assert ti["status"] == "host_match" and ti["match"] is False
    ind = r["explanation"]["external_evidence"]["indicators"][0]
    assert ind["verdict"] == "suspicious" and ind["confidence"] == CONFIDENCE_HOST_MATCH


# ── 8-10. Analysis, scoring with and without threat intelligence ─────────

def test_score_with_threat_intelligence_is_higher(stub, url_model):
    with_ti = service_for(stub.url, model=url_model).analyze(LISTED_URL)
    without = URLAnalysisService(model=url_model).analyze(LISTED_URL)
    assert with_ti["score"] >= without["score"]
    assert with_ti["score"] >= 80  # external_malicious_floor applies (confidence 0.85 >= 0.8)
    comps = {c["source"] for c in with_ti["explanation"]["score_breakdown"]["components"]}
    assert comps == {"model", "heuristic", "external"}
    assert with_ti["verdict"]["classification"] == "PHISHING"
    assert with_ti["verdict"]["ml_probability"] is not None


def test_score_without_threat_intelligence_unchanged(stub, url_model):
    """A URL that is not listed scores exactly as it would with no threat intel at all."""
    checked = service_for(stub.url, model=url_model).analyze(CLEAN_URL)
    offline = URLAnalysisService(model=url_model).analyze(CLEAN_URL)
    assert checked["score"] == offline["score"]


def test_project1_unavailable_falls_back_to_local_analysis(url_model):
    r = service_for(unused_port_url(), model=url_model).analyze(LISTED_URL)
    offline = URLAnalysisService(model=url_model).analyze(LISTED_URL)
    ti = r["verdict"]["threat_intelligence"]
    assert ti["status"] == "unavailable" and ti["match"] is False
    assert "Live threat intelligence unavailable" in ti["message"]
    assert "Live threat intelligence unavailable" in r["explanation"]["summary"]
    assert r["explanation"]["external_evidence"]["available"] is False
    assert r["score"] == offline["score"]  # nothing pretended
    assert r["explanation"]["model_evidence"]["available"] is True


def test_timeout_falls_back(stub):
    stub.state.delay = 1.5
    r = service_for(stub.url, timeout=0.5).analyze(LISTED_URL)
    assert r["verdict"]["threat_intelligence"]["status"] == "unavailable"
    assert "ThreatIntelTimeout" in r["explanation"]["external_evidence"]["error"]


def test_null_provider_reports_not_configured():
    r = URLAnalysisService(threat_intel=NullThreatIntelProvider()).analyze(CLEAN_URL)
    assert r["verdict"]["threat_intelligence"]["status"] == "not_configured"


# ── Flask routes (browser -> PhishShield backend -> threat-intel API) ────

@pytest.fixture
def wired_app(flask_app, stub, url_model, monkeypatch):
    provider = ThreatIntelAPIProvider(ThreatIntelClient(stub.url, timeout=2))
    monkeypatch.setattr(flask_app, "threat_intel_provider", provider)
    monkeypatch.setattr(flask_app, "url_service", URLAnalysisService(model=url_model, threat_intel=provider))
    return flask_app


def test_api_analyze_route(wired_app):
    r = wired_app.app.test_client().post("/api/analyze", json={"url": LISTED_URL})
    assert r.status_code == 200
    d = r.get_json()
    assert d["status"] == "ok" and d["verdict"]["threat_intelligence"]["status"] == "match"
    assert d["verdict"]["risk_score"] == d["score"] and d["verdict"]["severity"]
    # same handler under the original path
    assert wired_app.app.test_client().post("/api/analyze-url", json={"url": LISTED_URL}).status_code == 200


def test_url_page_shows_threat_intel(wired_app):
    r = wired_app.app.test_client().post("/analyze-url", data={"url": LISTED_URL})
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "MATCH FOUND" in html and "Why this score" in html


def test_latest_route_with_analysis(wired_app, stub):
    r = wired_app.app.test_client().get("/api/threat-intel/latest?limit=5&analyze=true")
    assert r.status_code == 200
    d = r.get_json()
    assert d["available"] is True and d["count"] == 2
    item = d["items"][0]
    assert item["intel"]["url"] == LISTED_URL and "[.]" in item["display_url"] and item["display_url"].startswith("hxxp")
    assert item["analysis"]["verdict"]["threat_intelligence"]["status"] == "match"
    # records came from the latest call; no per-item lookups were made
    assert [q["path"] for q in stub.state.requests] == ["/api/urls/latest"]


def test_latest_route_unavailable(wired_app, stub):
    stub.state.override = (503, {"success": False, "error": {"code": "database_unavailable", "message": "x"}})
    r = wired_app.app.test_client().get("/api/threat-intel/latest")
    assert r.status_code == 503 and r.get_json()["available"] is False
    assert "Live threat intelligence unavailable" in r.get_json()["message"]


def test_latest_route_bad_params(wired_app):
    c = wired_app.app.test_client()
    assert c.get("/api/threat-intel/latest?limit=0").status_code == 400
    assert c.get("/api/threat-intel/latest?limit=abc").status_code == 400
    assert c.get("/api/threat-intel/latest?limit=40&analyze=true").status_code == 400


def test_latest_route_not_configured(flask_app):
    r = flask_app.app.test_client().get("/api/threat-intel/latest")
    assert r.status_code == 503 and "not configured" in r.get_json()["message"]


def test_health_reports_threat_intel_api(wired_app):
    comp = wired_app.app.test_client().get("/api/health").get_json()["components"]
    assert comp["threat_intel_api"] == {"reachable": True, "status": "ok", "database": "ok"}
    assert comp["threat_intel"]["provider"] == "threat-intel-api"
