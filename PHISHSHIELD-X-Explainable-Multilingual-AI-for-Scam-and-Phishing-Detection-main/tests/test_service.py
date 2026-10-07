import pytest

from phishshield.service import URLAnalysisService
from phishshield.threat_intel import NullThreatIntelProvider, ThreatIndicator, ThreatIntelProvider
from phishshield.url_analysis import InvalidURLError


class _StaticProvider(ThreatIntelProvider):
    """Test double standing in for a future threat-intel client."""
    name = "test-double"

    def __init__(self, indicators=(), error=None):
        self.indicators, self.error = list(indicators), error

    def lookup_url(self, parsed_url):
        if self.error:
            raise self.error
        return self.indicators


def test_service_without_model_still_works():
    svc = URLAnalysisService(model=None, model_error="no model")
    r = svc.analyze("http://192.168.1.1/login")
    me = r["explanation"]["model_evidence"]
    assert me["available"] is False and me["note"] == "no model"
    assert r["score"] >= 50
    assert "rule-based indicators only" in r["explanation"]["summary"]
    assert [c["source"] for c in r["explanation"]["score_breakdown"]["components"]] == ["heuristic"]


def test_evidence_sections_are_separated(url_model):
    svc = URLAnalysisService(model=url_model)
    exp = svc.analyze("http://paypa1.com/signin")["explanation"]
    assert exp["model_evidence"]["available"] is True
    assert all("feature" in c for c in exp["model_evidence"]["toward_phishing"])
    assert all(i["source"] == "heuristic" for i in exp["heuristic_evidence"]["indicators"])
    assert exp["external_evidence"]["configured"] is False
    assert exp["external_evidence"]["indicators"] == []
    assert exp["limitations"]


def test_default_provider_is_null():
    svc = URLAnalysisService()
    assert isinstance(svc.threat_intel, NullThreatIntelProvider)
    assert svc.status()["threat_intel"] == {"configured": False, "provider": "none"}


def test_future_provider_plugs_in(url_model):
    ind = ThreatIndicator("test-double", "url", "https://example.com/", "malicious", 0.95)
    svc = URLAnalysisService(model=url_model, threat_intel=_StaticProvider([ind]))
    r = svc.analyze("https://example.com/")
    assert r["explanation"]["external_evidence"]["indicators"][0]["source"] == "test-double"
    assert r["score"] >= 80


def test_provider_failure_degrades_gracefully(url_model):
    svc = URLAnalysisService(model=url_model, threat_intel=_StaticProvider(error=TimeoutError("down")))
    r = svc.analyze("https://example.com/")
    assert "TimeoutError" in r["explanation"]["external_evidence"]["error"]
    assert 0 <= r["score"] <= 100


def test_invalid_url_raises():
    with pytest.raises(InvalidURLError):
        URLAnalysisService().analyze("ftp://example.com")


def test_result_is_json_serialisable(url_model):
    import json
    json.dumps(URLAnalysisService(model=url_model).analyze("https://bit.ly/x"))
