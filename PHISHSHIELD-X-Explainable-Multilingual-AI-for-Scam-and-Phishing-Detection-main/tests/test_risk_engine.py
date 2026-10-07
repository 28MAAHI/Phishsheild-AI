import pytest

from phishshield.config import ScoringWeights
from phishshield.scoring import risk_band, score_url
from phishshield.threat_intel import ThreatIndicator
from phishshield.url_analysis import parse_url, run_heuristics


def heur(url):
    return run_heuristics(parse_url(url))


def test_weighted_average_of_model_and_heuristics():
    h = heur("https://example.com/login")      # one low indicator: 5 points
    a = score_url(0.8, h, weights=ScoringWeights(model=0.6, heuristic=0.4))
    assert a.weighted_score == pytest.approx(0.6 * 80 + 0.4 * h.score)
    assert a.score == round(a.weighted_score)
    assert sum(c["normalized_weight"] for c in a.components) == pytest.approx(1.0)
    assert sum(c["points"] for c in a.components) == pytest.approx(a.weighted_score, abs=0.02)


def test_model_unavailable_uses_heuristics_only():
    h = heur("http://192.168.1.1/x")
    a = score_url(None, h)
    assert [c["source"] for c in a.components] == ["heuristic"]
    assert a.components[0]["normalized_weight"] == 1.0
    assert a.agreement == ""


def test_high_severity_floor():
    h = heur("http://192.168.1.1/")
    a = score_url(0.0, h)
    assert a.score >= 50
    assert any(adj["rule"] == "high_severity_floor" for adj in a.adjustments)


def test_trusted_domain_cap():
    h = heur("https://github.com/a/b/c/d/e")
    a = score_url(0.95, h)
    assert a.score == 20
    assert any(adj["rule"] == "trusted_domain_cap" for adj in a.adjustments)


def test_trusted_domain_cap_not_applied_with_medium_indicator():
    h = heur("https://www.google.com/url?q=http://evil.example/")  # open-redirect pattern
    a = score_url(0.95, h)
    assert not any(adj["rule"] == "trusted_domain_cap" for adj in a.adjustments)


def test_score_bounds():
    for p in (0.0, 0.5, 1.0):
        a = score_url(p, heur("http://paypal.com@1.2.3.4:8080/login/verify.exe"))
        assert 0 <= a.score <= 100


def test_external_indicators_are_accepted_through_the_interface():
    # A future threat-intel client returns ThreatIndicator objects; the engine
    # must combine them without any other code change.
    h = heur("https://example.com/")
    ext = [ThreatIndicator(source="test-double", indicator_type="url",
                           value="https://example.com/", verdict="malicious", confidence=0.9)]
    a = score_url(0.1, h, ext)
    assert "external" in [c["source"] for c in a.components]
    assert a.score >= 80
    assert any(adj["rule"] == "external_malicious_floor" for adj in a.adjustments)


def test_unknown_external_verdicts_are_ignored():
    h = heur("https://example.com/")
    ext = [ThreatIndicator("t", "url", "x", "unknown", 0.5)]
    a = score_url(0.1, h, ext)
    assert "external" not in [c["source"] for c in a.components]


def test_threat_indicator_validation():
    with pytest.raises(ValueError):
        ThreatIndicator("t", "url", "x", "evil", 0.5)
    with pytest.raises(ValueError):
        ThreatIndicator("t", "url", "x", "malicious", 1.5)


@pytest.mark.parametrize("score,label", [(0, "Safe"), (20, "Safe"), (21, "Low Risk"), (40, "Low Risk"),
                                         (41, "Suspicious"), (60, "Suspicious"), (61, "High Risk"),
                                         (80, "High Risk"), (81, "Critical"), (100, "Critical")])
def test_bands(score, label):
    assert risk_band(score)["label"] == label


def test_agreement_flags():
    clean = heur("https://example.com/")
    assert score_url(0.9, clean).agreement == "model_only"
    assert score_url(0.1, clean).agreement == "agree"
    assert score_url(0.1, heur("http://192.168.1.1/")).agreement == "heuristics_only"
