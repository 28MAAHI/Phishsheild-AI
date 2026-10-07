"""
Transparent URL risk-scoring engine.

    1. Component scores (each 0-100):
         model      = 100 x P(phishing) from the URL model        (if loaded)
         heuristic  = sum of points of fired rule indicators, cap 100
         external   = strongest external threat-intel finding     (if any)
    2. Weighted average over the components that are available, using
       the configured weights (renormalised so they sum to 1).
    3. Documented adjustments, each recorded in the breakdown:
         - a high-severity heuristic indicator raises the score to >= 50
         - an external "malicious" finding with confidence >= 0.8 raises it to >= 80
         - an official brand domain with no medium/high indicators caps it at 20
    4. Clamp to 0-100 and map to the same bands the message analyser uses.

Every number that went into the score is returned, so the UI and API can
show exactly how the result was produced.
"""

from dataclasses import dataclass, field

from ..config import ScoringWeights

HIGH_SEVERITY_FLOOR = 50
EXTERNAL_MALICIOUS_FLOOR = 80
EXTERNAL_MALICIOUS_MIN_CONFIDENCE = 0.8
TRUSTED_DOMAIN_CAP = 20

_VERDICT_SCALE = {"malicious": 100, "suspicious": 60, "benign": 0}

BANDS = (
    (20, {"label": "Safe", "color": "success", "icon": "✅", "class": "safe"}),
    (40, {"label": "Low Risk", "color": "info", "icon": "ℹ️", "class": "low"}),
    (60, {"label": "Suspicious", "color": "warning", "icon": "🕵️", "class": "suspicious"}),
    (80, {"label": "High Risk", "color": "danger", "icon": "⚠️", "class": "high"}),
    (100, {"label": "Critical", "color": "danger", "icon": "🚨", "class": "critical"}),
)


def risk_band(score):
    for upper, band in BANDS:
        if score <= upper:
            return dict(band)
    return dict(BANDS[-1][1])


@dataclass
class RiskAssessment:
    score: int
    band: dict
    components: list = field(default_factory=list)
    adjustments: list = field(default_factory=list)
    weighted_score: float = 0.0
    agreement: str = ""

    def to_dict(self):
        return {"score": self.score, "band": self.band, "components": self.components,
                "adjustments": self.adjustments, "weighted_score": self.weighted_score,
                "agreement": self.agreement}


def external_component_score(indicators):
    """Strongest external finding as a 0-100 score, or None if nothing usable."""
    scores = [
        _VERDICT_SCALE[i.verdict] * float(i.confidence)
        for i in indicators if i.verdict in _VERDICT_SCALE
    ]
    return round(max(scores), 2) if scores else None


def score_url(model_probability, heuristics, external_indicators=(), weights=None):
    """Combine evidence into a RiskAssessment.

    model_probability: float in [0, 1], or None if the model is unavailable
    heuristics: HeuristicResult
    external_indicators: iterable of threat_intel.ThreatIndicator (empty today)
    """
    weights = weights or ScoringWeights()
    external_indicators = list(external_indicators)
    components = []

    if model_probability is not None:
        components.append({"source": "model", "label": "URL model (machine learning)",
                           "score": round(100 * model_probability, 2), "weight": weights.model})
    components.append({"source": "heuristic", "label": "Rule-based indicators",
                       "score": float(heuristics.score), "weight": weights.heuristic})
    ext = external_component_score(external_indicators)
    if ext is not None and weights.external > 0:
        components.append({"source": "external", "label": "External threat intelligence",
                           "score": ext, "weight": weights.external})

    total_w = sum(c["weight"] for c in components)
    if total_w <= 0:  # e.g. model missing and heuristic weight set to 0
        for c in components:
            c["weight"] = 1.0
        total_w = float(len(components))
    for c in components:
        c["normalized_weight"] = round(c["weight"] / total_w, 4)
        c["points"] = round(c["score"] * c["weight"] / total_w, 2)
    weighted = sum(c["score"] * c["weight"] for c in components) / total_w

    score = weighted
    adjustments = []
    high = [i for i in heuristics.indicators if i.severity == "high"]
    if high and score < HIGH_SEVERITY_FLOOR:
        adjustments.append({
            "rule": "high_severity_floor", "from": round(score, 2), "to": HIGH_SEVERITY_FLOOR,
            "reason": f"High-severity indicator '{high[0].title}' fired; score raised to at least "
                      f"{HIGH_SEVERITY_FLOOR} (Suspicious).",
        })
        score = HIGH_SEVERITY_FLOOR

    strong_ext = [i for i in external_indicators
                  if i.verdict == "malicious" and i.confidence >= EXTERNAL_MALICIOUS_MIN_CONFIDENCE]
    if strong_ext and score < EXTERNAL_MALICIOUS_FLOOR:
        adjustments.append({
            "rule": "external_malicious_floor", "from": round(score, 2), "to": EXTERNAL_MALICIOUS_FLOOR,
            "reason": f"External source '{strong_ext[0].source}' reports this as malicious "
                      f"(confidence {strong_ext[0].confidence:.0%}).",
        })
        score = EXTERNAL_MALICIOUS_FLOOR

    serious = [i for i in heuristics.indicators if i.severity in ("high", "medium")]
    if heuristics.trusted_domain and not serious and not strong_ext and score > TRUSTED_DOMAIN_CAP:
        adjustments.append({
            "rule": "trusted_domain_cap", "from": round(score, 2), "to": TRUSTED_DOMAIN_CAP,
            "reason": "Official brand domain with no medium- or high-severity indicators; "
                      f"score capped at {TRUSTED_DOMAIN_CAP}.",
        })
        score = TRUSTED_DOMAIN_CAP

    final = int(round(min(100.0, max(0.0, score))))

    agreement = ""
    if model_probability is not None:
        model_flag = model_probability >= 0.5
        heur_flag = heuristics.score >= 25 or bool(high)
        if model_flag == heur_flag:
            agreement = "agree"
        else:
            agreement = "model_only" if model_flag else "heuristics_only"

    return RiskAssessment(score=final, band=risk_band(final), components=components,
                          adjustments=adjustments, weighted_score=round(weighted, 2),
                          agreement=agreement)
