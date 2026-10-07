"""
Builds a human-readable explanation of a URL risk assessment.

Evidence is kept in separate sections by origin so users can tell how much
each kind of evidence contributed:

    model_evidence      statistical patterns the trained model learned
    heuristic_evidence  fixed, hand-written rules with documented points
    external_evidence   findings from the threat-intel API service, plus whether
                        it was reachable and what was checked

build_verdict() condenses all of this into a classification and a list of
reasons, each tagged with the evidence category it comes from.
"""

TOP_CONTRIBUTIONS = 5
MIN_CONTRIBUTION = 0.05   # log-odds; smaller terms are not worth showing


def _fmt_value(c):
    v, unit = c["value"], c["unit"]
    if unit == "bool":
        return "yes" if v else "no"
    if unit == "ratio":
        return f"{v:.0%}"
    if unit == "bits":
        return f"{v:.2f} bits"
    return f"{v} {unit}" if unit and unit != "count" else str(v)


def _model_section(prediction, model_info, model_error):
    if prediction is None:
        return {
            "available": False,
            "note": model_error or "URL model is not loaded.",
        }
    pos = [c for c in prediction.contributions if c["contribution"] >= MIN_CONTRIBUTION][:TOP_CONTRIBUTIONS]
    neg = [c for c in prediction.contributions if c["contribution"] <= -MIN_CONTRIBUTION][:TOP_CONTRIBUTIONS]
    for c in pos + neg:
        c["display_value"] = _fmt_value(c)
    return {
        "available": True,
        "probability": prediction.probability,
        "verdict": "phishing" if prediction.probability >= 0.5 else "legitimate",
        "toward_phishing": pos,
        "toward_legitimate": neg,
        "logit": prediction.logit,
        "intercept": prediction.intercept,
        "model": model_info,
        "note": ("Contributions are exact log-odds terms of a logistic-regression model, measured "
                 "relative to the average URL in its training data. They describe statistical "
                 "patterns in that dataset, not verified facts about this site."),
    }


def _threat_intel_sentence(external, external_status):
    if not external_status.get("configured"):
        return ""
    if external_status.get("error"):
        return "Live threat intelligence unavailable, so this score uses the model and rules only."
    if not external_status.get("checked"):
        return external_status.get("message") or ""
    match = external_status.get("match")
    if match == "url" and external:
        return f"Threat intelligence: {external[0].description}"
    if match == "host" and external:
        return f"Threat intelligence: {external[0].description}"
    return "Threat intelligence: this URL is not listed in the collected phishing feeds."


def _summary(assessment, prediction, heuristics, external, external_status=None):
    parts = [f"{assessment.band['label']} ({assessment.score}/100)."]
    ti = _threat_intel_sentence(external, external_status or {})
    if ti:
        parts.append(ti)
    if prediction is not None:
        parts.append(f"The URL model estimates a {prediction.probability:.0%} probability of phishing.")
    else:
        parts.append("The URL model is unavailable, so this score uses rule-based indicators only.")
    n = len(heuristics.indicators)
    if n:
        top = heuristics.indicators[0]
        parts.append(f"{n} rule-based indicator{'s' if n != 1 else ''} fired"
                     f"{', the strongest being: ' + top.title if top.severity in ('high', 'medium') else ''}.")
    else:
        parts.append("No rule-based indicators fired.")
    if assessment.agreement == "model_only":
        parts.append("Only the model flags this URL; no strong rule matched, so treat the result with caution.")
    elif assessment.agreement == "heuristics_only":
        parts.append("Rules flag this URL while the model does not; review the indicators below.")
    return " ".join(parts)


def _recommendations(assessment, heuristics):
    s = assessment.score
    ids = {i.id for i in heuristics.indicators}
    recs = []
    if s > 60:
        recs.append("Do not open this link or enter any information on the page it leads to.")
    elif s > 40:
        recs.append("Avoid opening this link unless you can confirm it with the sender through another channel.")
    elif s > 20:
        recs.append("Some weak signals were found. Check the domain carefully before entering any details.")
    else:
        recs.append("No significant risk signals were found. Still, only enter credentials on sites you reached yourself.")
    if ids & {"brand_impersonation", "typosquat", "mixed_script_host", "punycode_host"}:
        recs.append("Go to the brand's website by typing its address yourself rather than using this link.")
    if "shortener" in ids:
        recs.append("Shortened links hide their destination. Use the shortener's preview feature if available.")
    if "executable_download" in ids:
        recs.append("Do not download or run the file this link points to.")
    if s > 60:
        recs.append("In India, report cyber fraud at cybercrime.gov.in or call 1930.")
    return recs


def _limitations(parsed, prediction, external_status):
    lims = [
        "Analysis uses only the URL text. The page content, DNS records, domain age and "
        "hosting are not inspected.",
        "The rule-based points are expert-assigned weights, not values calibrated on data.",
    ]
    if prediction is not None:
        lims.append("The model was trained on a public dataset collected in 2020. Phishing "
                    "techniques change, so its accuracy on current URLs may be lower than its test score.")
    if not external_status.get("configured"):
        lims.append("No threat-intelligence source is configured, so known-bad URL lists were not checked.")
    elif external_status.get("error"):
        lims.append("Live threat intelligence was unavailable for this analysis, so known-bad URL lists "
                    "were not checked.")
    elif external_status.get("checked"):
        lims.append("Threat intelligence covers only the phishing feeds the threat-intel service collects. "
                    "A URL that is not listed there is not necessarily safe.")
    lims.extend(parsed.notes)
    return lims


def _external_note(external_status):
    if not external_status.get("configured"):
        return "No threat-intelligence source is configured (set THREAT_INTEL_API_URL)."
    return external_status.get("message") or ""


def explain_url(parsed, assessment, heuristics, prediction=None, model_info=None,
                model_error=None, external_indicators=(), external_status=None):
    external_indicators = list(external_indicators)
    external_status = external_status or {"configured": False, "provider": "none", "error": None}
    return {
        "summary": _summary(assessment, prediction, heuristics, external_indicators, external_status),
        "model_evidence": _model_section(prediction, model_info, model_error),
        "heuristic_evidence": heuristics.to_dict(),
        "external_evidence": {
            **external_status,
            "indicators": [i.to_dict() for i in external_indicators],
            "note": _external_note(external_status),
        },
        "score_breakdown": assessment.to_dict(),
        "recommendations": _recommendations(assessment, heuristics),
        "limitations": _limitations(parsed, prediction, external_status),
    }


# ── Condensed verdict ────────────────────────────────────────────────────
# Classification thresholds match the risk bands: > 60 is High Risk / Critical
# (the UI already shows "likely phishing" there), 41-60 is Suspicious.
PHISHING_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 40


def _classification(score):
    if score > PHISHING_THRESHOLD:
        return "PHISHING"
    if score > SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "LOW_RISK"


def _threat_intel_summary(external, external_status):
    if not external_status.get("configured"):
        state = "not_configured"
    elif external_status.get("error"):
        state = "unavailable"
    elif not external_status.get("checked"):
        state = "not_checked"
    else:
        state = {"url": "match", "host": "host_match"}.get(external_status.get("match"), "no_match")
    out = {"status": state, "match": state == "match", "message": external_status.get("message") or ""}
    if external:
        top = max(external, key=lambda i: i.confidence)
        out.update({
            "match_type": top.indicator_type,
            "sources": top.details.get("sources", []),
            "threat_types": top.details.get("threat_types", []),
            "confidence": top.confidence,
            "confidence_basis": top.confidence_basis,
            "first_seen": top.details.get("first_seen"),
            "last_seen": top.details.get("last_seen"),
        })
    return out


def _reasons(assessment, prediction, heuristics, external, external_status):
    """Reasons that actually influenced the score, tagged by evidence category."""
    reasons = []
    ti = external_status
    if ti.get("configured"):
        if ti.get("error"):
            reasons.append({"category": "threat_intelligence", "effect": "none",
                            "text": "Live threat intelligence unavailable; not used in this score."})
        for i in external:
            if i.indicator_type == "url":
                reasons.append({"category": "threat_intelligence", "effect": "raises",
                                "text": f"URL matched a known threat-intelligence record. {i.description}"})
            else:
                reasons.append({"category": "threat_intelligence", "effect": "raises",
                                "text": i.description})
        if ti.get("checked") and not external:
            reasons.append({"category": "threat_intelligence", "effect": "none",
                            "text": "Not listed in the collected phishing feeds (this does not prove the URL is safe)."})

    if prediction is not None:
        p = prediction.probability
        if p >= 0.5:
            reasons.append({"category": "ml", "effect": "raises",
                            "text": f"URL model estimates a {p:.0%} phishing probability."})
        else:
            reasons.append({"category": "ml", "effect": "lowers",
                            "text": f"URL model estimates only a {p:.0%} phishing probability."})

    for i in heuristics.indicators:
        if i.severity in ("high", "medium"):
            reasons.append({"category": "heuristic", "effect": "raises",
                            "text": f"{i.title} ({i.severity}, +{i.points} pts)."})
    if heuristics.trusted_domain:
        reasons.append({"category": "heuristic", "effect": "lowers", "text": heuristics.trusted_domain_detail})

    for a in assessment.adjustments:
        reasons.append({"category": "score_rule", "effect": "raises" if a["to"] > a["from"] else "lowers",
                        "text": a["reason"]})
    return reasons


def build_verdict(assessment, prediction, heuristics, external_indicators=(), external_status=None):
    external = list(external_indicators)
    external_status = external_status or {}
    return {
        "classification": _classification(assessment.score),
        "risk_score": assessment.score,
        "severity": assessment.band["label"].upper(),
        "ml_probability": round(prediction.probability, 4) if prediction is not None else None,
        "heuristic_score": heuristics.score,
        "threat_intelligence": _threat_intel_summary(external, external_status),
        "reasons": _reasons(assessment, prediction, heuristics, external, external_status),
    }
