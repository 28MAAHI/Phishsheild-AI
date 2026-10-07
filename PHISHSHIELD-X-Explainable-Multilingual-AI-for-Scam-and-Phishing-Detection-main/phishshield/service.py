"""
URL analysis service: parse -> model -> heuristics -> threat intel -> score -> explain.

Each step lives in its own module; this class only wires them together and
makes sure a failure in an optional component (model, threat-intel provider)
degrades the analysis instead of breaking it.
"""

import logging

from .config import ScoringWeights
from .detection import ModelLoadError, load_url_model
from .explain import build_verdict, explain_url
from .scoring import score_url
from .threat_intel import NullThreatIntelProvider
from .url_analysis import parse_url, run_heuristics
from .url_analysis.parser import DEFAULT_MAX_URL_LENGTH

log = logging.getLogger(__name__)


class URLAnalysisService:
    def __init__(self, model=None, model_error=None, threat_intel=None,
                 weights=None, max_url_length=DEFAULT_MAX_URL_LENGTH):
        self.model = model
        self.model_error = model_error
        self.threat_intel = threat_intel or NullThreatIntelProvider()
        self.weights = weights or ScoringWeights()
        self.max_url_length = max_url_length

    @classmethod
    def from_settings(cls, settings, threat_intel=None):
        model, error = None, None
        try:
            model = load_url_model(settings.url_model_path)
            log.info("URL model loaded from %s", settings.url_model_path)
        except ModelLoadError as e:
            error = str(e)
            log.warning("%s", error)
        return cls(model=model, model_error=error, threat_intel=threat_intel,
                   weights=settings.weights, max_url_length=settings.max_url_length)

    def status(self):
        return {
            "url_model": {
                "loaded": self.model is not None,
                "error": self.model_error,
                **({"info": self.model.description} if self.model else {}),
            },
            "heuristics": {"loaded": True},
            "threat_intel": {"configured": self.threat_intel.configured,
                             "provider": self.threat_intel.name},
        }

    def threat_intel_health(self):
        """Live reachability of the threat-intel API (None if not configured)."""
        client = getattr(self.threat_intel, "client", None)
        if client is None:
            return None
        try:
            data = client.health()
            return {"reachable": True, "status": data.get("status"), "database": data.get("database")}
        except Exception as e:  # report, never raise
            return {"reachable": False, "error": str(e)}

    def _lookup_external(self, parsed, outcome=None):
        """Query the threat-intel provider. Never raises.

        status keys: configured, provider, available (source answered),
        checked (URL was actually checked), match ("url" | "host" | None),
        records, message, error.
        """
        status = {"configured": self.threat_intel.configured, "provider": self.threat_intel.name,
                  "available": False, "checked": False, "match": None, "records": [],
                  "message": "", "error": None}
        if outcome is None and not self.threat_intel.configured:
            status["message"] = "No threat-intelligence source is configured."
            return [], status
        try:
            outcome = outcome or self.threat_intel.lookup(parsed)
        except Exception as e:  # provider failures must never break analysis
            log.warning("Threat-intel provider %s failed: %s", self.threat_intel.name, e)
            status["error"] = f"{type(e).__name__}: {e}"
            status["message"] = f"Live threat intelligence unavailable: {e}"
            return [], status
        status.update({"available": True, "checked": True})
        status.update(outcome.details or {})
        return list(outcome.indicators), status

    def analyze(self, url, external_outcome=None):
        """Analyse one URL. Raises url_analysis.InvalidURLError for bad input.

        external_outcome: a threat_intel.LookupOutcome to use instead of querying
        the provider (when the caller already holds the threat-intel record).
        """
        parsed = parse_url(url, max_length=self.max_url_length)

        prediction, model_error = None, self.model_error
        if self.model is not None:
            try:
                prediction = self.model.predict(parsed)
            except Exception as e:
                log.exception("URL model prediction failed")
                model_error = f"Model prediction failed: {type(e).__name__}: {e}"

        heuristics = run_heuristics(parsed)
        external, external_status = self._lookup_external(parsed, external_outcome)

        assessment = score_url(
            prediction.probability if prediction else None,
            heuristics, external, self.weights,
        )
        explanation = explain_url(
            parsed, assessment, heuristics, prediction=prediction,
            model_info=self.model.description if self.model else None,
            model_error=model_error, external_indicators=external,
            external_status=external_status,
        )
        return {
            "url": parsed.original,
            "parsed": parsed.to_dict(),
            "score": assessment.score,
            "risk": assessment.band,
            "verdict": build_verdict(assessment, prediction, heuristics, external, external_status),
            "explanation": explanation,
        }
