"""
Wrapper around the trained URL phishing model.

The model is a scikit-learn Pipeline(StandardScaler -> LogisticRegression)
over the lexical features in phishshield.url_analysis.features. A linear
model was chosen so explanations are exact rather than approximated:

    logit = intercept + sum_i coef_i * (x_i - mean_i) / scale_i

Each term of the sum is that feature's contribution to the log-odds of
"phishing", measured relative to the average URL in the training data.

Security note: joblib/pickle files can execute code when loaded. Only load
model artifacts you trained yourself with train_url_model.py.
"""

import math
import os
from dataclasses import dataclass, field

import joblib
import numpy as np

from ..url_analysis.features import (
    FEATURE_NAMES, FEATURE_VERSION, SPEC_BY_NAME, extract_features, raw_feature_values,
)


class ModelLoadError(RuntimeError):
    """The model artifact is missing, unreadable or incompatible."""


@dataclass
class ModelPrediction:
    probability: float            # P(phishing), 0-1
    logit: float
    intercept: float
    contributions: list = field(default_factory=list)  # sorted by |contribution|

    def to_dict(self):
        return {"probability": self.probability, "logit": self.logit,
                "intercept": self.intercept, "contributions": self.contributions}


class URLPhishingModel:
    def __init__(self, artifact, path=""):
        self.path = path
        self.pipeline = artifact["pipeline"]
        self.feature_names = tuple(artifact["feature_names"])
        self.feature_version = str(artifact["feature_version"])
        self.metadata = artifact.get("metadata", {})
        self.metrics = artifact.get("metrics", {})

        if self.feature_version != FEATURE_VERSION or self.feature_names != FEATURE_NAMES:
            raise ModelLoadError(
                f"Model was trained with feature version {self.feature_version} but the code "
                f"uses version {FEATURE_VERSION}. Retrain with: python train_url_model.py"
            )
        try:
            self._scaler = self.pipeline.named_steps["scaler"]
            self._clf = self.pipeline.named_steps["clf"]
            self._coef = np.asarray(self._clf.coef_[0], dtype=float)
            self._intercept = float(self._clf.intercept_[0])
            classes = list(self._clf.classes_)
        except (AttributeError, KeyError, IndexError) as e:
            raise ModelLoadError(f"Model artifact has an unexpected structure: {e}") from None
        if classes != [0, 1]:
            raise ModelLoadError(f"Expected classes [0, 1] (1 = phishing), got {classes}")

    @property
    def description(self):
        ds = self.metadata.get("dataset", {})
        return {
            "algorithm": "Logistic regression on standardised lexical URL features",
            "feature_count": len(self.feature_names),
            "feature_version": self.feature_version,
            "trained_at": self.metadata.get("trained_at", ""),
            "dataset_name": ds.get("name", "unknown"),
            "dataset_citation": ds.get("citation", ""),
            "test_metrics": self.metrics.get("test", {}),
        }

    def predict(self, parsed):
        x = np.asarray([extract_features(parsed)], dtype=float)
        z = (x[0] - self._scaler.mean_) / self._scaler.scale_
        terms = self._coef * z
        logit = self._intercept + float(terms.sum())
        prob = 1.0 / (1.0 + math.exp(-logit))

        raw = raw_feature_values(parsed)
        contributions = []
        for name, term in zip(self.feature_names, terms):
            spec = SPEC_BY_NAME[name]
            contributions.append({
                "feature": name,
                "label": spec.label,
                "value": raw[name],
                "unit": spec.unit,
                "contribution": round(float(term), 4),
                "direction": "phishing" if term > 0 else "legitimate",
            })
        contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)
        return ModelPrediction(probability=round(prob, 4), logit=round(logit, 4),
                               intercept=round(self._intercept, 4), contributions=contributions)


def load_url_model(path):
    """Load a model artifact, raising ModelLoadError with a readable message."""
    if not os.path.exists(path):
        raise ModelLoadError(
            f"URL model not found at '{path}'. Train it with: python train_url_model.py "
            "(see README). The app will use heuristic indicators only."
        )
    try:
        artifact = joblib.load(path)
    except Exception as e:  # corrupt file, incompatible library version, ...
        raise ModelLoadError(f"Could not load URL model from '{path}': {e}") from None
    if not isinstance(artifact, dict) or "pipeline" not in artifact:
        raise ModelLoadError(f"'{path}' is not a PhishShield URL model artifact.")
    return URLPhishingModel(artifact, path=path)
