import math
import os

import joblib
import pytest

from phishshield.detection import ModelLoadError, load_url_model
from phishshield.url_analysis import parse_url


def test_missing_model_gives_clear_error(tmp_path):
    with pytest.raises(ModelLoadError, match="not found"):
        load_url_model(str(tmp_path / "nope.joblib"))


def test_wrong_artifact_rejected(tmp_path):
    path = tmp_path / "bad.joblib"
    joblib.dump({"something": 1}, path)
    with pytest.raises(ModelLoadError):
        load_url_model(str(path))


def test_corrupt_file_rejected(tmp_path):
    path = tmp_path / "corrupt.joblib"
    path.write_bytes(b"not a pickle")
    with pytest.raises(ModelLoadError):
        load_url_model(str(path))


def test_feature_version_mismatch_rejected(tmp_path, url_model):
    artifact = joblib.load(url_model.path)
    artifact["feature_version"] = "999"
    path = tmp_path / "old.joblib"
    joblib.dump(artifact, path)
    with pytest.raises(ModelLoadError, match="feature version"):
        load_url_model(str(path))


def test_probability_in_range(url_model):
    pred = url_model.predict(parse_url("https://example.com/"))
    assert 0.0 <= pred.probability <= 1.0


def test_contributions_reconstruct_logit_exactly(url_model):
    # The explanation is exact for a linear model: intercept + sum(terms) = logit.
    for url in ("https://www.wikipedia.org/wiki/Phishing",
                "http://paypa1-secure-login.example.xyz/webscr/verify?cmd=_login"):
        pred = url_model.predict(parse_url(url))
        total = pred.intercept + sum(c["contribution"] for c in pred.contributions)
        assert total == pytest.approx(pred.logit, abs=1e-3)
        assert pred.probability == pytest.approx(1 / (1 + math.exp(-pred.logit)), abs=1e-3)


def test_matches_sklearn_pipeline(url_model):
    from phishshield.url_analysis import extract_features
    p = parse_url("http://login.example-bank.xyz/verify")
    expected = url_model.pipeline.predict_proba([extract_features(p)])[0][1]
    assert url_model.predict(p).probability == pytest.approx(expected, abs=1e-4)


def test_model_metadata_present(url_model):
    d = url_model.description
    assert d["dataset_name"]
    assert {"accuracy", "precision", "recall", "f1", "roc_auc"} <= set(d["test_metrics"])


def test_obvious_cases_rank_sensibly(url_model):
    # Not an accuracy claim: just checks the model orders clear-cut examples sensibly.
    benign = url_model.predict(parse_url("https://www.wikipedia.org/")).probability
    phish = url_model.predict(parse_url(
        "http://secure-paypal.account-verify.example.ru/webscr/login/verify?cmd=_login&id=88123")).probability
    assert phish > benign
