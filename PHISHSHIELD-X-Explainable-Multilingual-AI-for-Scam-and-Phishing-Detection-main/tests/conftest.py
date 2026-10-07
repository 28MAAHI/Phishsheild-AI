import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Configure the app for tests BEFORE it is imported anywhere:
# no network translation, no 1.6 GB zero-shot model, throwaway feedback DB.
_TMP = tempfile.mkdtemp(prefix="phishshield-tests-")
os.environ["PHISHSHIELD_ENABLE_TRANSLATION"] = "false"
os.environ["PHISHSHIELD_ENABLE_ZERO_SHOT"] = "false"
os.environ["PHISHSHIELD_FEEDBACK_DB"] = os.path.join(_TMP, "feedback-test.db")
# Never contact a real threat-intel API from tests (overrides any .env value);
# integration tests point the client at a local stub server instead.
os.environ["THREAT_INTEL_API_URL"] = ""
os.environ["THREAT_INTEL_API_KEY"] = ""

URL_MODEL_PATH = os.path.join(ROOT, "models", "url_model.joblib")
requires_url_model = pytest.mark.skipif(
    not os.path.exists(URL_MODEL_PATH),
    reason="URL model not trained (run scripts/download_url_dataset.py and train_url_model.py)",
)


@pytest.fixture(scope="session")
def url_model():
    from phishshield.detection import load_url_model
    if not os.path.exists(URL_MODEL_PATH):
        pytest.skip("URL model not trained")
    return load_url_model(URL_MODEL_PATH)


@pytest.fixture(scope="session")
def flask_app():
    import app as app_module
    app_module.app.config["TESTING"] = True
    return app_module


@pytest.fixture()
def client(flask_app):
    return flask_app.app.test_client()
