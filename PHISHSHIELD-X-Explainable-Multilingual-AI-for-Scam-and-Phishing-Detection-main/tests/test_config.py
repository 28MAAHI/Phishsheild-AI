import pytest

from phishshield.config import ConfigError, Settings


def test_defaults(monkeypatch):
    for k in ("PHISHSHIELD_WEIGHT_MODEL", "PHISHSHIELD_MAX_URL_LENGTH", "FLASK_DEBUG"):
        monkeypatch.delenv(k, raising=False)
    s = Settings.from_env()
    assert s.weights.model == 0.6 and s.weights.heuristic == 0.4
    assert s.max_url_length == 2048
    assert s.debug is False
    assert s.url_model_path.endswith("url_model.joblib")


@pytest.mark.parametrize("name,value", [
    ("PHISHSHIELD_ENABLE_TRANSLATION", "maybe"),
    ("PHISHSHIELD_WEIGHT_MODEL", "abc"),
    ("PHISHSHIELD_WEIGHT_MODEL", "1.5"),
    ("PHISHSHIELD_PORT", "70000"),
])
def test_invalid_values_raise(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError):
        Settings.from_env()


def test_both_main_weights_zero_rejected(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_WEIGHT_MODEL", "0")
    monkeypatch.setenv("PHISHSHIELD_WEIGHT_HEURISTIC", "0")
    with pytest.raises(ConfigError):
        Settings.from_env()
