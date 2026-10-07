"""
Application configuration, read from environment variables.

Every setting has a safe default so the app runs with no configuration at all.
Invalid values raise ConfigError at startup instead of failing later.
"""

import os
from dataclasses import dataclass, field

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Optional .env file in the project root. Variables already set in the
# environment always win (override=False).
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"), override=False)
except ImportError:
    pass


class ConfigError(ValueError):
    """Raised when an environment variable holds an invalid value."""


def _env_bool(name, default):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    val = raw.strip().lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be a boolean (true/false), got {raw!r}")


def _env_number(name, default, cast, minimum=None, maximum=None):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        val = cast(raw.strip())
    except ValueError:
        raise ConfigError(f"{name} must be a {cast.__name__}, got {raw!r}") from None
    if minimum is not None and val < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {val}")
    if maximum is not None and val > maximum:
        raise ConfigError(f"{name} must be <= {maximum}, got {val}")
    return val


def _env_path(name, default_relative):
    raw = os.environ.get(name)
    path = raw.strip() if raw and raw.strip() else default_relative
    return path if os.path.isabs(path) else os.path.join(PROJECT_ROOT, path)


@dataclass(frozen=True)
class ScoringWeights:
    """Relative weights of each evidence source in the URL risk score.

    Weights are renormalised over the sources that are actually available,
    so a missing model or an absent threat-intel source never drags the
    score towards zero.
    """
    model: float = 0.6
    heuristic: float = 0.4
    external: float = 0.5   # only used when external indicators are supplied


@dataclass(frozen=True)
class Settings:
    url_model_path: str
    spam_model_path: str
    feedback_db_path: str
    enable_translation: bool
    enable_zero_shot: bool
    zero_shot_timeout: float
    max_message_chars: int
    max_url_length: int
    debug: bool
    host: str
    port: int
    weights: ScoringWeights = field(default_factory=ScoringWeights)
    # Threat-intel API (the separate collection service). Empty URL = not configured.
    threat_intel_api_url: str = ""
    threat_intel_api_key: str | None = field(default=None, repr=False)
    threat_intel_timeout: float = 5.0
    threat_intel_check_host: bool = True

    @classmethod
    def from_env(cls):
        weights = ScoringWeights(
            model=_env_number("PHISHSHIELD_WEIGHT_MODEL", 0.6, float, 0.0, 1.0),
            heuristic=_env_number("PHISHSHIELD_WEIGHT_HEURISTIC", 0.4, float, 0.0, 1.0),
            external=_env_number("PHISHSHIELD_WEIGHT_EXTERNAL", 0.5, float, 0.0, 1.0),
        )
        if weights.model + weights.heuristic <= 0:
            raise ConfigError("PHISHSHIELD_WEIGHT_MODEL and PHISHSHIELD_WEIGHT_HEURISTIC cannot both be 0")
        ti_url = (os.environ.get("THREAT_INTEL_API_URL") or "").strip().rstrip("/")
        if ti_url and not ti_url.startswith(("http://", "https://")):
            raise ConfigError(f"THREAT_INTEL_API_URL must start with http:// or https://, got {ti_url!r}")
        return cls(
            threat_intel_api_url=ti_url,
            threat_intel_api_key=(os.environ.get("THREAT_INTEL_API_KEY") or "").strip() or None,
            threat_intel_timeout=_env_number("THREAT_INTEL_API_TIMEOUT", 5.0, float, 0.5, 60.0),
            threat_intel_check_host=_env_bool("THREAT_INTEL_CHECK_HOST", True),
            url_model_path=_env_path("PHISHSHIELD_URL_MODEL_PATH", os.path.join("models", "url_model.joblib")),
            spam_model_path=_env_path("PHISHSHIELD_SPAM_MODEL_PATH", "spam_pipeline.joblib"),
            feedback_db_path=_env_path("PHISHSHIELD_FEEDBACK_DB", "feedback.db"),
            enable_translation=_env_bool("PHISHSHIELD_ENABLE_TRANSLATION", True),
            enable_zero_shot=_env_bool("PHISHSHIELD_ENABLE_ZERO_SHOT", True),
            zero_shot_timeout=_env_number("PHISHSHIELD_ZERO_SHOT_TIMEOUT", 30.0, float, 0.0, 600.0),
            max_message_chars=_env_number("PHISHSHIELD_MAX_MESSAGE_CHARS", 10000, int, 100, 1_000_000),
            max_url_length=_env_number("PHISHSHIELD_MAX_URL_LENGTH", 2048, int, 64, 65536),
            debug=_env_bool("FLASK_DEBUG", False),
            host=os.environ.get("PHISHSHIELD_HOST", "127.0.0.1"),
            port=_env_number("PHISHSHIELD_PORT", 5000, int, 1, 65535),
            weights=weights,
        )
