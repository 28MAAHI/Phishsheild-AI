from .api_provider import ThreatIntelAPIProvider
from .base import LookupOutcome, NullThreatIntelProvider, ThreatIndicator, ThreatIntelProvider, VERDICTS
from .threat_intel_client import ThreatIntelClient, ThreatIntelError


def build_provider(settings):
    """Provider for the configured threat-intel API, or the null provider if none is configured."""
    if not settings.threat_intel_api_url:
        return NullThreatIntelProvider()
    client = ThreatIntelClient(settings.threat_intel_api_url, api_key=settings.threat_intel_api_key,
                               timeout=settings.threat_intel_timeout)
    return ThreatIntelAPIProvider(client, check_host=settings.threat_intel_check_host)


__all__ = ["ThreatIndicator", "ThreatIntelProvider", "NullThreatIntelProvider", "VERDICTS", "LookupOutcome",
           "ThreatIntelAPIProvider", "ThreatIntelClient", "ThreatIntelError", "build_provider"]
