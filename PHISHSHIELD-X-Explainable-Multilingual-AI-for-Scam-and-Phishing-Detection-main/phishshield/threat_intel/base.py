"""
Interface for external threat intelligence.

The analysis service talks to threat-intelligence sources only through
ThreatIntelProvider. Two implementations exist:

    NullThreatIntelProvider   used when no source is configured; returns nothing
    ThreatIntelAPIProvider    (api_provider.py) queries the separate
                              "Real-Time Phishing URL Collection & Threat
                              Intelligence API" service over REST

Providers return ThreatIndicator objects. The risk engine and explainer
consume those; they never see raw API responses.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field

VERDICTS = ("malicious", "suspicious", "benign", "unknown")


@dataclass(frozen=True)
class ThreatIndicator:
    """One finding reported by an external source about a URL or domain."""
    source: str             # name of the provider that produced it
    indicator_type: str     # e.g. "url", "host", "domain", "ip"
    value: str              # the URL/domain/IP the finding refers to
    verdict: str            # one of VERDICTS
    confidence: float       # 0.0 - 1.0 used for scoring; see confidence_basis
    description: str = ""
    observed_at: str = ""   # ISO-8601 timestamp from the source, if any
    reference: str = ""     # link or ID in the source system, if any
    # Where `confidence` comes from: reported by the source, or a documented
    # PhishShield policy value when the source publishes no confidence.
    confidence_basis: str = ""
    details: dict = field(default_factory=dict, hash=False, compare=False)

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}, got {self.verdict!r}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self):
        return asdict(self)


@dataclass
class LookupOutcome:
    """Result of one provider lookup: indicators plus facts about the lookup
    itself (was the source reachable, what matched, the records it returned)."""
    indicators: list = field(default_factory=list)
    details: dict = field(default_factory=dict)


class ThreatIntelProvider(ABC):
    """Interface every external threat-intelligence client must implement."""

    name = "abstract"

    @abstractmethod
    def lookup_url(self, parsed_url):
        """Return a list of ThreatIndicator for a phishshield ParsedURL.

        Implementations must not raise for "not found"; return [] instead.
        Network or service errors may raise; the caller records them and
        continues with model + heuristic evidence only.
        """

    def lookup(self, parsed_url):
        """Like lookup_url, but also returns lookup details. Override to add details."""
        return LookupOutcome(indicators=list(self.lookup_url(parsed_url)))

    @property
    def configured(self):
        return True


class NullThreatIntelProvider(ThreatIntelProvider):
    """Default provider: no external source configured, never returns data."""

    name = "none"

    def lookup_url(self, parsed_url):
        return []

    @property
    def configured(self):
        return False
