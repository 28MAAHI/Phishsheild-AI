"""
PhishShield X core package.

Sub-packages are deliberately independent so each can be maintained or
replaced on its own:

    url_analysis/   URL parsing, lexical feature extraction, rule-based heuristics
    detection/      Trained URL phishing model (load / predict / explain)
    scoring/        Transparent risk-scoring engine
    explain/        Human-readable explanation builder
    threat_intel/   Interface for future external threat-intelligence sources
                    (no client is implemented; the default provider returns nothing)
    service.py      Orchestrates the components above for a single URL
"""

__version__ = "2.1.0"
