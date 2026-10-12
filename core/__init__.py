"""
Core package for URL security analysis.
"""

from .ai_checker import apply_ai_verification
from .anatomy import normalize_input_url, parse_url_anatomy
from .brands import OFFICIAL_DOMAINS, REPUTABLE_DOMAINS, SOURCES, URL_SHORTENERS
from .detector import analyze_url
from .models import (
    AIVerificationResult,
    Analysis,
    Finding,
    FindingSeverity,
    ThreatLevel,
    URLAnatomy,
)
from .scanners import apply_scanners

__all__ = [
    "AIVerificationResult",
    "Analysis",
    "Finding",
    "FindingSeverity",
    "ThreatLevel",
    "URLAnatomy",
    "analyze_url",
    "apply_ai_verification",
    "apply_scanners",
    "normalize_input_url",
    "parse_url_anatomy",
    "OFFICIAL_DOMAINS",
    "REPUTABLE_DOMAINS",
    "SOURCES",
    "URL_SHORTENERS",
]

