"""
Core package for URL security analysis and AI-powered threat verification.
"""

from .ai_checker import apply_ai_verification
from .anatomy import normalize_input_url, parse_url_anatomy
from .brands import (
    OFFICIAL_DOMAINS,
    REPUTABLE_DOMAINS,
    SOURCES,
    URL_SHORTENERS,
    get_official_brand,
    is_reputable_domain,
    is_url_shortener,
)
from .cache import ttl_cache
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
    "get_official_brand",
    "is_reputable_domain",
    "is_url_shortener",
    "normalize_input_url",
    "parse_url_anatomy",
    "ttl_cache",
    "OFFICIAL_DOMAINS",
    "REPUTABLE_DOMAINS",
    "SOURCES",
    "URL_SHORTENERS",
]
