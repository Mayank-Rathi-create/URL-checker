"""
Data models for URL analysis results and findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ThreatLevel(str, Enum):
    SAFE = "Safe"
    MODERATE = "Moderate"
    DANGER = "Danger"


class FindingSeverity(str, Enum):
    GOOD = "good"
    INFO = "info"
    WARN = "warn"
    BAD = "bad"


@dataclass
class Finding:
    """A single diagnostic finding or observation about the URL."""
    level: FindingSeverity
    title: str
    detail: str
    category: str = "general"  # identity | structure | transport | context | intelligence
    points: int = 0            # Risk points contributed (0-100 scale)

    @property
    def icon(self) -> str:
        if self.level == FindingSeverity.BAD:
            return "🚨"
        if self.level == FindingSeverity.WARN:
            return "⚠️"
        if self.level == FindingSeverity.GOOD:
            return "✅"
        return "ℹ️"


@dataclass
class URLAnatomy:
    """Structural breakdown of the parsed URL."""
    raw: str
    normalized: str
    scheme: str = ""
    host: str = ""
    subdomain: str = ""
    domain: str = ""
    suffix: str = ""
    registered_domain: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    has_credentials: bool = False
    is_ip: bool = False
    is_punycode: bool = False
    decoded_host: str = ""
    homoglyphs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Analysis:
    """Complete security assessment result."""
    url: str
    anatomy: URLAnatomy
    findings: list[Finding] = field(default_factory=list)
    official_brand: str | None = None
    is_reputable_domain: bool = False
    scanner_clean: bool = False
    scanners_used: list[str] = field(default_factory=list)
    scanner_notes: list[str] = field(default_factory=list)
    source_context: str = ""

    def add(
        self,
        level: FindingSeverity | str,
        title: str,
        detail: str,
        category: str = "general",
        points: int = 0,
    ) -> None:
        if isinstance(level, str):
            level = FindingSeverity(level)
        self.findings.append(Finding(level=level, title=title, detail=detail, category=category, points=points))

    @property
    def score(self) -> int:
        """Normalized overall risk score between 0 and 100."""
        raw_sum = sum(f.points for f in self.findings)
        # Cap score between 0 and 100
        return max(0, min(100, raw_sum))

    @property
    def threat_level(self) -> ThreatLevel:
        """Calculates final threat level incorporating verification state."""
        score = self.score
        if score >= 50:
            return ThreatLevel.DANGER
        if score >= 20:
            return ThreatLevel.MODERATE
        
        # When score is low (0-19):
        # Site is verified if it's an official brand domain, a known reputable domain, or clean in scanners
        is_verified = self.official_brand is not None or self.is_reputable_domain or self.scanner_clean
        if not is_verified:
            # Low risk heuristics, but not on verified whitelist
            return ThreatLevel.MODERATE
        return ThreatLevel.SAFE

    @property
    def category_scores(self) -> dict[str, int]:
        """Breakdown of points by category."""
        scores = {
            "identity": 0,
            "structure": 0,
            "transport": 0,
            "context": 0,
            "intelligence": 0,
        }
        for f in self.findings:
            if f.category in scores:
                scores[f.category] += f.points
            else:
                scores["structure"] += f.points
        return scores

    @property
    def verdict_summary(self) -> tuple[str, str]:
        """Short title and explanatory sentence for the verdict."""
        level = self.threat_level
        if level == ThreatLevel.DANGER:
            return (
                "High Risk / Do Not Click",
                "Strong indicators of deception, phishing, or malicious behavior detected."
            )
        if level == ThreatLevel.MODERATE:
            if self.score < 20:
                return (
                    "Caution / Unverified Domain",
                    "No direct red flags were detected, but this domain is not on known official directories and lacks external scanner verification."
                )
            return (
                "Moderate Risk / Proceed With Caution",
                "Suspicious characteristics or atypical link attributes were detected."
            )
        return (
            "Safe & Verified",
            "No red flags detected, and the destination matches an authentic, reputable service."
        )
