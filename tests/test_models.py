"""
Unit tests for data models, risk scoring, and threat level calculation.
"""

from __future__ import annotations

import unittest

from core.models import (
    AIVerificationResult,
    Analysis,
    Finding,
    FindingSeverity,
    ThreatLevel,
    URLAnatomy,
)


class TestModels(unittest.TestCase):
    """Test suite for Analysis models and threat level properties."""

    def setUp(self) -> None:
        self.anatomy = URLAnatomy(
            raw="https://example.com",
            normalized="https://example.com",
            scheme="https",
            host="example.com",
            registered_domain="example.com",
        )

    def test_score_calculation(self) -> None:
        analysis = Analysis(url="https://example.com", anatomy=self.anatomy)
        analysis.add(FindingSeverity.BAD, "Test Bad", "Detail", category="identity", points=30)
        analysis.add(FindingSeverity.WARN, "Test Warn", "Detail", category="structure", points=15)
        self.assertEqual(analysis.score, 45)

    def test_score_caps_at_100(self) -> None:
        analysis = Analysis(url="https://example.com", anatomy=self.anatomy)
        analysis.add(FindingSeverity.BAD, "Flag 1", "Detail", points=60)
        analysis.add(FindingSeverity.BAD, "Flag 2", "Detail", points=60)
        self.assertEqual(analysis.score, 100)

    def test_category_scores_breakdown(self) -> None:
        analysis = Analysis(url="https://example.com", anatomy=self.anatomy)
        analysis.add(FindingSeverity.BAD, "Identity Issue", "Detail", category="identity", points=25)
        analysis.add(FindingSeverity.WARN, "Transport Issue", "Detail", category="transport", points=10)
        breakdown = analysis.category_scores
        self.assertEqual(breakdown["identity"], 25)
        self.assertEqual(breakdown["transport"], 10)
        self.assertEqual(breakdown["structure"], 0)

    def test_threat_level_unverified_low_score_is_moderate(self) -> None:
        analysis = Analysis(url="https://unknown-domain.xyz", anatomy=self.anatomy)
        # Score is 0, but domain is neither official, reputable, scanner clean, nor AI verified
        self.assertEqual(analysis.score, 0)
        self.assertEqual(analysis.threat_level, ThreatLevel.MODERATE)

    def test_threat_level_official_brand_is_safe(self) -> None:
        analysis = Analysis(url="https://google.com", anatomy=self.anatomy, official_brand="google")
        self.assertEqual(analysis.score, 0)
        self.assertEqual(analysis.threat_level, ThreatLevel.SAFE)

    def test_threat_level_danger_on_high_score(self) -> None:
        analysis = Analysis(url="https://evil.com", anatomy=self.anatomy)
        analysis.add(FindingSeverity.BAD, "Severe Threat", "Detail", points=55)
        self.assertEqual(analysis.threat_level, ThreatLevel.DANGER)

    def test_finding_icon(self) -> None:
        f_bad = Finding(FindingSeverity.BAD, "Title", "Detail")
        f_warn = Finding(FindingSeverity.WARN, "Title", "Detail")
        f_good = Finding(FindingSeverity.GOOD, "Title", "Detail")
        f_info = Finding(FindingSeverity.INFO, "Title", "Detail")
        self.assertEqual(f_bad.icon, "🚨")
        self.assertEqual(f_warn.icon, "⚠️")
        self.assertEqual(f_good.icon, "✅")
        self.assertEqual(f_info.icon, "ℹ️")


if __name__ == "__main__":
    unittest.main()

