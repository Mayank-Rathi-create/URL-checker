"""
Unit tests for the URL safety inspection engine.
"""

from __future__ import annotations

import unittest

from core.ai_checker import apply_ai_verification
from core.anatomy import is_obfuscated_or_raw_ip, parse_url_anatomy
from core.detector import analyze_url
from core.models import FindingSeverity, ThreatLevel


class TestURLDetector(unittest.TestCase):
    """Test suite for offline heuristic detection and AI verification."""

    def test_official_domain_safe(self) -> None:
        res = analyze_url("https://paypal.com")
        self.assertEqual(res.threat_level, ThreatLevel.SAFE)
        self.assertEqual(res.score, 0)
        self.assertTrue(any(f.level == FindingSeverity.GOOD and "Verified Official Domain" in f.title for f in res.findings))

    def test_typosquatting_lookalike(self) -> None:
        res = analyze_url("https://paypa1.com")
        self.assertEqual(res.threat_level, ThreatLevel.DANGER)
        self.assertGreaterEqual(res.score, 50)
        self.assertTrue(any("Impersonation" in f.title or "Typosquatting" in f.detail for f in res.findings))

    def test_subdomain_brand_impersonation(self) -> None:
        res = analyze_url("https://paypal.com.account-update.evil.xyz/login")
        self.assertEqual(res.threat_level, ThreatLevel.DANGER)
        self.assertTrue(any("Subdomain" in f.title for f in res.findings))

    def test_reputable_domain(self) -> None:
        res = analyze_url("https://en.wikipedia.org/wiki/Computer_security")
        self.assertEqual(res.threat_level, ThreatLevel.SAFE)
        self.assertEqual(res.score, 0)

    def test_url_shortener(self) -> None:
        res = analyze_url("https://bit.ly/3AbCd")
        self.assertEqual(res.threat_level, ThreatLevel.MODERATE)
        self.assertTrue(any("URL Shortener" in f.title for f in res.findings))

    def test_ip_address_host(self) -> None:
        res = analyze_url("http://192.168.1.1/admin")
        self.assertEqual(res.threat_level, ThreatLevel.DANGER)
        self.assertTrue(any("Direct IP Address" in f.title for f in res.findings))

    def test_dangerous_schemes(self) -> None:
        res = analyze_url("javascript:alert(1)")
        self.assertEqual(res.threat_level, ThreatLevel.DANGER)
        self.assertTrue(any("Dangerous scheme" in f.title for f in res.findings))

    def test_embedded_credentials(self) -> None:
        res = analyze_url("https://paypal.com@evil.com/signin")
        self.assertEqual(res.threat_level, ThreatLevel.DANGER)
        self.assertTrue(any("@" in f.title for f in res.findings))

    def test_punycode_homoglyph(self) -> None:
        # Cyrillic small letter a in paypal (xn--pypal-4ve.com)
        res = analyze_url("https://xn--pypal-4ve.com")
        self.assertEqual(res.threat_level, ThreatLevel.DANGER)
        self.assertTrue(any("Homograph" in f.title for f in res.findings))

    def test_open_redirect(self) -> None:
        res = analyze_url("https://legit-site.com/redirect?url=https://evil-target.com")
        self.assertTrue(any("Open Redirect" in f.title for f in res.findings))

    def test_dangerous_file_extension(self) -> None:
        res = analyze_url("https://example.com/invoice_update.exe")
        self.assertTrue(any("Dangerous Payload" in f.title for f in res.findings))

    def test_obfuscated_hex_ip(self) -> None:
        is_ip, detail = is_obfuscated_or_raw_ip("0x7f000001")
        self.assertTrue(is_ip)

    def test_unencrypted_http(self) -> None:
        res = analyze_url("http://example.com/login")
        self.assertTrue(any("Unencrypted HTTP" in f.title for f in res.findings))

    def test_ai_verification_safe_unlisted_domain(self) -> None:
        res = analyze_url("https://coddy.tech/journeys/c/logic_and_flow")
        apply_ai_verification(res)
        self.assertEqual(res.threat_level, ThreatLevel.SAFE)
        self.assertTrue(res.is_ai_verified)
        self.assertIsNotNone(res.ai_result)
        if res.ai_result:
            self.assertEqual(res.ai_result.status, "SAFE")
        self.assertIn("Safe & AI-Verified", res.verdict_summary[0])


if __name__ == "__main__":
    unittest.main()
