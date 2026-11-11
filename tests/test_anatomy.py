"""
Unit tests for URL anatomy parsing, homoglyph detection, and IP obfuscation.
"""

from __future__ import annotations

import unittest

from core.anatomy import (
    inspect_homoglyphs,
    is_obfuscated_or_raw_ip,
    normalize_input_url,
    parse_url_anatomy,
)


class TestURLAnatomy(unittest.TestCase):
    """Test suite for URL anatomy, normalization, and character deception."""

    def test_normalize_assumed_scheme(self) -> None:
        url, assumed = normalize_input_url("example.com/test")
        self.assertEqual(url, "https://example.com/test")
        self.assertTrue(assumed)

    def test_normalize_explicit_scheme(self) -> None:
        url, assumed = normalize_input_url("http://example.com/test")
        self.assertEqual(url, "http://example.com/test")
        self.assertFalse(assumed)

    def test_normalize_protocol_relative(self) -> None:
        url, assumed = normalize_input_url("//example.com/test")
        self.assertEqual(url, "https://example.com/test")
        self.assertTrue(assumed)

    def test_normalize_empty_url(self) -> None:
        url, assumed = normalize_input_url("   ")
        self.assertEqual(url, "")
        self.assertFalse(assumed)

    def test_normalize_strips_brackets_quotes(self) -> None:
        url, assumed = normalize_input_url("<https://example.com/path>")
        self.assertEqual(url, "https://example.com/path")
        self.assertFalse(assumed)

    def test_risky_scheme_preserved(self) -> None:
        url, assumed = normalize_input_url("javascript:alert(1)")
        self.assertEqual(url, "javascript:alert(1)")
        self.assertFalse(assumed)

    def test_raw_ipv4_detection(self) -> None:
        is_ip, detail = is_obfuscated_or_raw_ip("127.0.0.1")
        self.assertTrue(is_ip)
        self.assertEqual(detail, "127.0.0.1")

    def test_dword_ip_detection(self) -> None:
        is_ip, detail = is_obfuscated_or_raw_ip("2130706433")  # 127.0.0.1
        self.assertTrue(is_ip)
        self.assertIn("Obfuscated DWORD IP", detail)

    def test_hex_ip_detection(self) -> None:
        is_ip, detail = is_obfuscated_or_raw_ip("0x7f000001")
        self.assertTrue(is_ip)
        self.assertIn("Obfuscated Hex IP", detail)

    def test_octal_ip_detection(self) -> None:
        is_ip, detail = is_obfuscated_or_raw_ip("0177.0.0.1")
        self.assertTrue(is_ip)
        self.assertIn("Obfuscated Octal IP", detail)

    def test_empty_host_not_ip(self) -> None:
        is_ip, detail = is_obfuscated_or_raw_ip("")
        self.assertFalse(is_ip)
        self.assertEqual(detail, "")

    def test_standard_hostname_not_ip(self) -> None:
        is_ip, _ = is_obfuscated_or_raw_ip("google.com")
        self.assertFalse(is_ip)

    def test_homoglyph_detection(self) -> None:
        has_deception, decoded, homoglyphs = inspect_homoglyphs("p\u0430ypal.com")
        self.assertTrue(has_deception)
        self.assertGreater(len(homoglyphs), 0)
        self.assertEqual(homoglyphs[0]["char"], "\u0430")
        self.assertEqual(homoglyphs[0]["mimics"], "a")

    def test_empty_host_homoglyphs(self) -> None:
        has_deception, decoded, homoglyphs = inspect_homoglyphs("")
        self.assertFalse(has_deception)
        self.assertEqual(decoded, "")
        self.assertEqual(homoglyphs, [])

    def test_parse_url_anatomy_components(self) -> None:
        anatomy = parse_url_anatomy("https://sub.portal.example.com:8443/auth/login?ref=123#top")
        self.assertEqual(anatomy.scheme, "https")
        self.assertEqual(anatomy.host, "sub.portal.example.com")
        self.assertEqual(anatomy.subdomain, "sub.portal")
        self.assertEqual(anatomy.domain, "example")
        self.assertEqual(anatomy.suffix, "com")
        self.assertEqual(anatomy.registered_domain, "example.com")
        self.assertEqual(anatomy.port, 8443)
        self.assertEqual(anatomy.path, "/auth/login")
        self.assertEqual(anatomy.query, "ref=123")
        self.assertEqual(anatomy.fragment, "top")
        self.assertFalse(anatomy.has_credentials)
        self.assertFalse(anatomy.is_ip)
        self.assertEqual(anatomy.ip_detail, "")


if __name__ == "__main__":
    unittest.main()
