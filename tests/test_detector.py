"""
Unit tests for the URL safety inspection engine.
"""

from __future__ import annotations

from core.anatomy import is_obfuscated_or_raw_ip, parse_url_anatomy
from core.detector import analyze_url
from core.models import FindingSeverity, ThreatLevel


def test_official_domain_safe():
    res = analyze_url("https://paypal.com")
    assert res.threat_level == ThreatLevel.SAFE
    assert res.score == 0
    assert any(f.level == FindingSeverity.GOOD and "Verified Official Domain" in f.title for f in res.findings)


def test_typosquatting_lookalike():
    res = analyze_url("https://paypa1.com")
    assert res.threat_level == ThreatLevel.DANGER
    assert res.score >= 50
    assert any("Impersonation" in f.title or "Typosquatting" in f.detail for f in res.findings)


def test_subdomain_brand_impersonation():
    res = analyze_url("https://paypal.com.account-update.evil.xyz/login")
    assert res.threat_level == ThreatLevel.DANGER
    assert any("Subdomain" in f.title for f in res.findings)


def test_reputable_domain():
    res = analyze_url("https://en.wikipedia.org/wiki/Computer_security")
    assert res.threat_level == ThreatLevel.SAFE
    assert res.score == 0


def test_url_shortener():
    res = analyze_url("https://bit.ly/3AbCd")
    assert res.threat_level == ThreatLevel.MODERATE
    assert any("URL Shortener" in f.title for f in res.findings)


def test_ip_address_host():
    res = analyze_url("http://192.168.1.1/admin")
    assert res.threat_level == ThreatLevel.DANGER
    assert any("Direct IP Address" in f.title for f in res.findings)


def test_dangerous_schemes():
    res = analyze_url("javascript:alert(1)")
    assert res.threat_level == ThreatLevel.DANGER
    assert any("Dangerous scheme" in f.title for f in res.findings)


def test_embedded_credentials():
    res = analyze_url("https://paypal.com@evil.com/signin")
    assert res.threat_level == ThreatLevel.DANGER
    assert any("@" in f.title for f in res.findings)


def test_punycode_homoglyph():
    # Cyrillic small letter a in paypal (xn--pypal-4ve.com)
    res = analyze_url("https://xn--pypal-4ve.com")
    assert res.threat_level == ThreatLevel.DANGER
    assert any("Homograph" in f.title for f in res.findings)


def test_open_redirect():
    res = analyze_url("https://legit-site.com/redirect?url=https://evil-target.com")
    assert any("Open Redirect" in f.title for f in res.findings)


def test_dangerous_file_extension():
    res = analyze_url("https://example.com/invoice_update.exe")
    assert any("Dangerous Payload" in f.title for f in res.findings)


def test_obfuscated_hex_ip():
    is_ip, detail = is_obfuscated_or_raw_ip("0x7f000001")
    assert is_ip is True


def test_unencrypted_http():
    res = analyze_url("http://example.com/login")
    assert any("Unencrypted HTTP" in f.title for f in res.findings)
