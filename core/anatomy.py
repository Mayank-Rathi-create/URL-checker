"""
URL structure parsing, component decomposition, and homoglyph inspection.
"""

from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

import idna
import tldextract

from .models import URLAnatomy

# Bundled public suffix list extractor (runs 100% offline, zero network)
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# Mapping of deceptive Cyrillic/Greek/other Unicode characters commonly used to spoof Latin characters
HOMOGLYPH_MAP: dict[str, tuple[str, str]] = {
    # Cyrillic small letters mimicking Latin
    "\u0430": ("a", "Cyrillic small letter a"),
    "\u0441": ("c", "Cyrillic small letter es"),
    "\u0435": ("e", "Cyrillic small letter ie"),
    "\u0456": ("i", "Cyrillic small letter byelorussian-ukrainian i"),
    "\u0458": ("j", "Cyrillic small letter je"),
    "\u043E": ("o", "Cyrillic small letter o"),
    "\u0440": ("p", "Cyrillic small letter er"),
    "\u0445": ("x", "Cyrillic small letter ha"),
    "\u0443": ("y", "Cyrillic small letter u"),
    "\u0455": ("s", "Cyrillic small letter dze"),
    "\u043A": ("k", "Cyrillic small letter ka"),
    "\u0442": ("t", "Cyrillic small letter te"),
    "\u0501": ("d", "Cyrillic small letter komi de"),
    # Greek letters mimicking Latin
    "\u03BF": ("o", "Greek small letter omicron"),
    "\u03BD": ("v", "Greek small letter nu"),
    "\u03C1": ("p", "Greek small letter rho"),
    "\u03B9": ("i", "Greek small letter iota"),
    "\u03BA": ("k", "Greek small letter kappa"),
    "\u03C9": ("w", "Greek small letter omega"),
}


def normalize_input_url(raw: str) -> tuple[str, bool]:
    """
    Cleans raw input URL and ensures an appropriate scheme is present.
    Returns (cleaned_url, scheme_was_assumed).
    """
    text = raw.strip()
    # Strip wrapping quotes or brackets often copied from logs or emails
    text = text.strip("<>\"'[]`")

    risky_schemes = ("javascript:", "data:", "vbscript:", "file:", "mailto:", "blob:")
    if any(text.lower().startswith(s) for s in risky_schemes):
        return text, False

    if "://" not in text:
        return f"https://{text}", True
    return text, False


def is_obfuscated_or_raw_ip(host: str) -> tuple[bool, str]:
    """
    Detects if the host is a standard IPv4/IPv6 address or an obfuscated IP
    (e.g. hex 0x7f000001, octal 0177.0.0.1, or dword 2130706433).
    """
    # 1. Standard IP test
    try:
        ip_obj = ipaddress.ip_address(host)
        return True, str(ip_obj)
    except ValueError:
        pass

    # 2. Obfuscated integer (DWORD) IP
    if host.isdigit():
        try:
            val = int(host)
            if 0 <= val <= 0xFFFFFFFF:
                ip_obj = ipaddress.IPv4Address(val)
                return True, f"Obfuscated DWORD IP ({ip_obj})"
        except Exception:
            pass

    # 3. Hexadecimal IP notation (e.g., 0x7f.0x00.0x00.0x01 or 0x7f000001)
    if host.lower().startswith("0x"):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                ip_obj = ipaddress.IPv4Address(val)
                return True, f"Obfuscated Hex IP ({ip_obj})"
        except Exception:
            pass

    # 4. Octal notation (parts starting with 0 followed by digits)
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        if any(len(p) > 1 and p.startswith("0") for p in parts):
            try:
                dec_parts = [int(p, 8) if (len(p) > 1 and p.startswith("0")) else int(p, 10) for p in parts]
                if all(0 <= p <= 255 for p in dec_parts):
                    return True, f"Obfuscated Octal IP ({'.'.join(map(str, dec_parts))})"
            except Exception:
                pass

    return False, ""


def inspect_homoglyphs(host: str) -> tuple[bool, str, list[dict]]:
    """
    Decodes IDNA punycode and inspects for spoofed characters (homoglyphs).
    Returns (is_punycode_or_mixed, decoded_host, list_of_detected_homoglyphs).
    """
    is_punycode = "xn--" in host.lower()
    decoded_host = host

    if is_punycode:
        try:
            decoded_host = idna.decode(host)
        except Exception:
            decoded_host = host

    homoglyphs = []
    for idx, ch in enumerate(decoded_host):
        if ch in HOMOGLYPH_MAP:
            target_latin, desc = HOMOGLYPH_MAP[ch]
            homoglyphs.append({
                "index": idx,
                "char": ch,
                "codepoint": f"U+{ord(ch):04X}",
                "mimics": target_latin,
                "description": desc,
            })
        elif not ch.isascii() and ch not in (".", "-"):
            homoglyphs.append({
                "index": idx,
                "char": ch,
                "codepoint": f"U+{ord(ch):04X}",
                "mimics": "?",
                "description": unicodedata.name(ch, "Unknown non-ASCII character"),
            })

    has_deception = is_punycode or len(homoglyphs) > 0
    return has_deception, decoded_host, homoglyphs


def parse_url_anatomy(raw_url: str) -> URLAnatomy:
    """
    Deconstructs a URL into its structural security components.
    """
    normalized, assumed_scheme = normalize_input_url(raw_url)
    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return URLAnatomy(
            raw=raw_url,
            normalized=normalized,
            scheme="",
            host="",
            subdomain="",
            domain="",
            suffix="",
            registered_domain="",
        )

    # Check for credentials in authority (e.g. user:pass@evil.com)
    has_creds = bool(parsed.username or parsed.password or ("@" in parsed.netloc))

    # IP detection
    is_ip, ip_details = is_obfuscated_or_raw_ip(host)

    # TLD extraction
    if is_ip:
        subdomain = ""
        domain = host
        suffix = ""
        reg_domain = host
    else:
        ext = EXTRACTOR(host)
        subdomain = ext.subdomain.lower()
        domain = ext.domain.lower()
        suffix = ext.suffix.lower()
        reg_domain = f"{domain}.{suffix}" if suffix else host

    # Homoglyphs
    is_puny, decoded_host, homoglyphs = inspect_homoglyphs(host)

    return URLAnatomy(
        raw=raw_url,
        normalized=normalized,
        scheme=parsed.scheme.lower(),
        host=host,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registered_domain=reg_domain,
        port=port,
        path=parsed.path or "/",
        query=parsed.query or "",
        fragment=parsed.fragment or "",
        has_credentials=has_creds,
        is_ip=is_ip,
        is_punycode=is_puny,
        decoded_host=decoded_host,
        homoglyphs=homoglyphs,
    )
