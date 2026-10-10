"""
Core offline heuristic analysis engine.
Inspects URLs thoroughly for deception, typosquatting, and suspicious attributes.
Guaranteed to never make network requests to the target URL.
"""

from __future__ import annotations

import difflib
import re
from urllib.parse import parse_qs, unquote, urlparse

from .anatomy import is_obfuscated_or_raw_ip, normalize_input_url, parse_url_anatomy
from .brands import (
    DANGEROUS_EXTENSIONS,
    OFFICIAL_DOMAINS,
    OPEN_REDIRECT_PARAMS,
    PHISHING_KEYWORDS,
    REPUTABLE_DOMAINS,
    SOURCES,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from .models import Analysis, FindingSeverity, URLAnatomy

LEET_TABLE = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "$": "s", "@": "a", "!": "i", "|": "l",
})


def normalize_leetspeak(text: str) -> str:
    """Normalize common character substitutions used in typosquatting."""
    lowered = text.lower().translate(LEET_TABLE)
    return lowered.replace("rn", "m").replace("vv", "w").replace("cl", "d")


def find_brand_impersonation(host: str, registered_domain: str, path: str) -> tuple[str, str, int] | None:
    """
    Evaluates whether the host or URL structure is attempting to impersonate a known brand.
    Returns (brand_name, explanation, risk_points) or None.
    """
    host_lower = host.lower()
    reg_lower = registered_domain.lower()
    norm_host = normalize_leetspeak(host_lower)
    tokens = [t for t in re.split(r"[.\-_/]", host_lower) if len(t) >= 3]
    norm_tokens = [normalize_leetspeak(t) for t in tokens]

    candidates: list[tuple[str, str, int]] = []

    for brand, domains in OFFICIAL_DOMAINS.items():
        # If the domain is already an official domain of this brand, skip
        if reg_lower in domains:
            continue

        primary_official = sorted(domains)[0]

        # 1. Exact brand in registered domain label (e.g. paypal-security.com or verify-paypal.net)
        reg_labels = reg_lower.split(".")
        if len(reg_labels) >= 2:
            main_label = reg_labels[0]
            norm_main = normalize_leetspeak(main_label)

            # Lookalike spelling (e.g., paypa1, rnicrosoft, googIe)
            if norm_main == brand and main_label != brand:
                candidates.append((
                    brand,
                    f"Typosquatting: '{main_label}' is a deceptive lookalike spelling of '{brand.title()}'. Official domain: {primary_official}.",
                    60,
                ))
            # Exact brand token in hyphenated domain (e.g., paypal-login.com, chase-update.org)
            elif brand in main_label.split("-"):
                candidates.append((
                    brand,
                    f"Brand keyword combo: '{main_label}' contains brand '{brand.title()}' on non-official domain '{reg_lower}'. Official domain: {primary_official}.",
                    50,
                ))
            # Fuzzy match (Levenshtein similarity >= 0.85)
            elif len(brand) >= 4 and len(norm_main) >= 4:
                sim = difflib.SequenceMatcher(None, norm_main, brand).ratio()
                if sim >= 0.85:
                    candidates.append((
                        brand,
                        f"Close misspelling: '{main_label}' is dangerously similar to '{brand.title()}' (similarity {int(sim*100)}%). Official domain: {primary_official}.",
                        55,
                    ))

        # 2. Subdomain Brand Spoofing (e.g., paypal.com.attacker.xyz, appleid.apple.com.auth-service.com)
        # Users often read subdomains left-to-right and mistake the brand subdomain for the real site.
        for off_dom in domains:
            if off_dom in host_lower and not host_lower.endswith(f".{off_dom}") and host_lower != off_dom:
                candidates.append((
                    brand,
                    f"Subdomain brand deception: The official address '{off_dom}' is placed in a subdomain, but the real destination is '{reg_lower}'.",
                    60,
                ))
                break

        # Brand name inside subdomains
        if any(t == brand or normalize_leetspeak(t) == brand for t in tokens[:-2]):
            candidates.append((
                brand,
                f"Subdomain spoofing: The brand name '{brand.title()}' appears in a prefix subdomain of '{reg_lower}'. Official domain: {primary_official}.",
                50,
            ))

        # 3. Brand in path for untrusted domain (e.g., sketchy.com/paypal/signin)
        path_lower = path.lower()
        if f"/{brand}/" in path_lower or path_lower.endswith(f"/{brand}"):
            candidates.append((
                brand,
                f"Brand name in path: '{brand.title()}' is referenced in URL path on third-party domain '{reg_lower}'.",
                20,
            ))

    return max(candidates, key=lambda c: c[2]) if candidates else None


def check_open_redirects(query_string: str) -> list[str]:
    """Detects parameters commonly exploited for open redirect attacks."""
    if not query_string:
        return []
    suspicious_redirects = []
    try:
        parsed_params = parse_qs(query_string, keep_blank_values=True)
        for key, vals in parsed_params.items():
            if key.lower() in OPEN_REDIRECT_PARAMS:
                for v in vals:
                    unquoted = unquote(v)
                    if unquoted.startswith(("http://", "https://", "//")):
                        suspicious_redirects.append(f"Param '{key}' targets '{unquoted[:40]}...'")
    except Exception:
        pass
    return suspicious_redirects


def analyze_url(raw_url: str, source: str = "A website I am browsing") -> Analysis:
    """
    Performs complete offline static security analysis of the provided URL.
    Never connects to or opens the link.
    """
    raw_clean = raw_url.strip()
    clean_url, assumed_scheme = normalize_input_url(raw_clean)
    anatomy = parse_url_anatomy(raw_clean)
    result = Analysis(url=clean_url, anatomy=anatomy, source_context=source)

    # 1. Scheme Validation
    risky_schemes = ("javascript:", "data:", "vbscript:", "file:", "blob:", "mailto:")
    if any(raw_clean.lower().startswith(s) for s in risky_schemes):
        scheme_found = raw_clean.split(":")[0].lower()
        result.add(
            FindingSeverity.BAD,
            f"Dangerous scheme '{scheme_found}:'",
            f"This URI uses the '{scheme_found}:' scheme which can directly execute arbitrary scripts, read local files, or trigger client-side exploits.",
            category="transport",
            points=85,
        )
        return result

    if not anatomy.host:
        result.add(
            FindingSeverity.BAD,
            "Missing or Malformed Host",
            "The URL does not contain a valid, resolvable host or domain name.",
            category="structure",
            points=70,
        )
        return result

    if assumed_scheme:
        result.add(
            FindingSeverity.INFO,
            "Scheme auto-assigned",
            "No protocol scheme was supplied in the input; 'https://' was assumed by default.",
            category="transport",
            points=0,
        )

    if anatomy.scheme == "https":
        result.add(
            FindingSeverity.GOOD,
            "HTTPS Transport Encryption",
            "Traffic over this connection is encrypted in transit using SSL/TLS. (Note: Phishing websites can also employ HTTPS certificates).",
            category="transport",
            points=0,
        )
    elif anatomy.scheme == "http":
        result.add(
            FindingSeverity.WARN,
            "Unencrypted HTTP Protocol",
            "The link uses plaintext HTTP. Communication is unencrypted and vulnerable to eavesdropping and Man-In-The-Middle interception.",
            category="transport",
            points=15,
        )
    else:
        result.add(
            FindingSeverity.WARN,
            f"Uncommon Scheme '{anatomy.scheme}'",
            f"Standard web pages operate over HTTP/HTTPS. The '{anatomy.scheme}' protocol is atypical for standard browsing.",
            category="transport",
            points=20,
        )

    # 2. Credential and Obfuscation Exploits
    if anatomy.has_credentials:
        result.add(
            FindingSeverity.BAD,
            "Embedded Authority / '@' Deception",
            "The URL contains text before an '@' sign. Browsers discard characters prior to '@', which is heavily abused to deceive users regarding the true destination.",
            category="structure",
            points=60,
        )

    # 3. IP Host Detection
    if anatomy.is_ip:
        result.add(
            FindingSeverity.BAD,
            "Direct IP Address Destination",
            f"The link points to a raw or obfuscated numerical IP ({anatomy.host}) rather than a named domain. Legitimate consumer services virtually always use branded domains.",
            category="identity",
            points=40,
        )
    else:
        # Check for obfuscated IP formats (e.g. hex/octal/dword)
        is_obf, obf_detail = is_obfuscated_or_raw_ip(anatomy.host)
        if is_obf:
            result.add(
                FindingSeverity.BAD,
                "Obfuscated IP Representation",
                f"The hostname uses an obfuscated integer/hexadecimal IP notation: {obf_detail}.",
                category="identity",
                points=50,
            )

    # 4. Port Anomalies
    if anatomy.port:
        if anatomy.port in (21, 22, 23, 25, 3389, 6667, 1337):
            result.add(
                FindingSeverity.BAD,
                f"High-Risk Non-Web Port :{anatomy.port}",
                f"Port {anatomy.port} is typically reserved for non-web services (SSH, FTP, SMTP, RDP) or malware command-and-control.",
                category="transport",
                points=35,
            )
        elif anatomy.port not in (80, 443, 8080, 8443):
            result.add(
                FindingSeverity.WARN,
                f"Non-Standard Port :{anatomy.port}",
                f"Websites rarely operate on port {anatomy.port}. Legitimate web services primarily use 80 or 443.",
                category="transport",
                points=10,
            )

    # 5. Punycode & Homoglyph Deception
    if anatomy.is_punycode or anatomy.homoglyphs:
        spoofed_chars = [f"'{h['char']}' ({h['description']}) mimicking Latin '{h['mimics']}'" for h in anatomy.homoglyphs[:3]]
        detail = (
            f"The domain contains internationalized characters or punycode ({anatomy.decoded_host}). "
            f"Detected spoofing characters: {'; '.join(spoofed_chars) if spoofed_chars else 'Punycode encoding'}."
        )
        result.add(
            FindingSeverity.BAD,
            "Homograph / Punycode Character Spoofing",
            detail,
            category="identity",
            points=55,
        )

    # 6. Official Brands & Reputable Domains
    reg_domain = anatomy.registered_domain.lower()

    # Check known official brands
    brand_match = next((b for b, doms in OFFICIAL_DOMAINS.items() if reg_domain in doms), None)
    if brand_match:
        result.official_brand = brand_match
        result.add(
            FindingSeverity.GOOD,
            f"Verified Official Domain ({brand_match.title()})",
            f"'{reg_domain}' is an authenticated, official registered domain of {brand_match.title()}.",
            category="identity",
            points=0,
        )
    elif reg_domain in REPUTABLE_DOMAINS:
        result.is_reputable_domain = True
        result.add(
            FindingSeverity.GOOD,
            "Recognized Reputable Domain",
            f"'{reg_domain}' is a recognized high-reputation public platform/institution.",
            category="identity",
            points=0,
        )
    else:
        # Check brand impersonation heuristics
        impersonation = find_brand_impersonation(anatomy.host, reg_domain, anatomy.path)
        if impersonation:
            brand, explanation, points = impersonation
            result.add(
                FindingSeverity.BAD,
                f"Suspected Brand Impersonation: {brand.title()}",
                explanation,
                category="identity",
                points=points,
            )

    # 7. URL Shorteners
    if reg_domain in URL_SHORTENERS or anatomy.host in URL_SHORTENERS:
        result.add(
            FindingSeverity.WARN,
            "URL Shortener Masking Destination",
            "This link uses a shortening service that obscures the real destination. Shortened links are frequently leveraged to bypass security scanners.",
            category="structure",
            points=25,
        )

    # 8. Suspicious Top-Level Domains (TLD)
    suffix = anatomy.suffix.split(".")[-1]
    if suffix in SUSPICIOUS_TLDS:
        result.add(
            FindingSeverity.WARN,
            f"High-Abuse Top-Level Domain (.{suffix})",
            f"The '.{suffix}' TLD exhibits elevated rates of spam, bulk automated registration, and phishing abuse.",
            category="identity",
            points=15,
        )

    # 9. Host Structural Characteristics
    if anatomy.subdomain:
        sub_parts = anatomy.subdomain.split(".")
        if len(sub_parts) >= 3:
            result.add(
                FindingSeverity.WARN,
                f"Deep Subdomain Chain ({len(sub_parts)} levels)",
                "Excessive nested subdomains are often constructed to push the real domain off-screen on mobile displays.",
                category="structure",
                points=12,
            )

    hyphen_count = anatomy.host.count("-")
    if hyphen_count >= 3:
        result.add(
            FindingSeverity.WARN,
            f"Excessive Hyphenation ({hyphen_count} hyphens)",
            "Multiple hyphens in domain names are a common hallmark of disposable phishing registrations.",
            category="structure",
            points=12,
        )

    # 10. Phishing Keywords
    if not result.official_brand:
        full_target = f"{anatomy.host}{anatomy.path}".lower()
        matched_keywords = sorted({k for k in PHISHING_KEYWORDS if k in full_target})
        if len(matched_keywords) >= 2:
            result.add(
                FindingSeverity.WARN,
                f"Phishing & Credential Keywords ({', '.join(matched_keywords[:4])})",
                f"The URL string contains multiple high-risk security/credential terms: {', '.join(matched_keywords)}.",
                category="structure",
                points=18,
            )

    # 11. Open Redirect Vector
    open_redirects = check_open_redirects(anatomy.query)
    if open_redirects:
        result.add(
            FindingSeverity.WARN,
            "Potential Open Redirect Parameter",
            f"The link contains redirect parameters pointing to external addresses ({', '.join(open_redirects[:2])}). Attackers abuse open redirects to disguise malicious targets behind legitimate domains.",
            category="structure",
            points=25,
        )

    # 12. Risky Executable File Downloads
    path_lower = anatomy.path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if path_lower.endswith(ext) or f"{ext}?" in path_lower:
            result.add(
                FindingSeverity.BAD,
                f"Executable / Dangerous Payload Download ({ext})",
                f"The URL directly targets an executable or script payload ({ext}). Opening this file can compromise your device.",
                category="structure",
                points=45,
            )
            break

    # 13. URL Length Check
    if len(clean_url) > 120:
        result.add(
            FindingSeverity.INFO,
            f"Long URL Length ({len(clean_url)} chars)",
            "Extremely lengthy URLs can obscure tracking tokens or deceptive target subdirectories.",
            category="structure",
            points=5,
        )

    # 14. Origin / Acquisition Context
    source_risk, source_note = SOURCES.get(source, (0, ""))
    if source_risk > 0:
        result.add(
            FindingSeverity.WARN if source_risk >= 15 else FindingSeverity.INFO,
            f"Link Origin: {source}",
            source_note,
            category="context",
            points=source_risk,
        )
    else:
        result.add(
            FindingSeverity.INFO,
            f"Link Origin: {source}",
            "Standard context provided with no elevated baseline risk.",
            category="context",
            points=0,
        )

    return result
