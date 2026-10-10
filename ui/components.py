"""
Reusable UI components for the URL Safety Inspector.
Crafted for clean aesthetics, readability, and modern ergonomics.
"""

from __future__ import annotations

import html
import json
from typing import Any

import streamlit as st

from core.models import Analysis, FindingSeverity, ThreatLevel


def render_header() -> None:
    """Renders the top branding and header."""
    st.markdown(
        """
        <div class="hero-container">
            <div style="font-size:2.6rem; line-height:1; margin-bottom:8px;">🛡️</div>
            <div class="hero-title">URL Safety Checker</div>
            <div class="hero-subtitle">
                Inspect links for phishing, impersonation, and hidden threats before you click.<br>
                <span style="font-size:0.85rem; color:var(--safe-text); font-weight:600;">🔒 Zero-Click Guarantee: We never connect to or load the target URL.</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_verdict_card(analysis: Analysis) -> None:
    """Renders the top-level security verdict with a visual risk gauge."""
    score = analysis.score
    threat = analysis.threat_level
    title, summary = analysis.verdict_summary

    if threat == ThreatLevel.SAFE:
        card_class = "safe"
        badge_icon = "✅"
        gauge_color = "#10B981"
        tag_text = "AUTHENTIC / SAFE"
    elif threat == ThreatLevel.MODERATE:
        card_class = "moderate"
        badge_icon = "⚠️"
        gauge_color = "#F59E0B"
        tag_text = "CAUTION / MODERATE RISK"
    else:
        card_class = "danger"
        badge_icon = "🚨"
        gauge_color = "#EF4444"
        tag_text = "HIGH RISK / SUSPICIOUS"

    st.markdown(
        f"""
        <div class="verdict-card {card_class}">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="font-size:0.78rem; font-weight:800; letter-spacing:1px; text-transform:uppercase;">
                    {tag_text}
                </span>
                <span style="font-size:0.9rem; font-weight:700;">
                    Risk Score: {score}/100
                </span>
            </div>
            <div class="verdict-headline">
                <span>{badge_icon}</span>
                <span>{title}</span>
            </div>
            <div class="verdict-subtext">
                {summary}
            </div>
            <div class="gauge-wrapper">
                <div class="gauge-label-row">
                    <span>Threat Exposure Meter</span>
                    <span>{score}%</span>
                </div>
                <div class="gauge-track">
                    <div class="gauge-fill" style="width: {score}%; background: {gauge_color};"></div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metrics_grid(analysis: Analysis) -> None:
    """Displays a responsive 4-column metric grid."""
    c1, c2, c3, c4 = st.columns(4)

    # 1. Risk Score
    score = analysis.score
    score_desc = "Safe range" if score < 20 else ("Moderate risk" if score < 50 else "High threat")
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-card-title">Risk Score</div>
                <div class="metric-card-val">{score} <span style="font-size:0.85rem; font-weight:500; color:var(--text-muted);">/ 100</span></div>
                <div class="metric-card-sub">{score_desc}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 2. Destination Domain
    dom = analysis.anatomy.registered_domain or analysis.anatomy.host or "Unknown"
    with c2:
        status = "Official Brand" if analysis.official_brand else ("Reputable" if analysis.is_reputable_domain else "Unverified")
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-card-title">Registered Domain</div>
                <div class="metric-card-val" style="font-size:1.15rem; word-break:break-all;">{dom}</div>
                <div class="metric-card-sub">{status}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 3. Transport Security
    proto = analysis.anatomy.scheme.upper() or "-"
    is_https = analysis.anatomy.scheme == "https"
    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-card-title">Transport Protocol</div>
                <div class="metric-card-val" style="font-size:1.15rem;">
                    {"🔒 " if is_https else "🔓 "}{proto}
                </div>
                <div class="metric-card-sub">{"Encrypted (TLS)" if is_https else "Unencrypted plaintext"}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 4. Intelligence & Origin
    with c4:
        num_red_flags = len([f for f in analysis.findings if f.level == FindingSeverity.BAD])
        num_warns = len([f for f in analysis.findings if f.level == FindingSeverity.WARN])
        flag_summary = f"{num_red_flags} red flags, {num_warns} warnings" if (num_red_flags or num_warns) else "0 alerts detected"
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-card-title">Signals Detected</div>
                <div class="metric-card-val" style="font-size:1.15rem;">{len(analysis.findings)} Findings</div>
                <div class="metric-card-sub">{flag_summary}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_url_anatomy(analysis: Analysis) -> None:
    """Renders the decomposed URL anatomy into color-coded structural pills."""
    anat = analysis.anatomy
    st.markdown(
        """
        <div class="anatomy-box">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-size:0.86rem; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-secondary);">
                    🔍 URL Structural Anatomy Breakdown
                </span>
                <span style="font-size:0.78rem; color:var(--text-muted);">
                    The real destination is the <b>Registered Domain</b>, not subdomains
                </span>
            </div>
            <div class="anatomy-pill-row">
        """,
        unsafe_allow_html=True,
    )

    pills_html = []
    # Scheme
    if anat.scheme:
        pills_html.append(f'<span class="anatomy-pill"><span class="pill-tag">Scheme</span><span class="pill-val">{anat.scheme}://</span></span>')

    # Subdomain
    if anat.subdomain:
        pills_html.append(f'<span class="anatomy-pill"><span class="pill-tag">Subdomain</span><span class="pill-val">{anat.subdomain}.</span></span>')

    # Registered Domain (Prominently styled)
    if anat.registered_domain:
        pills_html.append(f'<span class="anatomy-pill registered"><span class="pill-tag">Real Domain</span><span class="pill-val">{anat.registered_domain}</span></span>')

    # Port
    if anat.port:
        pills_html.append(f'<span class="anatomy-pill"><span class="pill-tag">Port</span><span class="pill-val">:{anat.port}</span></span>')

    # Path
    if anat.path and anat.path != "/":
        path_disp = anat.path if len(anat.path) < 35 else f"{anat.path[:32]}..."
        pills_html.append(f'<span class="anatomy-pill"><span class="pill-tag">Path</span><span class="pill-val">{html.escape(path_disp)}</span></span>')

    # Query
    if anat.query:
        query_disp = f"?{anat.query[:28]}..." if len(anat.query) > 30 else f"?{anat.query}"
        pills_html.append(f'<span class="anatomy-pill"><span class="pill-tag">Query</span><span class="pill-val">{html.escape(query_disp)}</span></span>')

    st.markdown("".join(pills_html) + "</div></div>", unsafe_allow_html=True)


def render_homoglyphs_alert(analysis: Analysis) -> None:
    """Highlights homoglyph spoofing details if present."""
    anat = analysis.anatomy
    if not (anat.is_punycode or anat.homoglyphs):
        return

    st.markdown(
        """
        <div style="background:var(--danger-bg); border:1.5px solid var(--danger-border); border-radius:14px; padding:18px; margin-bottom:20px;">
            <div style="display:flex; align-items:center; gap:8px; font-weight:800; font-size:1.1rem; color:var(--danger-text); margin-bottom:8px;">
                <span>⚠️</span> <span>Homograph / Character Deception Detected!</span>
            </div>
            <div style="font-size:0.9rem; color:var(--text-secondary); line-height:1.45;">
                This address uses characters that visually mimic Latin letters to impersonate legitimate brand domains.
            </div>
            <div style="margin-top:12px; font-family:'JetBrains Mono', monospace; font-size:0.88rem; background:rgba(0,0,0,0.15); padding:10px 14px; border-radius:8px;">
        """,
        unsafe_allow_html=True,
    )

    for h in anat.homoglyphs:
        st.markdown(
            f"• Spoofed letter: `<b style='color:#EF4444; font-size:1.1rem;'>{h['char']}</b>` "
            f"({h['codepoint']} - {h['description']}) disguising Latin `<b>{h['mimics']}</b>`",
            unsafe_allow_html=True,
        )

    st.markdown("</div></div>", unsafe_allow_html=True)


def render_hover_preview(analysis: Analysis) -> None:
    """Renders non-clickable hover preview with safe copy mechanism."""
    safe_url = html.escape(analysis.url)
    st.markdown(
        f"""
        <div class="preview-box">
            <div style="font-size:0.8rem; font-weight:700; text-transform:uppercase; color:var(--text-muted); margin-bottom:6px;">
                Zero-Click Safe Preview (Not Clickable)
            </div>
            <div class="preview-link" title="Target: {safe_url}">
                {safe_url}
            </div>
            <div style="font-size:0.78rem; color:var(--text-muted); margin-top:8px;">
                Hover over the link above to inspect the target destination. This app never connects to or executes remote code.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_findings_list(analysis: Analysis) -> None:
    """Renders categorized findings with risk indicators."""
    groups = [
        ("🚨 Critical Red Flags", (FindingSeverity.BAD,), True),
        ("⚠️ Warnings & Anomalies", (FindingSeverity.WARN,), True),
        ("✅ Verified Safeguards", (FindingSeverity.GOOD,), False),
        ("ℹ️ Context & Information", (FindingSeverity.INFO,), False),
    ]

    for title, levels, default_open in groups:
        matching = [f for f in analysis.findings if f.level in levels]
        if not matching:
            continue

        with st.expander(f"{title} ({len(matching)})", expanded=default_open):
            for finding in matching:
                points_badge = f'<span class="finding-points">+{finding.points} Risk</span>' if finding.points > 0 else ""
                st.markdown(
                    f"""
                    <div class="finding-row">
                        <div class="finding-icon">{finding.icon}</div>
                        <div class="finding-content">
                            <div class="finding-header">
                                <span class="finding-title">{finding.title}</span>
                                {points_badge}
                            </div>
                            <div class="finding-detail">{finding.detail}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    if analysis.scanner_notes:
        with st.expander("ℹ️ External Scanner Diagnostics", expanded=False):
            for note in analysis.scanner_notes:
                st.info(note)


def render_export_report(analysis: Analysis) -> None:
    """Offers quick report copying and raw JSON export."""
    col1, col2 = st.columns([1, 1])

    report_lines = [
        f"# URL Safety Report: {analysis.anatomy.registered_domain or analysis.anatomy.host}",
        f"- Target URL: `{analysis.url}`",
        f"- Verdict: **{analysis.threat_level.value}** ({analysis.score}/100 Risk Score)",
        f"- Transport: {analysis.anatomy.scheme.upper()} ({'Encrypted' if analysis.anatomy.scheme == 'https' else 'Unencrypted'})",
        f"- Origin Context: {analysis.source_context}",
        "\n### Key Findings:",
    ]
    for f in analysis.findings:
        pts = f" (+{f.points} risk)" if f.points else ""
        report_lines.append(f"- [{f.icon}] **{f.title}**{pts}: {f.detail}")

    report_text = "\n".join(report_lines)

    with col1:
        st.download_button(
            "📋 Download Markdown Report",
            data=report_text,
            file_name=f"url-report-{analysis.anatomy.registered_domain or 'scan'}.md",
            mime="text/markdown",
            use_container_width=True,
        )

    with col2:
        export_data = {
            "url": analysis.url,
            "threat_level": analysis.threat_level.value,
            "score": analysis.score,
            "registered_domain": analysis.anatomy.registered_domain,
            "findings": [
                {"level": f.level.value, "title": f.title, "points": f.points, "detail": f.detail}
                for f in analysis.findings
            ],
        }
        st.download_button(
            "💾 Download JSON Data",
            data=json.dumps(export_data, indent=2),
            file_name="url-analysis.json",
            mime="application/json",
            use_container_width=True,
        )


def render_threat_guide() -> None:
    """Educational guide explaining common link attack vectors."""
    st.markdown("### 📚 Phishing Tactics & URL Deception Cheat Sheet")
    st.write(
        "Attackers use a variety of deceptive techniques to make malicious links appear legitimate. "
        "Here is how to recognize the most prevalent vectors:"
    )

    t1, t2, t3, t4 = st.tabs(["🔤 Typosquatting", "🎭 Subdomain Deception", "🪞 Homograph / Punycode", "🔗 Open Redirects"])

    with t1:
        st.markdown(
            """
            #### What is Typosquatting?
            Typosquatting involves registering misspelled versions of popular brand domains to capture users who make typing mistakes or to deceive victims in emails.

            - **Character Swapping:** Replacing letters with visually identical numbers (e.g., `paypa1.com` instead of `paypal.com`).
            - **Double/Omitted Letters:** `gooogle.com` or `amzon.com`.
            - **Combo Squatting:** Adding keywords like `-security`, `-login`, or `-verify` (e.g., `paypal-security-update.com`).
            """
        )

    with t2:
        st.markdown(
            """
            #### How Subdomain Deception Works
            Humans read text from left to right, but domain hierarchies are resolved from **right to left**.

            - **Example:** `https://paypal.com.verify-account.security-auth.xyz`
            - **The Illusion:** It starts with `paypal.com`, leading you to believe it is PayPal.
            - **The Reality:** The actual domain is `security-auth.xyz`. Everything before it is just a subdomain created by the attacker.
            """
        )

    with t3:
        st.markdown(
            """
            #### Homograph (Punycode) Attacks
            Internationalized Domain Names (IDNs) allow websites to use alphabets beyond ASCII (e.g. Cyrillic, Greek, Hebrew).

            - **The Danger:** The Cyrillic letter `а` (U+0430) is visually indistinguishable on screen from Latin `a` (U+0061).
            - **Example:** An attacker registers `pаypal.com` (with Cyrillic 'а'). To your eyes, it looks identical to `paypal.com`, but browsers resolve it via Punycode to `xn--pypal-4ve.com`.
            - **Protection:** This inspector identifies and flags foreign scripts disguised within standard brand names.
            """
        )

    with t4:
        st.markdown(
            """
            #### Open Redirect Vulnerabilities
            An open redirect occurs when a legitimate website accepts a parameter that redirects visitors to an arbitrary external URL without validation.

            - **Example:** `https://google.com/url?q=https://malicious-phishing-site.com`
            - **Why it is Dangerous:** Victims see `google.com` and trust the link, but upon clicking, the site immediately redirects to the attacker's fake login page.
            """
        )
