"""
Reusable UI components for URL Safety Checker.
Crafted for clean presentation, high contrast, and direct HTML rendering (no markdown leaking).
"""

from __future__ import annotations

import html
import json
from typing import Any

import streamlit as st

from core.models import Analysis, FindingSeverity, ThreatLevel


def render_header() -> None:
    """Renders the top branding and header without any logo."""
    st.html(
        """<div class="hero-container">
<div class="hero-title">URL Safety Checker</div>
<div class="hero-subtitle">
Inspect links for phishing, impersonation, and hidden threats before you click.<br>
<span style="font-size:0.85rem; color:#10B981; font-weight:600;">Zero-Click Guarantee: We never connect to or open the target URL.</span>
</div>
</div>"""
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

    safe_title = html.escape(title)
    safe_summary = html.escape(summary)

    st.html(
        f"""<div class="verdict-card {card_class}">
<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
<span style="font-size:0.78rem; font-weight:800; letter-spacing:1px; text-transform:uppercase;">{tag_text}</span>
<span style="font-size:0.9rem; font-weight:700;">Risk Score: {score}/100</span>
</div>
<div class="verdict-headline">
<span>{badge_icon}</span>
<span>{safe_title}</span>
</div>
<div class="verdict-subtext">{safe_summary}</div>
<div class="gauge-wrapper">
<div class="gauge-label-row">
<span>Threat Exposure Meter</span>
<span>{score}%</span>
</div>
<div class="gauge-track">
<div class="gauge-fill" style="width: {score}%; background: {gauge_color};"></div>
</div>
</div>
</div>"""
    )


def render_metrics_grid(analysis: Analysis) -> None:
    """Displays a responsive 4-column metric grid."""
    score = analysis.score
    score_desc = "Safe range" if score < 20 else ("Moderate risk" if score < 50 else "High threat")
    dom = html.escape(analysis.anatomy.registered_domain or analysis.anatomy.host or "Unknown")
    status = "Official Brand" if analysis.official_brand else ("Reputable" if analysis.is_reputable_domain else "Unverified")
    proto = html.escape(analysis.anatomy.scheme.upper() or "-")
    is_https = analysis.anatomy.scheme == "https"
    proto_icon = "🔒" if is_https else "🔓"
    proto_desc = "Encrypted (TLS)" if is_https else "Unencrypted plaintext"
    num_bad = len([f for f in analysis.findings if f.level == FindingSeverity.BAD])
    num_warn = len([f for f in analysis.findings if f.level == FindingSeverity.WARN])
    flag_summary = f"{num_bad} alerts, {num_warn} warnings" if (num_bad or num_warn) else "0 alerts detected"

    st.html(
        f"""<div class="metrics-grid">
<div class="metric-card">
<div class="metric-card-title">Risk Score</div>
<div class="metric-card-val">{score} <span style="font-size:0.85rem; font-weight:500; color:#64748B;">/ 100</span></div>
<div class="metric-card-sub">{score_desc}</div>
</div>
<div class="metric-card">
<div class="metric-card-title">Registered Domain</div>
<div class="metric-card-val" style="font-size:1.15rem; word-break:break-all;">{dom}</div>
<div class="metric-card-sub">{status}</div>
</div>
<div class="metric-card">
<div class="metric-card-title">Transport Protocol</div>
<div class="metric-card-val" style="font-size:1.15rem;">{proto_icon} {proto}</div>
<div class="metric-card-sub">{proto_desc}</div>
</div>
<div class="metric-card">
<div class="metric-card-title">Signals Detected</div>
<div class="metric-card-val" style="font-size:1.15rem;">{len(analysis.findings)} Findings</div>
<div class="metric-card-sub">{flag_summary}</div>
</div>
</div>"""
    )


def render_url_anatomy(analysis: Analysis) -> None:
    """Renders the decomposed URL anatomy into color-coded structural pills."""
    anat = analysis.anatomy
    pills = []
    if anat.scheme:
        pills.append(f'<span class="anatomy-pill"><span class="pill-tag">Scheme</span><span class="pill-val">{html.escape(anat.scheme)}://</span></span>')
    if anat.subdomain:
        pills.append(f'<span class="anatomy-pill"><span class="pill-tag">Subdomain</span><span class="pill-val">{html.escape(anat.subdomain)}.</span></span>')
    if anat.registered_domain:
        pills.append(f'<span class="anatomy-pill registered"><span class="pill-tag">Real Domain</span><span class="pill-val">{html.escape(anat.registered_domain)}</span></span>')
    if anat.port:
        pills.append(f'<span class="anatomy-pill"><span class="pill-tag">Port</span><span class="pill-val">:{anat.port}</span></span>')
    if anat.path and anat.path != "/":
        path_disp = anat.path if len(anat.path) < 35 else f"{anat.path[:32]}..."
        pills.append(f'<span class="anatomy-pill"><span class="pill-tag">Path</span><span class="pill-val">{html.escape(path_disp)}</span></span>')
    if anat.query:
        query_disp = f"?{anat.query[:28]}..." if len(anat.query) > 30 else f"?{anat.query}"
        pills.append(f'<span class="anatomy-pill"><span class="pill-tag">Query</span><span class="pill-val">{html.escape(query_disp)}</span></span>')

    pills_str = "".join(pills)
    st.html(
        f"""<div class="anatomy-box">
<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
<span style="font-size:0.86rem; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; color:#94A3B8;">URL Structural Anatomy Breakdown</span>
<span style="font-size:0.78rem; color:#64748B;">The real destination is the <b>Registered Domain</b></span>
</div>
<div class="anatomy-pill-row">{pills_str}</div>
</div>"""
    )


def render_homoglyphs_alert(analysis: Analysis) -> None:
    """Highlights homoglyph spoofing details if present."""
    anat = analysis.anatomy
    if not (anat.is_punycode or anat.homoglyphs):
        return

    items = []
    for h in anat.homoglyphs:
        safe_char = html.escape(h["char"])
        safe_code = html.escape(h["codepoint"])
        safe_desc = html.escape(h["description"])
        safe_mimic = html.escape(h["mimics"])
        items.append(
            f"<div>• Spoofed letter: <b style='color:#EF4444; font-size:1.05rem;'>{safe_char}</b> "
            f"({safe_code} - {safe_desc}) disguising Latin <b>{safe_mimic}</b></div>"
        )
    items_str = "".join(items)

    st.html(
        f"""<div style="background:rgba(239,68,68,0.12); border:1.5px solid #EF4444; border-radius:14px; padding:18px; margin-bottom:20px;">
<div style="display:flex; align-items:center; gap:8px; font-weight:800; font-size:1.1rem; color:#F87171; margin-bottom:8px;">
<span>⚠️</span> <span>Homograph / Character Deception Detected!</span>
</div>
<div style="font-size:0.9rem; color:#94A3B8; line-height:1.45; margin-bottom:10px;">
This address uses international characters that visually mimic Latin letters to fake legitimate brand domains.
</div>
<div style="font-family:'JetBrains Mono', monospace; font-size:0.86rem; background:rgba(0,0,0,0.25); padding:10px 14px; border-radius:8px; color:#F8FAFC; line-height:1.6;">
{items_str}
</div>
</div>"""
    )


def render_hover_preview(analysis: Analysis) -> None:
    """Renders non-clickable hover preview with safe copy mechanism."""
    safe_url = html.escape(analysis.url)
    st.html(
        f"""<div class="preview-box">
<div style="font-size:0.8rem; font-weight:700; text-transform:uppercase; color:#64748B; margin-bottom:6px;">Zero-Click Safe Preview (Not Clickable)</div>
<div class="preview-link" title="Target: {safe_url}">{safe_url}</div>
<div style="font-size:0.78rem; color:#64748B; margin-top:8px;">Hover to view target address safely. This tool never opens or connects to the link.</div>
</div>"""
    )


def render_findings_list(analysis: Analysis) -> None:
    """Renders categorized findings cleanly without code block leakage."""
    groups = [
        ("Critical Red Flags", (FindingSeverity.BAD,), True, "🚨"),
        ("Warnings & Anomalies", (FindingSeverity.WARN,), True, "⚠️"),
        ("Verified Safeguards", (FindingSeverity.GOOD,), False, "✅"),
        ("Context & Information", (FindingSeverity.INFO,), False, "ℹ️"),
    ]

    for group_name, levels, default_open, icon in groups:
        matching = [f for f in analysis.findings if f.level in levels]
        if not matching:
            continue

        with st.expander(f"{icon} {group_name} ({len(matching)})", expanded=default_open):
            rows = []
            for f in matching:
                pts = f'<span class="finding-points">+{f.points} Risk</span>' if f.points > 0 else ""
                safe_title = html.escape(f.title)
                safe_detail = html.escape(f.detail)
                rows.append(
                    f"""<div class="finding-row">
<div class="finding-icon">{f.icon}</div>
<div class="finding-content">
<div class="finding-header">
<span class="finding-title">{safe_title}</span>
{pts}
</div>
<div class="finding-detail">{safe_detail}</div>
</div>
</div>"""
                )
            st.html("\n".join(rows))

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
    st.markdown("### Phishing Tactics & URL Deception Cheat Sheet")
    st.write(
        "Attackers use a variety of deceptive techniques to make malicious links appear legitimate. "
        "Here is how to recognize the most prevalent vectors:"
    )

    t1, t2, t3, t4 = st.tabs(["Typosquatting", "Subdomain Deception", "Homograph / Punycode", "Open Redirects"])

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
