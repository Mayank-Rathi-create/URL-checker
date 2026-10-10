"""
URL Safety & Phishing Inspector
A privacy-first Streamlit web application that rates links as Safe, Moderate, or Danger
WITHOUT ever connecting to or opening the target URL.
"""

from __future__ import annotations

import os
import streamlit as st

from core import (
    Analysis,
    OFFICIAL_DOMAINS,
    SOURCES,
    ThreatLevel,
    analyze_url,
    apply_scanners,
)
from ui import (
    get_theme_css,
    render_export_report,
    render_findings_list,
    render_header,
    render_homoglyphs_alert,
    render_hover_preview,
    render_metrics_grid,
    render_threat_guide,
    render_url_anatomy,
    render_verdict_card,
)


def get_secret_or_env(key_name: str) -> str:
    """Safely retrieves a configuration key from st.secrets or os.environ."""
    try:
        if key_name in st.secrets:
            return str(st.secrets[key_name]).strip()
    except Exception:
        pass
    return os.environ.get(key_name, "").strip()


def init_session_state() -> None:
    """Initializes persistent application session variables."""
    if "theme" not in st.session_state:
        st.session_state["theme"] = "dark"
    if "url_input" not in st.session_state:
        st.session_state["url_input"] = ""
    if "source_selection" not in st.session_state:
        st.session_state["source_selection"] = list(SOURCES.keys())[0]
    if "last_analysis" not in st.session_state:
        st.session_state["last_analysis"] = None


def render_sidebar(vt_key: str, gsb_key: str) -> tuple[str, str]:
    """Renders the settings, API keys, and privacy assurance panel in the sidebar."""
    with st.sidebar:
        st.markdown("### ⚙️ Settings & Threat Intel")

        # Zero-click guarantee badge
        st.markdown(
            """
            <div style="background:var(--pill-bg); border:1px solid var(--pill-border); border-radius:12px; padding:14px; margin-bottom:18px;">
                <div style="font-weight:700; font-size:0.85rem; color:var(--safe-text); display:flex; align-items:center; gap:6px;">
                    <span>🔒</span> Zero-Click Privacy Guarantee
                </div>
                <div style="font-size:0.78rem; color:var(--text-secondary); margin-top:4px; line-height:1.4;">
                    This app <b>never makes HTTP/TCP connections</b> to the links you enter. All analyses run offline or through sandboxed vendor APIs.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("#### 🔑 External Intelligence APIs")
        st.caption("Optional free API keys for enhanced cloud threat detection:")

        custom_vt = st.text_input(
            "VirusTotal API Key",
            value=vt_key,
            type="password",
            help="Free key from virustotal.com (profile → API key)",
            placeholder="Paste VT key here...",
        )

        custom_gsb = st.text_input(
            "Google Safe Browsing Key",
            value=gsb_key,
            type="password",
            help="Free key from Google Cloud Console (Safe Browsing API)",
            placeholder="Paste Google Cloud API key...",
        )

        # Status indicators
        st.markdown("---")
        st.markdown("#### 🛰️ Engine Status")
        st.markdown("• **Offline Heuristics:** 🟢 Active (Instant)")
        vt_active = bool(custom_vt.strip())
        gsb_active = bool(custom_gsb.strip())
        st.markdown(f"• **VirusTotal v3:** {'🟢 Connected' if vt_active else '⚪ Inactive (Offline mode)'}")
        st.markdown(f"• **Google Safe Browsing:** {'🟢 Connected' if gsb_active else '⚪ Inactive (Offline mode)'}")

        st.markdown("---")
        st.caption("Built with privacy & modern heuristics · v2.0")

    return custom_vt, custom_gsb


def run_single_inspection(url_val: str, source_val: str, vt_key: str, gsb_key: str) -> None:
    """Executes single URL analysis and renders visual feedback."""
    if not url_val.strip():
        st.warning("⚠️ Please provide a URL to inspect.")
        return

    with st.spinner("Analyzing link heuristics & signature integrity (Zero-Click)..."):
        analysis = analyze_url(url_val, source=source_val)
        if analysis.anatomy.host:
            apply_scanners(analysis, vt_key, gsb_key)
        st.session_state["last_analysis"] = analysis

    # Render Visual Dashboard
    render_verdict_card(analysis)
    render_metrics_grid(analysis)
    render_homoglyphs_alert(analysis)
    render_url_anatomy(analysis)
    render_hover_preview(analysis)

    st.markdown("### 📋 Detailed Inspection Findings")
    render_findings_list(analysis)

    st.markdown("---")
    render_export_report(analysis)


def render_batch_tab(vt_key: str, gsb_key: str) -> None:
    """Renders the Batch URL scanner tab for evaluating multiple URLs."""
    st.markdown("### ⚡ Batch URL Safety Scanner")
    st.write("Paste multiple links (one per line) to evaluate threat scores and red flags simultaneously:")

    sample_batch = (
        "https://paypal.com\n"
        "https://paypa1.com\n"
        "http://paypal.com.evil.xyz/login\n"
        "https://bit.ly/sample-link\n"
        "https://en.wikipedia.org/wiki/Phishing\n"
        "http://192.168.1.1/admin"
    )

    batch_input = st.text_area(
        "URLs to inspect (one per line):",
        value=sample_batch,
        height=150,
        placeholder="https://example1.com\nhttps://example2.com",
    )

    col1, col2 = st.columns([1, 4])
    with col1:
        run_batch = st.button("🚀 Inspect All Links", type="primary", use_container_width=True)

    if run_batch:
        raw_lines = [line.strip() for line in batch_input.splitlines() if line.strip()]
        if not raw_lines:
            st.warning("No valid URLs found in input.")
            return

        with st.spinner(f"Evaluating {len(raw_lines)} links offline..."):
            results: list[Analysis] = []
            for u in raw_lines:
                res = analyze_url(u, source="A website I am browsing")
                if res.anatomy.host and (vt_key or gsb_key):
                    apply_scanners(res, vt_key, gsb_key)
                results.append(res)

        st.markdown(f"#### 📊 Batch Results ({len(results)} links evaluated)")

        table_data = []
        for r in results:
            threat = r.threat_level
            badge = "✅ Safe" if threat == ThreatLevel.SAFE else ("⚠️ Moderate" if threat == ThreatLevel.MODERATE else "🚨 Danger")
            dom = r.anatomy.registered_domain or r.anatomy.host or "Invalid"
            flags = [f.title for f in r.findings if f.level.value in ("bad", "warn")]
            table_data.append({
                "Verdict": badge,
                "Risk Score": f"{r.score}/100",
                "Domain": dom,
                "Protocol": r.anatomy.scheme.upper(),
                "Primary Signals": "; ".join(flags[:2]) if flags else "No red flags",
                "Full URL": r.url,
            })

        st.dataframe(table_data, use_container_width=True, hide_index=True)


def main() -> None:
    """Main application lifecycle."""
    st.set_page_config(
        page_title="URL Safety & Phishing Inspector",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    init_session_state()
    theme = st.session_state["theme"]

    # Inject dynamic CSS tailored to Dark or Light theme
    st.markdown(get_theme_css(theme), unsafe_allow_html=True)

    # API Keys from secrets / env
    vt_env = get_secret_or_env("VT_API_KEY")
    gsb_env = get_secret_or_env("GSB_API_KEY")

    # Sidebar settings
    active_vt, active_gsb = render_sidebar(vt_env, gsb_env)

    # Main Page Header
    render_header(theme)

    # Tabs
    tab_single, tab_batch, tab_guide = st.tabs([
        "🔍 Single Link Inspector",
        "⚡ Batch URL Scanner",
        "🛡️ Threat Guide & Heuristics",
    ])

    with tab_single:
        # Quick sample test pills
        st.markdown(
            """
            <div style="font-size:0.82rem; font-weight:700; color:var(--text-secondary); margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">
                💡 Quick-Test Samples (Click to Try)
            </div>
            """,
            unsafe_allow_html=True,
        )

        p1, p2, p3, p4, p5, p6 = st.columns(6)
        with p1:
            if st.button("✅ paypal.com", key="sample_paypal", help="Authentic official domain", use_container_width=True):
                st.session_state["url_input"] = "https://paypal.com"
                st.rerun()
        with p2:
            if st.button("🚨 paypa1.com", key="sample_typo", help="Typosquatting lookalike", use_container_width=True):
                st.session_state["url_input"] = "https://paypa1.com"
                st.rerun()
        with p3:
            if st.button("🎭 Subdomain Spoof", key="sample_sub", help="Brand hidden in subdomain", use_container_width=True):
                st.session_state["url_input"] = "https://paypal.com.account-update.evil.xyz/login"
                st.rerun()
        with p4:
            if st.button("🔗 bit.ly Shortener", key="sample_short", help="Masked shortened link", use_container_width=True):
                st.session_state["url_input"] = "http://bit.ly/xyz-login"
                st.rerun()
        with p5:
            if st.button("🌐 192.168.1.1 IP", key="sample_ip", help="Direct numerical IP address", use_container_width=True):
                st.session_state["url_input"] = "http://192.168.1.1/admin"
                st.rerun()
        with p6:
            if st.button("🔤 Punycode Deception", key="sample_puny", help="Cyrillic homoglyph spoofing", use_container_width=True):
                st.session_state["url_input"] = "https://xn--pypal-4ve.com/signin"
                st.rerun()

        # Input Form
        with st.form("inspect_form"):
            user_url = st.text_input(
                "Link to inspect:",
                value=st.session_state["url_input"],
                placeholder="Paste or type URL (e.g., https://example.com/account/login)",
                help="Right-click and copy link address. Do not open suspicious links.",
            )

            col_src, col_btn = st.columns([3, 1], vertical_alignment="bottom")
            with col_src:
                selected_source = st.selectbox(
                    "Where did you receive this link?",
                    options=list(SOURCES.keys()),
                    index=0,
                )
            with col_btn:
                submitted = st.form_submit_button("🛡️ Inspect URL", type="primary", use_container_width=True)

        if submitted:
            st.session_state["url_input"] = user_url
            run_single_inspection(user_url, selected_source, active_vt, active_gsb)
        elif st.session_state.get("last_analysis"):
            # Show cached last analysis if available
            last_res = st.session_state["last_analysis"]
            render_verdict_card(last_res)
            render_metrics_grid(last_res)
            render_homoglyphs_alert(last_res)
            render_url_anatomy(last_res)
            render_hover_preview(last_res)
            st.markdown("### 📋 Detailed Inspection Findings")
            render_findings_list(last_res)
            st.markdown("---")
            render_export_report(last_res)

    with tab_batch:
        render_batch_tab(active_vt, active_gsb)

    with tab_guide:
        render_threat_guide()

    # Footer
    st.markdown(
        """
        <div class="app-footer">
            <b>URL Safety & Phishing Inspector</b> · Designed with Zero-Click Architecture.<br>
            <i>Remember: No automated heuristic can guarantee 100% safety. Always exercise caution before submitting credentials.</i>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()