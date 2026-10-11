"""
URL Safety Checker
A clean, privacy-first web app that rates links as Safe, Moderate, or Danger
WITHOUT ever connecting to or opening the target URL.
Features dynamic background intelligence based on URL safety verdicts.
"""

from __future__ import annotations

import os
import streamlit as st

from core import (
    Analysis,
    SOURCES,
    ThreatLevel,
    analyze_url,
    apply_scanners,
)
from ui import (
    get_theme_css,
    render_findings_list,
    render_header,
    render_homoglyphs_alert,
    render_hover_preview,
    render_metrics_grid,
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


def main() -> None:
    st.set_page_config(
        page_title="URL Safety Checker",
        layout="centered",
        initial_sidebar_state="collapsed",
    )

    # Read optional scanner keys from secrets/environment
    vt_key = get_secret_or_env("VT_API_KEY")
    gsb_key = get_secret_or_env("GSB_API_KEY")

    # Header
    render_header()

    if "url_input" not in st.session_state:
        st.session_state["url_input"] = ""

    def handle_clear() -> None:
        st.session_state["url_input"] = ""
        st.session_state["last_analysis"] = None

    # Input Form
    with st.form("check_form", enter_to_submit=True, clear_on_submit=False):
        url_input = st.text_input(
            "URL to check",
            placeholder="Paste or type URL (e.g. https://example.com/login)",
            help="Copy and paste the link address. This app will never open the link.",
            key="url_input",
        )
        source = st.selectbox(
            "Where did you get this link?",
            options=list(SOURCES.keys()),
            index=0,
            key="source_input",
        )
        col_submit, col_clear = st.columns([4, 1])
        with col_submit:
            submitted = st.form_submit_button("Check URL", type="primary", use_container_width=True)
        with col_clear:
            st.form_submit_button("Clear", on_click=handle_clear, use_container_width=True)

    current_analysis: Analysis | None = None

    if submitted:
        clean_url = url_input.strip()
        if clean_url:
            with st.spinner("Analyzing link heuristics (the link is NOT being opened)..."):
                analysis = analyze_url(clean_url, source=source)
                if analysis.anatomy.host and (vt_key or gsb_key):
                    apply_scanners(analysis, vt_key, gsb_key)
                st.session_state["last_analysis"] = analysis
                current_analysis = analysis
        else:
            st.warning("Please enter a URL to check.")
    elif "last_analysis" in st.session_state and st.session_state["last_analysis"]:
        current_analysis = st.session_state["last_analysis"]

    # Determine threat level for dynamic background presentation
    threat_level = current_analysis.threat_level.value if current_analysis else None

    # Apply dynamic theme CSS (Safe: green matrix, Danger: red hacker, Moderate: "it may be safe")
    st.markdown(get_theme_css(threat_level), unsafe_allow_html=True)

    if current_analysis:
        # Display "it may be safe" ambient watermark in background for Moderate links
        if current_analysis.threat_level == ThreatLevel.MODERATE:
            st.html('<div class="moderate-bg-watermark">it may be safe</div>')

        # Render inspection results
        render_verdict_card(current_analysis)
        render_metrics_grid(current_analysis)
        render_homoglyphs_alert(current_analysis)
        render_url_anatomy(current_analysis)
        render_hover_preview(current_analysis)

        st.markdown("### Findings & Breakdown")
        render_findings_list(current_analysis)

    # Footer
    st.markdown(
        """
        <div class="app-footer">
            <b>URL Safety Checker</b> · Zero-Click Architecture<br>
            <i>No tool can guarantee a link is 100% safe. Always verify senders and exercise caution.</i>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()