"""
URL Safety Checker
A clean, privacy-first web app that rates links as Safe, Moderate, or Danger
WITHOUT ever connecting to or opening the target URL.
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


def run_inspection(url_val: str, source_val: str, vt_key: str, gsb_key: str) -> None:
    """Performs offline analysis + optional scanner enrichment, and displays results."""
    clean_val = url_val.strip()
    if not clean_val:
        st.warning("Please enter a URL to check.")
        return

    with st.spinner("Analyzing link heuristics (the link is NOT being opened)..."):
        analysis = analyze_url(clean_val, source=source_val)
        if analysis.anatomy.host and (vt_key or gsb_key):
            apply_scanners(analysis, vt_key, gsb_key)
        st.session_state["last_analysis"] = analysis

    # Render results
    render_verdict_card(analysis)
    render_metrics_grid(analysis)
    render_homoglyphs_alert(analysis)
    render_url_anatomy(analysis)
    render_hover_preview(analysis)

    st.markdown("### Findings & Breakdown")
    render_findings_list(analysis)


def main() -> None:
    st.set_page_config(
        page_title="URL Safety Checker",
        layout="centered",
        initial_sidebar_state="collapsed",
    )

    # Apply sleek dark theme CSS
    st.markdown(get_theme_css(), unsafe_allow_html=True)

    # Read optional scanner keys from secrets/environment
    vt_key = get_secret_or_env("VT_API_KEY")
    gsb_key = get_secret_or_env("GSB_API_KEY")

    # Header
    render_header()

    # Input Form
    with st.form("check_form"):
        url_input = st.text_input(
            "URL to check",
            placeholder="Paste or type URL (e.g. https://example.com/login)",
            help="Copy and paste the link address. This app will never open the link.",
        )
        source = st.selectbox(
            "Where did you get this link?",
            options=list(SOURCES.keys()),
            index=0,
        )
        submitted = st.form_submit_button("Check URL", type="primary", use_container_width=True)

    if submitted:
        st.session_state["submitted_url"] = url_input
        st.session_state["submitted_source"] = source
        run_inspection(url_input, source, vt_key, gsb_key)
    elif "last_analysis" in st.session_state and st.session_state["last_analysis"]:
        last_res: Analysis = st.session_state["last_analysis"]
        render_verdict_card(last_res)
        render_metrics_grid(last_res)
        render_homoglyphs_alert(last_res)
        render_url_anatomy(last_res)
        render_hover_preview(last_res)
        st.markdown("### Findings & Breakdown")
        render_findings_list(last_res)

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