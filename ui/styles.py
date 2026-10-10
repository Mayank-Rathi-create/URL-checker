"""
CSS Design System: Dynamic Threat-Aware Dark Theme.
Displays green Matrix rain for Safe links, red hacker backdrop for Danger links,
and 'it may be safe' ambient watermark text for Moderate links.
"""

from __future__ import annotations

import base64
import functools
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = BASE_DIR / "assets"


@functools.lru_cache(maxsize=1)
def get_safe_bg_b64() -> str:
    path = ASSETS_DIR / "safe_bg.png"
    if path.exists():
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return ""


@functools.lru_cache(maxsize=1)
def get_danger_bg_b64() -> str:
    path = ASSETS_DIR / "danger_bg.png"
    if path.exists():
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return ""


def get_theme_css(threat_level: str | None = None) -> str:
    """
    Returns custom CSS dynamically configured for the current threat classification.
    threat_level can be 'Safe', 'Moderate', 'Danger', or None.
    """
    if threat_level == "Safe":
        safe_b64 = get_safe_bg_b64()
        if safe_b64:
            bg_css = f"""
            background-color: #05140B !important;
            background-image: linear-gradient(rgba(5, 20, 11, 0.74), rgba(5, 20, 11, 0.86)), url('data:image/png;base64,{safe_b64}') !important;
            background-size: cover !important;
            background-position: center !important;
            background-attachment: fixed !important;
            background-repeat: no-repeat !important;
            """
        else:
            bg_css = "background-image: radial-gradient(ellipse at 50% -10%, rgba(16, 185, 129, 0.22) 0%, #0B0F19 70%) !important;"
    elif threat_level == "Danger":
        danger_b64 = get_danger_bg_b64()
        if danger_b64:
            bg_css = f"""
            background-color: #150608 !important;
            background-image: linear-gradient(rgba(21, 6, 8, 0.68), rgba(21, 6, 8, 0.84)), url('data:image/png;base64,{danger_b64}') !important;
            background-size: cover !important;
            background-position: center top !important;
            background-attachment: fixed !important;
            background-repeat: no-repeat !important;
            """
        else:
            bg_css = "background-image: radial-gradient(ellipse at 50% -10%, rgba(239, 68, 68, 0.22) 0%, #0B0F19 70%) !important;"
    elif threat_level == "Moderate":
        svg_pattern = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="360" height="180" viewBox="0 0 360 180">'
            '<text x="20" y="60" fill="rgba(245,158,11,0.065)" font-family="Plus Jakarta Sans, sans-serif" '
            'font-size="20" font-weight="900" transform="rotate(-18 20,60)" letter-spacing="2">IT MAY BE SAFE</text>'
            '<text x="200" y="150" fill="rgba(245,158,11,0.065)" font-family="Plus Jakarta Sans, sans-serif" '
            'font-size="20" font-weight="900" transform="rotate(-18 200,150)" letter-spacing="2">IT MAY BE SAFE</text>'
            '</svg>'
        )
        svg_encoded = urllib.parse.quote(svg_pattern)
        bg_css = f"""
        background-color: #0F0E09 !important;
        background-image: url('data:image/svg+xml;utf8,{svg_encoded}'), radial-gradient(ellipse at 50% -10%, rgba(245, 158, 11, 0.18) 0%, #0B0F19 72%) !important;
        background-repeat: repeat, no-repeat !important;
        background-attachment: fixed !important;
        """
    else:
        bg_css = """
        background-color: #0B0F19 !important;
        background-image: radial-gradient(ellipse at 50% -10%, rgba(56, 189, 248, 0.12) 0%, transparent 65%) !important;
        background-attachment: fixed !important;
        """

    return f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {{
        --bg-main: #0B0F19;
        --bg-card: #111827;
        --bg-card-sec: #161F30;
        --border-color: rgba(255, 255, 255, 0.08);
        --border-highlight: rgba(56, 189, 248, 0.35);
        --text-primary: #F8FAFC;
        --text-secondary: #94A3B8;
        --text-muted: #64748B;
        --accent-blue: #38BDF8;
        --accent-indigo: #6366F1;
        --pill-bg: #161F30;
        --pill-border: rgba(255, 255, 255, 0.12);
        --safe-bg: rgba(16, 185, 129, 0.14);
        --safe-border: #10B981;
        --safe-text: #34D399;
        --warn-bg: rgba(245, 158, 11, 0.14);
        --warn-border: #F59E0B;
        --warn-text: #FBBF24;
        --danger-bg: rgba(239, 68, 68, 0.14);
        --danger-border: #EF4444;
        --danger-text: #F87171;
    }}

    /* Hide sidebar and collapsed sidebar controls */
    [data-testid="stSidebar"], [data-testid="collapsedControl"] {{
        display: none !important;
    }}

    /* Base typography and background */
    html, body, [class*="css"], .stApp {{
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        color: #F8FAFC !important;
    }}

    .stApp {{
        {bg_css}
    }}

    /* Fixed ambient watermark for Moderate threat level */
    .moderate-bg-watermark {{
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%) rotate(-12deg);
        font-size: clamp(3.2rem, 9vw, 6.8rem);
        font-weight: 900;
        letter-spacing: 0.1em;
        color: rgba(245, 158, 11, 0.09);
        text-shadow: 0 0 35px rgba(245, 158, 11, 0.18);
        pointer-events: none;
        z-index: 0;
        user-select: none;
        white-space: nowrap;
        text-transform: uppercase;
    }}

    /* Centered content width elevated above background */
    .block-container {{
        max-width: 860px !important;
        padding-top: 32px !important;
        padding-bottom: 50px !important;
        position: relative !important;
        z-index: 2 !important;
    }}

    /* Transparent top header */
    header[data-testid="stHeader"] {{
        background-color: transparent !important;
    }}

    /* Hero section (no logo) */
    .hero-container {{
        text-align: center;
        padding: 6px 0 24px 0;
    }}

    .hero-title {{
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        line-height: 1.2;
        margin-bottom: 8px;
        background: linear-gradient(135deg, #F8FAFC 40%, #38BDF8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }}

    .hero-subtitle {{
        font-size: 0.98rem;
        color: #94A3B8;
        max-width: 620px;
        margin: 0 auto;
        line-height: 1.5;
    }}

    /* Verdict Card */
    .verdict-card {{
        border-radius: 14px;
        padding: 22px 26px;
        margin-bottom: 20px;
        border-width: 1.5px;
        border-style: solid;
        box-shadow: 0 10px 32px rgba(0, 0, 0, 0.45);
        backdrop-filter: blur(8px);
    }}

    .verdict-card.safe {{
        background: rgba(16, 185, 129, 0.16);
        border-color: #10B981;
        color: #34D399;
    }}

    .verdict-card.moderate {{
        background: rgba(245, 158, 11, 0.16);
        border-color: #F59E0B;
        color: #FBBF24;
    }}

    .verdict-card.danger {{
        background: rgba(239, 68, 68, 0.18);
        border-color: #EF4444;
        color: #F87171;
    }}

    .verdict-headline {{
        font-size: 1.55rem;
        font-weight: 800;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 6px;
    }}

    .verdict-subtext {{
        font-size: 0.96rem;
        opacity: 0.95;
        margin-bottom: 14px;
        line-height: 1.45;
        color: #F8FAFC;
    }}

    /* Threat Meter / Gauge */
    .gauge-wrapper {{
        margin-top: 14px;
    }}

    .gauge-label-row {{
        display: flex;
        justify-content: space-between;
        font-size: 0.84rem;
        font-weight: 600;
        margin-bottom: 6px;
        color: #F8FAFC;
    }}

    .gauge-track {{
        height: 10px;
        background: rgba(255, 255, 255, 0.12);
        border-radius: 999px;
        overflow: hidden;
    }}

    .gauge-fill {{
        height: 100%;
        border-radius: 999px;
        transition: width 0.6s ease;
    }}

    /* Metrics Grid */
    .metrics-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-bottom: 20px;
    }}

    .metric-card {{
        background: rgba(17, 24, 39, 0.85);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 14px 16px;
        text-align: left;
        box-shadow: 0 6px 24px rgba(0, 0, 0, 0.35);
        backdrop-filter: blur(8px);
    }}

    .metric-card-title {{
        font-size: 0.72rem;
        font-weight: 600;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
    }}

    .metric-card-val {{
        font-size: 1.25rem;
        font-weight: 700;
        color: #F8FAFC;
    }}

    .metric-card-sub {{
        font-size: 0.78rem;
        color: #94A3B8;
        margin-top: 2px;
    }}

    /* Anatomy Breakdown Box */
    .anatomy-box {{
        background: rgba(17, 24, 39, 0.85);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 14px;
        padding: 16px 20px;
        margin-bottom: 20px;
        box-shadow: 0 6px 24px rgba(0, 0, 0, 0.35);
        backdrop-filter: blur(8px);
    }}

    .anatomy-pill-row {{
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 10px;
    }}

    .anatomy-pill {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 12px;
        background: #161F30;
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.84rem;
    }}

    .anatomy-pill .pill-tag {{
        font-size: 0.68rem;
        text-transform: uppercase;
        font-weight: 700;
        color: #64748B;
        letter-spacing: 0.5px;
    }}

    .anatomy-pill .pill-val {{
        font-weight: 600;
        color: #F8FAFC;
    }}

    .anatomy-pill.registered {{
        background: rgba(56, 189, 248, 0.18);
        border-color: #38BDF8;
    }}

    .anatomy-pill.registered .pill-tag {{
        color: #38BDF8;
    }}

    /* Expander Container overrides */
    div[data-testid="stExpander"] {{
        background: rgba(17, 24, 39, 0.88) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 12px !important;
        margin-bottom: 12px !important;
        overflow: hidden !important;
        backdrop-filter: blur(8px) !important;
    }}

    div[data-testid="stExpander"] summary {{
        background: #161F30 !important;
        color: #F8FAFC !important;
        font-weight: 600 !important;
        padding: 12px 16px !important;
        font-size: 0.95rem !important;
    }}

    div[data-testid="stExpander"] summary:hover {{
        color: #38BDF8 !important;
    }}

    div[data-testid="stExpander"] div[data-testid="stExpanderDetails"] {{
        background: rgba(14, 20, 36, 0.95) !important;
        padding: 14px 16px !important;
        border-top: 1px solid rgba(255, 255, 255, 0.08) !important;
    }}

    /* Findings Rows */
    .finding-row {{
        background: #161F30;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 12px 16px;
        margin-bottom: 10px;
        display: flex;
        align-items: flex-start;
        gap: 12px;
    }}

    .finding-row:last-child {{
        margin-bottom: 0;
    }}

    .finding-icon {{
        font-size: 1.25rem;
        line-height: 1.2;
        flex-shrink: 0;
    }}

    .finding-content {{
        flex: 1;
        min-width: 0;
    }}

    .finding-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 10px;
        margin-bottom: 4px;
    }}

    .finding-title {{
        font-weight: 700;
        font-size: 0.94rem;
        color: #F8FAFC;
        line-height: 1.3;
    }}

    .finding-points {{
        font-size: 0.72rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 999px;
        background: rgba(239, 68, 68, 0.18);
        color: #F87171;
        border: 1px solid #EF4444;
        white-space: nowrap;
    }}

    .finding-detail {{
        font-size: 0.88rem;
        color: #CBD5E1;
        line-height: 1.45;
        word-break: break-word;
    }}

    /* Hover Preview Box */
    .preview-box {{
        background: rgba(22, 31, 48, 0.85);
        border: 1px dashed rgba(255, 255, 255, 0.18);
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        margin: 20px 0;
        backdrop-filter: blur(8px);
    }}

    .preview-link {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.95rem;
        color: #38BDF8;
        word-break: break-all;
        cursor: help;
        border-bottom: 1.5px dotted #38BDF8;
        padding-bottom: 2px;
    }}

    /* Streamlit Form & Controls */
    div[data-testid="stForm"] {{
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 16px !important;
        background: rgba(17, 24, 39, 0.85) !important;
        padding: 24px !important;
        box-shadow: 0 10px 32px rgba(0, 0, 0, 0.45) !important;
        margin-bottom: 24px !important;
        backdrop-filter: blur(10px) !important;
    }}

    div[data-testid="stForm"]:hover {{
        border-color: rgba(56, 189, 248, 0.35) !important;
    }}

    button[kind="primary"] {{
        background: linear-gradient(135deg, #38BDF8, #6366F1) !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 10px 24px !important;
        font-weight: 600 !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(56, 189, 248, 0.3) !important;
        transition: transform 0.15s ease, box-shadow 0.15s ease !important;
    }}

    button[kind="primary"]:hover {{
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(56, 189, 248, 0.4) !important;
    }}

    div[data-baseweb="input"] {{
        background-color: #161F30 !important;
        border-color: rgba(255, 255, 255, 0.1) !important;
        border-radius: 10px !important;
    }}

    div[data-baseweb="select"] {{
        background-color: #161F30 !important;
        border-radius: 10px !important;
    }}

    /* Footer */
    .app-footer {{
        text-align: center;
        margin-top: 40px;
        padding-top: 20px;
        font-size: 0.8rem;
        color: #64748B;
        border-top: 1px solid rgba(255, 255, 255, 0.08);
    }}
    </style>
    """
