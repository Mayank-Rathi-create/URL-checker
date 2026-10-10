"""
CSS Design System: Sleek, high-contrast dark theme.
Focused on crystal-clear result readability and flawless component presentation.
"""

from __future__ import annotations


def get_theme_css() -> str:
    """
    Returns custom CSS for the dark theme with full container and expander support.
    """
    return """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
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
        --safe-bg: rgba(16, 185, 129, 0.12);
        --safe-border: #10B981;
        --safe-text: #34D399;
        --warn-bg: rgba(245, 158, 11, 0.12);
        --warn-border: #F59E0B;
        --warn-text: #FBBF24;
        --danger-bg: rgba(239, 68, 68, 0.12);
        --danger-border: #EF4444;
        --danger-text: #F87171;
    }

    /* Hide sidebar and collapsed sidebar controls */
    [data-testid="stSidebar"], [data-testid="collapsedControl"] {
        display: none !important;
    }

    /* Base typography and background */
    html, body, [class*="css"], .stApp {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        background-color: #0B0F19 !important;
        color: #F8FAFC !important;
    }

    .stApp {
        background-image: radial-gradient(ellipse at 50% -10%, rgba(56, 189, 248, 0.12) 0%, transparent 65%) !important;
        background-attachment: fixed !important;
    }

    /* Centered content width */
    .block-container {
        max-width: 860px !important;
        padding-top: 32px !important;
        padding-bottom: 50px !important;
    }

    /* Transparent top header */
    header[data-testid="stHeader"] {
        background-color: transparent !important;
    }

    /* Hero section (no logo) */
    .hero-container {
        text-align: center;
        padding: 6px 0 24px 0;
    }

    .hero-title {
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        line-height: 1.2;
        margin-bottom: 8px;
        background: linear-gradient(135deg, #F8FAFC 40%, #38BDF8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .hero-subtitle {
        font-size: 0.98rem;
        color: #94A3B8;
        max-width: 620px;
        margin: 0 auto;
        line-height: 1.5;
    }

    /* Verdict Card */
    .verdict-card {
        border-radius: 14px;
        padding: 22px 26px;
        margin-bottom: 20px;
        border-width: 1.5px;
        border-style: solid;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
    }

    .verdict-card.safe {
        background: rgba(16, 185, 129, 0.12);
        border-color: #10B981;
        color: #34D399;
    }

    .verdict-card.moderate {
        background: rgba(245, 158, 11, 0.12);
        border-color: #F59E0B;
        color: #FBBF24;
    }

    .verdict-card.danger {
        background: rgba(239, 68, 68, 0.12);
        border-color: #EF4444;
        color: #F87171;
    }

    .verdict-headline {
        font-size: 1.55rem;
        font-weight: 800;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 6px;
    }

    .verdict-subtext {
        font-size: 0.96rem;
        opacity: 0.95;
        margin-bottom: 14px;
        line-height: 1.45;
        color: #F8FAFC;
    }

    /* Threat Meter / Gauge */
    .gauge-wrapper {
        margin-top: 14px;
    }

    .gauge-label-row {
        display: flex;
        justify-content: space-between;
        font-size: 0.84rem;
        font-weight: 600;
        margin-bottom: 6px;
        color: #F8FAFC;
    }

    .gauge-track {
        height: 10px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 999px;
        overflow: hidden;
    }

    .gauge-fill {
        height: 100%;
        border-radius: 999px;
        transition: width 0.6s ease;
    }

    /* Metrics Grid */
    .metrics-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-bottom: 20px;
    }

    .metric-card {
        background: #111827;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 14px 16px;
        text-align: left;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
    }

    .metric-card-title {
        font-size: 0.72rem;
        font-weight: 600;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
    }

    .metric-card-val {
        font-size: 1.25rem;
        font-weight: 700;
        color: #F8FAFC;
    }

    .metric-card-sub {
        font-size: 0.78rem;
        color: #94A3B8;
        margin-top: 2px;
    }

    /* Anatomy Breakdown Box */
    .anatomy-box {
        background: #111827;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 14px;
        padding: 16px 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
    }

    .anatomy-pill-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 10px;
    }

    .anatomy-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 12px;
        background: #161F30;
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.84rem;
    }

    .anatomy-pill .pill-tag {
        font-size: 0.68rem;
        text-transform: uppercase;
        font-weight: 700;
        color: #64748B;
        letter-spacing: 0.5px;
    }

    .anatomy-pill .pill-val {
        font-weight: 600;
        color: #F8FAFC;
    }

    .anatomy-pill.registered {
        background: rgba(56, 189, 248, 0.15);
        border-color: #38BDF8;
    }

    .anatomy-pill.registered .pill-tag {
        color: #38BDF8;
    }

    /* Expander Container overrides */
    div[data-testid="stExpander"] {
        background: #111827 !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 12px !important;
        margin-bottom: 12px !important;
        overflow: hidden !important;
    }

    div[data-testid="stExpander"] summary {
        background: #161F30 !important;
        color: #F8FAFC !important;
        font-weight: 600 !important;
        padding: 12px 16px !important;
        font-size: 0.95rem !important;
    }

    div[data-testid="stExpander"] summary:hover {
        color: #38BDF8 !important;
    }

    div[data-testid="stExpander"] div[data-testid="stExpanderDetails"] {
        background: #0E1424 !important;
        padding: 14px 16px !important;
        border-top: 1px solid rgba(255, 255, 255, 0.06) !important;
    }

    /* Findings Rows */
    .finding-row {
        background: #161F30;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 12px 16px;
        margin-bottom: 10px;
        display: flex;
        align-items: flex-start;
        gap: 12px;
    }

    .finding-row:last-child {
        margin-bottom: 0;
    }

    .finding-icon {
        font-size: 1.25rem;
        line-height: 1.2;
        flex-shrink: 0;
    }

    .finding-content {
        flex: 1;
        min-width: 0;
    }

    .finding-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 10px;
        margin-bottom: 4px;
    }

    .finding-title {
        font-weight: 700;
        font-size: 0.94rem;
        color: #F8FAFC;
        line-height: 1.3;
    }

    .finding-points {
        font-size: 0.72rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 999px;
        background: rgba(239, 68, 68, 0.15);
        color: #F87171;
        border: 1px solid #EF4444;
        white-space: nowrap;
    }

    .finding-detail {
        font-size: 0.88rem;
        color: #94A3B8;
        line-height: 1.45;
        word-break: break-word;
    }

    /* Hover Preview Box */
    .preview-box {
        background: #161F30;
        border: 1px dashed rgba(255, 255, 255, 0.15);
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        margin: 20px 0;
    }

    .preview-link {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.95rem;
        color: #38BDF8;
        word-break: break-all;
        cursor: help;
        border-bottom: 1.5px dotted #38BDF8;
        padding-bottom: 2px;
    }

    /* Streamlit Form & Controls */
    div[data-testid="stForm"] {
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 16px !important;
        background: #111827 !important;
        padding: 24px !important;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35) !important;
        margin-bottom: 24px !important;
    }

    div[data-testid="stForm"]:hover {
        border-color: rgba(56, 189, 248, 0.35) !important;
    }

    button[kind="primary"] {
        background: linear-gradient(135deg, #38BDF8, #6366F1) !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 10px 24px !important;
        font-weight: 600 !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(56, 189, 248, 0.25) !important;
        transition: transform 0.15s ease, box-shadow 0.15s ease !important;
    }

    button[kind="primary"]:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(56, 189, 248, 0.35) !important;
    }

    div[data-baseweb="input"] {
        background-color: #161F30 !important;
        border-color: rgba(255, 255, 255, 0.08) !important;
        border-radius: 10px !important;
    }

    div[data-baseweb="select"] {
        background-color: #161F30 !important;
        border-radius: 10px !important;
    }

    /* Footer */
    .app-footer {
        text-align: center;
        margin-top: 40px;
        padding-top: 20px;
        font-size: 0.8rem;
        color: #64748B;
        border-top: 1px solid rgba(255, 255, 255, 0.08);
    }
    </style>
    """
