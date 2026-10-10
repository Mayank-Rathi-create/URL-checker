"""
CSS Design System: Sleek, eye-catching dark theme.
Focused, simple, and modern with no distractions.
"""

from __future__ import annotations


def get_theme_css() -> str:
    """
    Returns custom CSS for the sleek dark cybersecurity aesthetic.
    """
    bg_main = "#0B0F19"
    bg_card = "#111827"
    bg_card_secondary = "#1E293B"
    border_color = "rgba(255, 255, 255, 0.08)"
    border_highlight = "rgba(56, 189, 248, 0.35)"
    text_primary = "#F8FAFC"
    text_secondary = "#94A3B8"
    text_muted = "#64748B"
    accent_blue = "#38BDF8"
    accent_indigo = "#6366F1"
    pill_bg = "#1E293B"
    pill_border = "#334155"

    safe_bg = "rgba(16, 185, 129, 0.12)"
    safe_border = "#10B981"
    safe_text = "#34D399"

    warn_bg = "rgba(245, 158, 11, 0.12)"
    warn_border = "#F59E0B"
    warn_text = "#FBBF24"

    danger_bg = "rgba(239, 68, 68, 0.12)"
    danger_border = "#EF4444"
    danger_text = "#F87171"

    card_shadow = "0 8px 30px rgba(0, 0, 0, 0.35)"
    hero_glow = "radial-gradient(ellipse at 50% -10%, rgba(56, 189, 248, 0.14) 0%, transparent 65%)"

    return f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {{
        --bg-main: {bg_main};
        --bg-card: {bg_card};
        --bg-card-sec: {bg_card_secondary};
        --border-color: {border_color};
        --border-highlight: {border_highlight};
        --text-primary: {text_primary};
        --text-secondary: {text_secondary};
        --text-muted: {text_muted};
        --accent-blue: {accent_blue};
        --accent-indigo: {accent_indigo};
        --pill-bg: {pill_bg};
        --pill-border: {pill_border};
        --safe-bg: {safe_bg};
        --safe-border: {safe_border};
        --safe-text: {safe_text};
        --warn-bg: {warn_bg};
        --warn-border: {warn_border};
        --warn-text: {warn_text};
        --danger-bg: {danger_bg};
        --danger-border: {danger_border};
        --danger-text: {danger_text};
    }}

    /* Hide sidebar and collapsed sidebar arrow completely */
    [data-testid="stSidebar"], [data-testid="collapsedControl"] {{
        display: none !important;
    }}

    /* Global Typography & Background */
    html, body, [class*="css"], .stApp {{
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        background-color: {bg_main} !important;
        color: {text_primary} !important;
    }}

    .stApp {{
        background-image: {hero_glow} !important;
        background-attachment: fixed !important;
    }}

    /* Centered content constraint for clean focus */
    .block-container {{
        max-width: 860px !important;
        padding-top: 36px !important;
        padding-bottom: 60px !important;
    }}

    /* Clean transparent header */
    header[data-testid="stHeader"] {{
        background-color: transparent !important;
    }}

    /* Hero section */
    .hero-container {{
        text-align: center;
        padding: 10px 0 28px 0;
    }}

    .hero-title {{
        font-size: 2.3rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        line-height: 1.2;
        margin-bottom: 8px;
        background: linear-gradient(135deg, {text_primary} 40%, {accent_blue} 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }}

    .hero-subtitle {{
        font-size: 1rem;
        color: {text_secondary};
        max-width: 620px;
        margin: 0 auto;
        line-height: 1.5;
    }}

    /* Verdict Card */
    .verdict-card {{
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 24px;
        border-width: 1.5px;
        border-style: solid;
        transition: transform 0.2s ease;
    }}

    .verdict-card.safe {{
        background: {safe_bg};
        border-color: {safe_border};
        color: {safe_text};
    }}

    .verdict-card.moderate {{
        background: {warn_bg};
        border-color: {warn_border};
        color: {warn_text};
    }}

    .verdict-card.danger {{
        background: {danger_bg};
        border-color: {danger_border};
        color: {danger_text};
    }}

    .verdict-headline {{
        font-size: 1.6rem;
        font-weight: 800;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 6px;
    }}

    .verdict-subtext {{
        font-size: 0.98rem;
        opacity: 0.95;
        margin-bottom: 16px;
        line-height: 1.45;
    }}

    /* Threat Meter / Gauge */
    .gauge-wrapper {{
        margin-top: 14px;
    }}

    .gauge-label-row {{
        display: flex;
        justify-content: space-between;
        font-size: 0.85rem;
        font-weight: 600;
        margin-bottom: 6px;
    }}

    .gauge-track {{
        height: 10px;
        background: rgba(255, 255, 255, 0.08);
        border-radius: 999px;
        overflow: hidden;
    }}

    .gauge-fill {{
        height: 100%;
        border-radius: 999px;
        transition: width 0.6s ease;
    }}

    /* Metrics Grid */
    .metric-card {{
        background: {bg_card};
        border: 1px solid {border_color};
        border-radius: 14px;
        padding: 16px 18px;
        text-align: left;
        box-shadow: {card_shadow};
    }}

    .metric-card-title {{
        font-size: 0.74rem;
        font-weight: 600;
        color: {text_muted};
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
    }}

    .metric-card-val {{
        font-size: 1.3rem;
        font-weight: 700;
        color: {text_primary};
    }}

    .metric-card-sub {{
        font-size: 0.78rem;
        color: {text_secondary};
        margin-top: 2px;
    }}

    /* Anatomy Pills */
    .anatomy-box {{
        background: {bg_card};
        border: 1px solid {border_color};
        border-radius: 14px;
        padding: 18px 20px;
        margin: 20px 0;
        box-shadow: {card_shadow};
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
        background: {pill_bg};
        border: 1px solid {pill_border};
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.84rem;
    }}

    .anatomy-pill .pill-tag {{
        font-size: 0.68rem;
        text-transform: uppercase;
        font-weight: 700;
        color: {text_muted};
        letter-spacing: 0.5px;
    }}

    .anatomy-pill .pill-val {{
        font-weight: 600;
        color: {text_primary};
    }}

    .anatomy-pill.registered {{
        background: rgba(56, 189, 248, 0.15);
        border-color: {accent_blue};
    }}

    .anatomy-pill.registered .pill-tag {{
        color: {accent_blue};
    }}

    /* Findings Items */
    .finding-row {{
        background: {bg_card};
        border: 1px solid {border_color};
        border-radius: 12px;
        padding: 14px 18px;
        margin-bottom: 10px;
        display: flex;
        align-items: flex-start;
        gap: 14px;
    }}

    .finding-icon {{
        font-size: 1.25rem;
        line-height: 1;
        margin-top: 2px;
    }}

    .finding-content {{
        flex: 1;
    }}

    .finding-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 4px;
    }}

    .finding-title {{
        font-weight: 700;
        font-size: 0.94rem;
        color: {text_primary};
    }}

    .finding-points {{
        font-size: 0.72rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 999px;
        background: {danger_bg};
        color: {danger_text};
        border: 1px solid {danger_border};
    }}

    .finding-detail {{
        font-size: 0.86rem;
        color: {text_secondary};
        line-height: 1.45;
    }}

    /* Preview box */
    .preview-box {{
        background: {pill_bg};
        border: 1px dashed {border_color};
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        margin: 20px 0;
    }}

    .preview-link {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.95rem;
        color: {accent_blue};
        word-break: break-all;
        cursor: help;
        border-bottom: 1.5px dotted {accent_blue};
        padding-bottom: 2px;
    }}

    /* Streamlit Form Styling */
    div[data-testid="stForm"] {{
        border: 1px solid {border_color} !important;
        border-radius: 16px !important;
        background: {bg_card} !important;
        padding: 24px !important;
        box-shadow: {card_shadow} !important;
    }}

    div[data-testid="stForm"]:hover {{
        border-color: {border_highlight} !important;
    }}

    button[kind="primary"] {{
        background: linear-gradient(135deg, {accent_blue}, {accent_indigo}) !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 10px 24px !important;
        font-weight: 600 !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(56, 189, 248, 0.25) !important;
        transition: transform 0.15s ease, box-shadow 0.15s ease !important;
    }}

    button[kind="primary"]:hover {{
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(56, 189, 248, 0.35) !important;
    }}

    /* Inputs */
    div[data-baseweb="input"] {{
        background-color: {bg_card_secondary} !important;
        border-color: {border_color} !important;
        border-radius: 10px !important;
    }}

    div[data-baseweb="select"] {{
        background-color: {bg_card_secondary} !important;
        border-radius: 10px !important;
    }}

    /* Footer */
    .app-footer {{
        text-align: center;
        margin-top: 48px;
        padding-top: 24px;
        font-size: 0.8rem;
        color: {text_muted};
        border-top: 1px solid {border_color};
    }}
    </style>
    """
