"""
CSS Design System and Theme Engine.
Provides bespoke styles for Dark and Light themes with simple, eye-catching aesthetics.
"""

from __future__ import annotations


def get_theme_css(theme: str = "dark") -> str:
    """
    Returns custom CSS tailored for the selected theme ('dark' or 'light').
    """
    is_dark = theme.lower() == "dark"

    if is_dark:
        bg_main = "#0B0F19"
        bg_card = "#111827"
        bg_card_secondary = "#1E293B"
        border_color = "rgba(255, 255, 255, 0.08)"
        border_highlight = "rgba(56, 189, 248, 0.3)"
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
        hero_glow = "radial-gradient(ellipse at 50% 0%, rgba(56, 189, 248, 0.12) 0%, transparent 70%)"
    else:
        bg_main = "#F8FAFC"
        bg_card = "#FFFFFF"
        bg_card_secondary = "#F1F5F9"
        border_color = "#E2E8F0"
        border_highlight = "rgba(37, 99, 235, 0.3)"
        text_primary = "#0F172A"
        text_secondary = "#475569"
        text_muted = "#94A3B8"
        accent_blue = "#2563EB"
        accent_indigo = "#4F46E5"
        pill_bg = "#F1F5F9"
        pill_border = "#CBD5E1"

        safe_bg = "#ECFDF5"
        safe_border = "#10B981"
        safe_text = "#065F46"

        warn_bg = "#FFFBEB"
        warn_border = "#F59E0B"
        warn_text = "#92400E"

        danger_bg = "#FEF2F2"
        danger_border = "#EF4444"
        danger_text = "#991B1B"

        card_shadow = "0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01)"
        hero_glow = "radial-gradient(ellipse at 50% 0%, rgba(37, 99, 235, 0.07) 0%, transparent 70%)"

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

    /* Global Typography & Background */
    html, body, [class*="css"], .stApp {{
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        background-color: {bg_main} !important;
        color: {text_primary} !important;
    }}

    /* Background glow effect */
    .stApp {{
        background-image: {hero_glow} !important;
        background-attachment: fixed !important;
    }}

    /* Header styling */
    header[data-testid="stHeader"] {{
        background-color: transparent !important;
    }}

    /* Card Containers */
    .custom-card {{
        background: {bg_card};
        border: 1px solid {border_color};
        border-radius: 16px;
        padding: 24px;
        box-shadow: {card_shadow};
        margin-bottom: 20px;
        transition: all 0.25s ease;
    }}

    .custom-card:hover {{
        border-color: {border_highlight};
    }}

    /* Hero Banner */
    .hero-container {{
        text-align: center;
        padding: 24px 0 32px 0;
    }}

    .hero-badge {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: {pill_bg};
        border: 1px solid {pill_border};
        padding: 6px 14px;
        border-radius: 9999px;
        font-size: 0.82rem;
        font-weight: 600;
        color: {accent_blue};
        letter-spacing: 0.5px;
        text-transform: uppercase;
        margin-bottom: 12px;
    }}

    .hero-title {{
        font-size: 2.5rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        line-height: 1.15;
        margin-bottom: 10px;
        background: linear-gradient(135deg, {text_primary} 30%, {accent_blue} 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }}

    .hero-subtitle {{
        font-size: 1.05rem;
        color: {text_secondary};
        max-width: 650px;
        margin: 0 auto;
        line-height: 1.5;
    }}

    /* Verdict Card */
    .verdict-card {{
        border-radius: 16px;
        padding: 28px;
        margin-bottom: 24px;
        position: relative;
        overflow: hidden;
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
        font-size: 1.7rem;
        font-weight: 800;
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 6px;
    }}

    .verdict-subtext {{
        font-size: 1rem;
        opacity: 0.95;
        margin-bottom: 16px;
        line-height: 1.45;
    }}

    /* Meter / Gauge Bar */
    .gauge-wrapper {{
        margin-top: 16px;
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
        background: rgba(128, 128, 128, 0.2);
        border-radius: 999px;
        overflow: hidden;
    }}

    .gauge-fill {{
        height: 100%;
        border-radius: 999px;
        transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
    }}

    /* Metrics Grid */
    .metric-card {{
        background: {bg_card};
        border: 1px solid {border_color};
        border-radius: 14px;
        padding: 16px 20px;
        text-align: left;
    }}

    .metric-card-title {{
        font-size: 0.78rem;
        font-weight: 600;
        color: {text_muted};
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
    }}

    .metric-card-val {{
        font-size: 1.4rem;
        font-weight: 700;
        color: {text_primary};
    }}

    .metric-card-sub {{
        font-size: 0.8rem;
        color: {text_secondary};
        margin-top: 2px;
    }}

    /* Anatomy Pills */
    .anatomy-box {{
        background: {bg_card};
        border: 1px solid {border_color};
        border-radius: 14px;
        padding: 18px 20px;
        margin-bottom: 20px;
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
        font-size: 0.7rem;
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
        font-size: 1.3rem;
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
        font-size: 0.95rem;
        color: {text_primary};
    }}

    .finding-points {{
        font-size: 0.75rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 999px;
        background: {danger_bg};
        color: {danger_text};
        border: 1px solid {danger_border};
    }}

    .finding-detail {{
        font-size: 0.87rem;
        color: {text_secondary};
        line-height: 1.45;
    }}

    /* Hover Preview Box */
    .preview-box {{
        background: {pill_bg};
        border: 1px dashed {border_color};
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        margin: 16px 0;
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

    /* Clean Streamlit form & button overrides */
    div[data-testid="stForm"] {{
        border: 1px solid {border_color} !important;
        border-radius: 16px !important;
        background: {bg_card} !important;
        padding: 24px !important;
    }}

    button[kind="primary"] {{
        background: linear-gradient(135deg, {accent_blue}, {accent_indigo}) !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 10px 24px !important;
        font-weight: 600 !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3) !important;
        transition: transform 0.15s ease, box-shadow 0.15s ease !important;
    }}

    button[kind="primary"]:hover {{
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(37, 99, 235, 0.4) !important;
    }}

    /* Input inputs */
    div[data-baseweb="input"] {{
        background-color: {bg_card_secondary} !important;
        border-color: {border_color} !important;
        border-radius: 10px !important;
    }}

    /* Selectbox */
    div[data-baseweb="select"] {{
        background-color: {bg_card_secondary} !important;
        border-radius: 10px !important;
    }}

    /* Tabs styling */
    button[data-baseweb="tab"] {{
        font-weight: 600 !important;
        font-size: 0.92rem !important;
    }}

    /* Code block */
    pre, code {{
        font-family: 'JetBrains Mono', monospace !important;
    }}

    /* Footer */
    .app-footer {{
        text-align: center;
        margin-top: 48px;
        padding: 24px;
        font-size: 0.82rem;
        color: {text_muted};
        border-top: 1px solid {border_color};
    }}
    </style>
    """
