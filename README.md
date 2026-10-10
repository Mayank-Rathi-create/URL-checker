# URL Safety & Phishing Inspector 🛡️

A modern, privacy-first web application that rates links as **Safe**, **Moderate**, or **Danger** *before* you click them — and explains why.
Built with a **Zero-Click Guarantee**: the application **never connects to, fetches, or executes the target URL**.

---

## ✨ Features & Capabilities

### 🎨 Simple & Eye-Catching UI / UX
- **🌓 Dark & Light Theme Switcher**: 1-click toggle between a high-contrast Cyber Dark mode and an ultra-clean Light mode.
- **⚡ Quick-Test Samples**: Test official domains, typosquatting, subdomain spoofs, shorteners, IP hosts, and punycode with a single click.
- **🔍 URL Anatomy Breakdown**: Visual deconstruction into color-coded pills (Scheme, Subdomain, Real Registered Domain, Port, Path, Query). Clearly distinguishes deceptive subdomains from the actual destination domain.
- **🔤 Homograph & Punycode Spotlight**: Directly identifies deceptive international characters (e.g. Cyrillic `а` U+0430 mimicking Latin `a`) and shows their Unicode codepoint and mimic target.
- **📊 Interactive Threat Meter**: Clean visual threat gauge bar (0 to 100) and categorized findings.
- **📦 Batch URL Scanner**: Inspect multiple links simultaneously from emails, messages, or reports.
- **📋 Export & Share**: Download comprehensive analysis reports in Markdown or raw JSON format.
- **🛡️ Zero-Click Link Preview**: Non-clickable safe hover preview preventing accidental navigation.

### 🧠 Advanced Detection Engine (Zero-Click Heuristics)
| Security Signal | How It Works |
|---|---|
| **Brand Authenticity & Protection** | Compares against 100+ major brands across Tech, Banking, E-Commerce, Social, Crypto, Logistics, and Streaming. Detects lookalikes (`paypa1.com`), fuzzy misspellings, hyphen combos (`paypal-login.com`), and brand injection in subdomains (`paypal.com.evil.xyz`). |
| **Reputable Domain Whitelist** | Recognizes thousands of established global public domains (Wikipedia, BBC, NYTimes, GitHub, StackOverflow, academic institutions) to avoid false alerts. |
| **Homoglyph & IDNA Inspection** | Decodes `xn--` punycode and checks characters against Unicode spoof maps to prevent visual deception. |
| **Protocol & Scheme Security** | Flags dangerous schemes (`javascript:`, `data:`, `file:`, `vbscript:`) and plaintext HTTP connections. |
| **Host Deception & IP Obfuscation** | Detects raw IPv4/IPv6, hex notation (`0x7f000001`), octal representations, and DWORD integers. |
| **Open Redirect Detection** | Checks query parameters (`?url=`, `?redirect=`, `?next=`) that redirect victims away from legitimate domains. |
| **Payload & Extension Watch** | Flags risky executable downloads (`.exe`, `.scr`, `.bat`, `.apk`, `.iso`, etc.) disguised in links. |
| **URL Shorteners & Risky TLDs** | Flags masking services (`bit.ly`, `tinyurl.com`, `t.co`, etc.) and top abused TLDs (`.zip`, `.mov`, `.top`, `.xyz`, etc.). |
| **Cloud Threat Intelligence** | Optional integration with VirusTotal v3 and Google Safe Browsing APIs with built-in caching. |

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
You can run using either `app.py` or `App.py`:
```bash
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🔑 External API Keys (Optional)

Offline heuristics run immediately without any API keys. For external multi-vendor antivirus scanning:

1. **VirusTotal** – Free API key from [virustotal.com](https://www.virustotal.com) (Profile → API Key).
2. **Google Safe Browsing** – Free key via [Google Cloud Console](https://console.cloud.google.com/) (Enable *Safe Browsing API*).

Provide them via either:
- The in-app **Settings** sidebar under *External Intelligence APIs*, or
- Environment variables: `VT_API_KEY` and `GSB_API_KEY`, or
- `.streamlit/secrets.toml`:
  ```toml
  VT_API_KEY = "your-virustotal-api-key"
  GSB_API_KEY = "your-google-safe-browsing-key"
  ```

---

## 📁 Project Architecture

```
URL-checker/
├── app.py                 # Primary application entrypoint
├── App.py                 # Entrypoint proxy (ensures case compatibility)
├── requirements.txt       # Dependencies (streamlit, requests, tldextract, idna)
├── README.md              # Documentation
├── core/                  # Security Analysis Engine (100% offline & safe)
│   ├── __init__.py
│   ├── models.py          # Data classes (Analysis, Finding, ThreatLevel, URLAnatomy)
│   ├── detector.py        # Core heuristics & rule engine
│   ├── brands.py          # Brand directory, reputable domains, threat signatures
│   ├── anatomy.py         # URL component parser & homoglyph detector
│   └── scanners.py        # VirusTotal & Google Safe Browsing API connectors
├── ui/                    # UI Components & Design System
│   ├── __init__.py
│   ├── styles.py          # Modern CSS styling for Dark & Light themes
│   └── components.py      # Verdict card, gauge, anatomy pills, metrics grid, reports
└── tests/                 # Unit test suite
    ├── __init__.py
    └── test_detector.py   # Heuristic verification tests
```

---

## 🧪 Running Tests

Execute the test suite to verify detection accuracy across all attack vectors:
```bash
python -c "import tests.test_detector as td; [getattr(td, n)() for n in dir(td) if n.startswith('test_')]; print('All tests passed!')"
```

---

## 🔒 Privacy & Security Policy

- **Zero Direct Connections**: This tool never opens, loads, or queries the target link on the user's computer or server.
- **Vendor Submission**: When VirusTotal or Google Safe Browsing keys are configured, links are queried through vendor security databases. Do not submit links containing private access tokens or sensitive confidential information.
- **Educational & Defensive**: Designed to provide clear, actionable intelligence to protect users against phishing and malicious links.