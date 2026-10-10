# URL Safety Checker

A sleek, simple, and privacy-first web application that rates links as **Safe**, **Moderate**, or **Danger** *before* you click them — and explains why.
Built with a **Zero-Click Guarantee**: the application **never connects to, fetches, or loads the target URL**.

---

## ✨ Features & Capabilities

- **🌑 Sleek Cyber Dark Theme**: Distraction-free, centered interface with high contrast and glowing security indicators.
- **📊 Eye-Catching Threat Verdict**: Visual threat exposure meter (0 to 100%) and plain-English risk classification.
- **🔍 URL Anatomy Breakdown**: Visual pills dissecting Scheme, Subdomain, Real Registered Domain, and Path to quickly spot brand spoofing in subdomains.
- **🔤 Homoglyph Deception Detector**: Identifies deceptive international characters (e.g. Cyrillic `а` mimicking Latin `a`) and shows the exact Unicode codepoints and mimic targets.
- **Zero-Click Hover Preview**: Non-clickable safe preview box to inspect destination details safely.
- **📋 Plain-English Findings**: Clear categorization into Critical Red Flags, Warnings, Good Signs, and Informational context.
- **💾 Export Findings**: Download complete analysis reports in Markdown or JSON format.

### 🧠 Detection Engine (100% Offline & Safe)
| Heuristic | What It Checks |
|---|---|
| **Brand Protection** | Compares against 100+ brands (PayPal, Apple, Google, Microsoft, Amazon, banks, crypto, shipping). Detects lookalikes (`paypa1.com`), typos, and brand injection in subdomains (`paypal.com.evil.xyz`). |
| **Reputable Domains** | Whitelist of thousands of established domains (Wikipedia, BBC, NYTimes, GitHub, StackOverflow, universities) to prevent false alerts. |
| **Punycode & Homographs** | Decodes `xn--` punycode and checks characters against Unicode spoof maps to prevent visual deception. |
| **Protocol Security** | Flags dangerous schemes (`javascript:`, `data:`, `file:`, `vbscript:`) and unencrypted plaintext HTTP. |
| **IP Obfuscation** | Detects raw IPv4/IPv6, hex notation (`0x7f000001`), octal representations, and DWORD integers. |
| **Open Redirects** | Flags deceptive query parameters (`?url=`, `?redirect=`, `?next=`) targeting external sites. |
| **Payload Downloads** | Flags dangerous executable/script extensions (`.exe`, `.scr`, `.bat`, `.apk`, `.iso`). |
| **Shorteners & Risky TLDs** | Detects link-masking services (`bit.ly`, `tinyurl.com`, `t.co`) and heavily abused TLDs (`.zip`, `.mov`, `.top`, `.xyz`). |
| **Cloud Intelligence** | Optional VirusTotal v3 and Google Safe Browsing scans with 10-minute caching. |

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the App
```bash
python -m streamlit run App.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🔑 External API Keys (Optional)

Offline heuristics run immediately without any API keys. To add cloud multi-engine threat intelligence:

Provide keys via environment variables or `.streamlit/secrets.toml`:
```toml
VT_API_KEY = "your-virustotal-api-key"
GSB_API_KEY = "your-google-safe-browsing-key"
```

---

## 📁 Project Structure

```
URL-checker/
├── App.py                 # Clean single-page application entrypoint
├── requirements.txt       # Dependencies (streamlit, requests, tldextract, idna)
├── README.md              # Documentation
├── .gitignore             # Git exclusion rules
├── core/                  # Security Heuristic Engine
│   ├── __init__.py
│   ├── models.py          # Data models and threat scoring
│   ├── brands.py          # 100+ brand signatures & reputable domains
│   ├── anatomy.py         # URL decomposition, IP obfuscation & homoglyphs
│   ├── detector.py        # Offline detection heuristics
│   └── scanners.py        # VirusTotal & Google Safe Browsing connectors
├── ui/                    # UI Components & Styling
│   ├── __init__.py
│   ├── styles.py          # Modern Dark Theme CSS design system
│   └── components.py      # Verdict card, gauge, anatomy pills, metrics
└── tests/                 # Unit Tests
    ├── __init__.py
    └── test_detector.py   # Automated heuristic verification tests
```

---

## 🧪 Running Tests

Verify all detection heuristics with the automated test suite:
```bash
python -c "import tests.test_detector as td; [getattr(td, n)() for n in dir(td) if n.startswith('test_')]; print('All tests passed!')"
```