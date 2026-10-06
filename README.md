
# 🛡️ URL Safety Checker

A Streamlit web app that rates a link as **Safe**, **Moderate** or **Danger** *before* you click it — and explains why.
The app **never opens or connects to the URL** you enter.

## Features

| Feature | How it works |
|---|---|
| Domain authenticity | Compares the domain with a list of official brand domains; detects look-alikes (`paypa1.com`), typos (`gooogle.com`) and brand names hidden in subdomains (`paypal.com.evil.xyz`) |
| HTTPS check | Checks the URL scheme (`https` vs `http`) |
| Online scanners | VirusTotal and Google Safe Browsing (optional, free API keys) |
| Source of the link | You pick where the link came from; unknown/unsolicited sources add risk |
| Hover preview | Shows the link as non-clickable text; hovering reveals the real destination |
| Link-text mismatch | Optional field: catches links that *say* `paypal.com` but go elsewhere |
| Extra red flags | IP-address hosts, `@` tricks, punycode/homograph characters, URL shorteners, risky TLDs, odd ports, phishing keywords |
| Feedback | Plain-English explanation of red flags and good signs |

## Quick start

```bash
# 1. (optional) create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. install dependencies
pip install -r requirements.txt

# 3. run
streamlit run app.py
```

Open http://localhost:8501.

## API keys (optional but recommended)

Without keys only the offline checks run. For stronger verdicts:

- **VirusTotal** – free key at https://www.virustotal.com (profile → API key)
- **Google Safe Browsing** – free key via Google Cloud Console (enable *Safe Browsing API*)

Provide them any of three ways:

1. Paste into the sidebar, **or**
2. Environment variables: `VT_API_KEY`, `GSB_API_KEY`, **or**
3. `.streamlit/secrets.toml` (never commit this file):

```toml
VT_API_KEY = "your-virustotal-key"
GSB_API_KEY = "your-safe-browsing-key"
```

> **URLVoid:** its API is a paid service, so Google Safe Browsing is used as the free alternative. You can add URLVoid by writing another function like `virustotal_scan()` in `app.py` and calling it from `apply_scanners()`.

## How the classification works

Every finding adds *risk points*:

| Score | Result |
|---|---|
| 50+ | 🚨 **Danger** |
| 20 – 49 | ⚠️ **Moderate** |
| 0 – 19 | ✅ **Safe** — *only if verified* (official domain, or a scanner returned clean). Otherwise **Moderate** ("unverified") |

Examples:

| Input | Result |
|---|---|
| `https://paypal.com` | Safe – official domain over HTTPS |
| `https://paypa1.com` | Danger – look-alike spelling of paypal |
| `http://bit.ly/xyz123` | Moderate – shortened link, no HTTPS |

## Known limitations (please read)

- **No tool can guarantee a link is safe.** A brand-new phishing site may not be in any database yet. Treat results as a second opinion.
- **The padlock icon can't be inspected** by a server-side app (it is a browser feature). The app checks the `https` scheme instead. HTTPS means *encrypted*, not *trustworthy*.
- **Shortened links are not expanded**, because that would require contacting the link. Use VirusTotal to analyse the final destination.
- **Brand list is small.** Add more brands/domains to `OFFICIAL_DOMAINS` in `app.py`.
- **Hover feature:** browsers can only show the hover tooltip for text rendered by the page, so the app shows the link as non-clickable text with a tooltip.
- Heuristics can give false positives (e.g. a legit `.xyz` site) and false negatives.

## Privacy

- The URL is **only** sent to VirusTotal / Google if you provide keys for them. VirusTotal submissions can become visible to other VirusTotal users, so don't scan links containing private tokens or personal data.
- Nothing is stored by this app.

## Project structure

```
url-safety-checker/
├── app.py            # whole application (analysis + scanners + UI)
├── requirements.txt
└── README.md
```

## Deploy (Streamlit Community Cloud)

1. Push this folder to GitHub.
2. Create a new app at https://share.streamlit.io pointing to `app.py`.
3. Add `VT_API_KEY` / `GSB_API_KEY` under *Settings → Secrets*.

## Ideas to extend

- Domain age via WHOIS (new domains are riskier)
- Safe link expansion using a sandboxed service
- Upload an `.eml` file and check every link in it
- Unit tests with `pytest` for `analyze_url()`