"""
URL Safety Checker - a Streamlit app that rates a link as Safe, Moderate or Danger
WITHOUT ever opening it.

How it works
------------
1. Local checks (offline, instant): scheme/HTTPS, lookalike / typo-squatted domains,
   brand impersonation, IP-address hosts, punycode (homograph) tricks, URL shorteners,
   suspicious keywords, and the source of the link.
2. Optional online scanners (need free API keys): VirusTotal and Google Safe Browsing.
   These scan the URL from THEIR servers - this app never connects to the target site.
3. All findings add risk points -> final classification + a plain-English explanation.

Run:  streamlit run app.py
"""

from __future__ import annotations

import base64
import difflib
import html
import ipaddress
import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
import streamlit as st
import tldextract

# --------------------------------------------------------------------------- #
# Configuration / reference data
# --------------------------------------------------------------------------- #

# Brand -> official registered domains. Extend this list for better coverage.
OFFICIAL_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "github": {"github.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "flipkart": {"flipkart.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "anthropic": {"anthropic.com", "claude.ai"},
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in", "t.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click",
    "country", "work", "support", "loan", "icu", "cyou", "rest", "monster",
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "wallet", "billing", "free", "gift", "prize", "otp", "kyc",
}

# Where did the link come from?  -> (risk points, explanation)
SOURCES: dict[str, tuple[int, str]] = {
    "A website I am browsing": (0, ""),
    "Someone I know and trust (I confirmed they sent it)": (0, ""),
    "Email from a known sender": (5, "Even known senders get hacked - confirm they really sent it."),
    "Social media post / advertisement": (10, "Links in ads and posts are a common phishing route."),
    "Unsolicited email, SMS or DM": (15, "Unexpected messages are the #1 delivery method for phishing."),
    "Unknown or suspicious sender": (25, "Never trust links from people or numbers you do not know."),
}

# Thresholds on the risk score
DANGER_AT = 50
MODERATE_AT = 20

# Offline extractor: uses the bundled public-suffix snapshot, no network call.
EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

VT_BASE = "https://www.virustotal.com/api/v3"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    """One observation about the URL."""
    level: str      # "good" | "info" | "warn" | "bad"
    title: str
    detail: str
    points: int = 0  # risk points added to the score


@dataclass
class Analysis:
    url: str
    scheme: str = ""
    host: str = ""
    registered_domain: str = ""
    path: str = ""
    official_brand: str | None = None
    findings: list[Finding] = field(default_factory=list)
    scanner_clean: bool = False  # True when an online scanner ran and flagged nothing

    @property
    def score(self) -> int:
        return min(100, sum(f.points for f in self.findings))

    def add(self, level: str, title: str, detail: str, points: int = 0) -> None:
        self.findings.append(Finding(level, title, detail, points))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                      "7": "t", "$": "s", "@": "a", "!": "i"})


def normalize_lookalikes(text: str) -> str:
    """Undo common character swaps (paypa1 -> paypal, rnicrosoft -> microsoft)."""
    text = text.lower().translate(LEET)
    return text.replace("rn", "m").replace("vv", "w")


def normalize_url(raw: str) -> tuple[str, bool]:
    """Trim the input; assume https:// when no scheme is given."""
    raw = raw.strip()
    risky_schemes = ("javascript:", "data:", "vbscript:", "file:", "mailto:")
    if "://" not in raw and not raw.lower().startswith(risky_schemes):
        return "https://" + raw, True
    return raw, False


def registered_domain_of(host: str) -> str:
    ext = EXTRACT(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else host


def best_brand_match(host: str, registered: str) -> tuple[str, str, int] | None:
    """Return (brand, explanation, points) for the strongest impersonation signal."""
    ext = EXTRACT(host)
    label = ext.domain.lower()
    label_norm = normalize_lookalikes(label).replace("-", "")
    tokens = [normalize_lookalikes(t) for t in re.split(r"[.\-_]", host) if t]
    candidates: list[tuple[str, str, int]] = []

    for brand, domains in OFFICIAL_DOMAINS.items():
        official = sorted(domains)[0]
        if label == brand:
            candidates.append((brand, f"Uses the name '{brand}' on '{registered}', which is not "
                               f"an official domain. Official: {official}.", 50))
        elif label_norm == brand:
            candidates.append((brand, f"'{label}' is a look-alike spelling of '{brand}' "
                               f"(character swap). Official domain: {official}.", 60))
        elif len(brand) >= 5 and len(label_norm) >= 4 and \
                difflib.SequenceMatcher(None, label_norm, brand).ratio() >= 0.85:
            candidates.append((brand, f"'{label}' is almost identical to '{brand}' "
                               f"(possible typo-squatting). Official domain: {official}.", 55))
        elif brand in tokens:
            candidates.append((brand, f"The name '{brand}' appears in the address, but the real "
                               f"site is '{registered}'. Official domain: {official}.", 45))

    return max(candidates, key=lambda c: c[2]) if candidates else None


# --------------------------------------------------------------------------- #
# Local analysis
# --------------------------------------------------------------------------- #

def analyze_url(raw_url: str, source: str) -> Analysis:
    """Run every offline check and return the findings. Never touches the network."""
    url, assumed_scheme = normalize_url(raw_url)
    result = Analysis(url=url)

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        result.add("bad", "Malformed URL", "The address cannot be parsed - it may be deliberately broken.", 60)
        return result

    result.scheme, result.host, result.path = parsed.scheme.lower(), host, parsed.path or "/"

    # --- 1. Scheme / HTTPS ------------------------------------------------- #
    if result.scheme not in ("http", "https"):
        result.add("bad", f"Unsafe scheme '{result.scheme}:'",
                   "Only http/https links are normal. Other schemes can run code or read files.", 80)
        return result
    if not host:
        result.add("bad", "No domain found", "The URL has no valid host name.", 60)
        return result

    if assumed_scheme:
        result.add("info", "No scheme given", "You did not type http:// or https://, so https:// was assumed.")
    if result.scheme == "https":
        result.add("good", "Uses HTTPS",
                   "Traffic is encrypted (the padlock appears in a browser). Note: HTTPS only means "
                   "encrypted - phishing sites use it too.")
    else:
        result.add("warn", "No HTTPS", "Plain HTTP is not encrypted; data you enter can be read or changed in transit.", 15)

    # --- 2. Host structure tricks ----------------------------------------- #
    try:
        ip = ipaddress.ip_address(host)
        result.add("bad", "IP address instead of a domain",
                   f"The link points to a raw IP ({ip}). Legitimate services almost always use domain names.", 35)
        result.registered_domain = host
    except ValueError:
        ip = None
        result.registered_domain = registered_domain_of(host)

    if "@" in parsed.netloc:
        result.add("bad", "Hidden '@' trick",
                   "Text before '@' is ignored by browsers, so the link can look like one site but go to another.", 55)
    if "xn--" in host or not host.isascii():
        result.add("bad", "Internationalised (punycode) characters",
                   "Look-alike letters from other alphabets (e.g. Cyrillic 'а') can fake a real brand.", 40)
    if port and port not in (80, 443):
        result.add("warn", f"Unusual port :{port}", "Normal websites rarely use non-standard ports.", 10)

    # --- 3. Brand authenticity / typo-squatting --------------------------- #
    if ip is None:
        reg = result.registered_domain
        result.official_brand = next((b for b, d in OFFICIAL_DOMAINS.items() if reg in d), None)

        if result.official_brand:
            result.add("good", "Matches an official domain",
                       f"'{reg}' is a known official domain of {result.official_brand.title()}.")
        else:
            match = best_brand_match(host, reg)
            if match:
                result.add("bad", "Possible brand impersonation / spelling trick", match[1], match[2])

        # Shorteners
        if reg in URL_SHORTENERS:
            result.add("warn", "URL shortener",
                       "The real destination is hidden. Use an online scanner or a link expander to see where it goes.", 25)

        # TLD / structure
        suffix = EXTRACT(host).suffix.split(".")[-1]
        if suffix in SUSPICIOUS_TLDS:
            result.add("warn", f"Risky top-level domain '.{suffix}'",
                       "This TLD is cheap and heavily abused for spam and phishing.", 10)
        sub = EXTRACT(host).subdomain
        if sub and sub.count(".") + 1 > 3:
            result.add("warn", "Too many subdomains", "Long subdomain chains are used to bury the real domain.", 10)
        if host.count("-") >= 3:
            result.add("warn", "Many hyphens in domain", "Domains stuffed with hyphens are typical of throw-away phishing sites.", 10)

        # Keywords (ignored for official domains)
        if not result.official_brand:
            hits = sorted(k for k in PHISHING_KEYWORDS if k in (host + parsed.path).lower())
            if len(hits) >= 2:
                result.add("warn", "Phishing-style keywords", f"The address contains: {', '.join(hits)}.", 15)

    if len(url) > 100:
        result.add("info", "Very long URL", "Long URLs can hide the real destination.", 5)

    # --- 4. Source of the link -------------------------------------------- #
    points, note = SOURCES[source]
    if points:
        result.add("warn", f"Source: {source}", note, points)
    else:
        result.add("info", f"Source: {source}", "No extra risk from the source.")

    return result


# --------------------------------------------------------------------------- #
# Online scanners (optional)
# --------------------------------------------------------------------------- #

def virustotal_scan(url: str, api_key: str, max_wait: int = 45) -> dict:
    """Return VirusTotal analysis stats for the URL (looks up first, submits if unknown)."""
    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=15)
    if resp.status_code != 404:
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]["last_analysis_stats"]

    submit = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=15)
    submit.raise_for_status()
    analysis_id = submit.json()["data"]["id"]
    deadline = time.time() + max_wait
    while time.time() < deadline:
        time.sleep(3)
        poll = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=15)
        poll.raise_for_status()
        attrs = poll.json()["data"]["attributes"]
        if attrs["status"] == "completed":
            return attrs["stats"]
    raise TimeoutError("VirusTotal did not finish in time - try again in a minute.")


def safe_browsing_scan(url: str, api_key: str) -> list[dict]:
    """Return Google Safe Browsing threat matches (empty list = nothing known)."""
    body = {
        "client": {"clientId": "url-safety-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    resp = requests.post(GSB_URL, params={"key": api_key}, json=body, timeout=15)
    resp.raise_for_status()
    return resp.json().get("matches", [])


def apply_scanners(result: Analysis, vt_key: str, gsb_key: str) -> list[str]:
    """Run whichever scanners have keys; add findings. Returns a list of notes/errors."""
    notes: list[str] = []
    ran_clean = []

    if vt_key:
        try:
            stats = virustotal_scan(result.url, vt_key)
            bad, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
            total = sum(stats.values())
            if bad >= 3:
                result.add("bad", "VirusTotal: flagged as malicious", f"{bad} of {total} engines flagged this URL.", 80)
            elif bad or sus:
                result.add("warn", "VirusTotal: some engines are suspicious",
                           f"{bad} malicious + {sus} suspicious out of {total} engines.", 35)
            else:
                result.add("good", "VirusTotal: no detections", f"0 of {total} engines flagged this URL.")
                ran_clean.append(True)
        except Exception as exc:  # network, quota, bad key ...
            notes.append(f"VirusTotal check failed: {exc}")

    if gsb_key:
        try:
            matches = safe_browsing_scan(result.url, gsb_key)
            if matches:
                kinds = ", ".join(sorted({m["threatType"] for m in matches}))
                result.add("bad", "Google Safe Browsing: known threat", f"Listed as: {kinds}.", 90)
            else:
                result.add("good", "Google Safe Browsing: not listed", "No known threats for this URL.")
                ran_clean.append(True)
        except Exception as exc:
            notes.append(f"Google Safe Browsing check failed: {exc}")

    # "Clean" only if every scanner that ran came back clean
    ran = int(bool(vt_key)) + int(bool(gsb_key)) - len(notes)
    result.scanner_clean = ran > 0 and len(ran_clean) == ran
    return notes


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

def classify(result: Analysis) -> tuple[str, str]:
    """Return (label, reason-for-label)."""
    score = result.score
    if score >= DANGER_AT:
        return "Danger", "Strong warning signs were found."
    if score >= MODERATE_AT:
        return "Moderate", "Some warning signs were found - be careful."
    verified = result.official_brand is not None or result.scanner_clean
    if not verified:
        return "Moderate", ("No red flags found, but this domain is not on the known-official list "
                            "and no online scanner confirmed it. Add API keys for a stronger verdict.")
    return "Safe", "No red flags found and the site is verified."


def build_feedback(result: Analysis, label: str) -> str:
    bad = [f.title for f in result.findings if f.level in ("bad", "warn")]
    good = [f.title for f in result.findings if f.level == "good"]
    if bad and good:
        return f"**Mixed result.** Good: {'; '.join(good)}. But: {'; '.join(bad)}."
    if bad:
        return f"**Why it is not safe:** {'; '.join(bad)}."
    if good:
        return f"**Why it looks safe:** {'; '.join(good)}."
    return "Not enough information to give a strong opinion."


# --------------------------------------------------------------------------- #
# Streamlit UI
# --------------------------------------------------------------------------- #

def get_secret(name: str) -> str:
    """Read a key from Streamlit secrets or environment variables."""
    try:
        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:
        pass
    return os.environ.get(name, "")


def render_hover_preview(url: str, display_text: str) -> None:
    """Show the link as plain text; hovering reveals the REAL URL. It is not clickable."""
    safe_real = html.escape(url, quote=True)
    safe_text = html.escape(display_text or url)
    st.markdown(
        f'<span title="{safe_real}" style="border-bottom:1px dotted #888;cursor:help;'
        f'font-size:1.05rem;">{safe_text}</span>',
        unsafe_allow_html=True,
    )
    st.caption("Hover over the text above to see the real destination. It is not clickable - this app never opens links.")


def render_result(result: Analysis, label: str, reason: str, notes: list[str]) -> None:
    box = {"Safe": st.success, "Moderate": st.warning, "Danger": st.error}[label]
    icon = {"Safe": "✅", "Moderate": "⚠️", "Danger": "🚨"}[label]
    box(f"{icon} **Classification: {label}** - {reason}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{result.score} / 100")
    c2.metric("Domain", result.registered_domain or "-")
    c3.metric("Protocol", result.scheme.upper() or "-")

    st.markdown(build_feedback(result, label))

    groups = [("🚩 Red flags", ("bad",)), ("⚠️ Warnings", ("warn",)),
              ("✅ Good signs", ("good",)), ("ℹ️ Info", ("info",))]
    for title, levels in groups:
        items = [f for f in result.findings if f.level in levels]
        if items:
            with st.expander(title, expanded=levels[0] in ("bad", "warn")):
                for f in items:
                    pts = f" (+{f.points} risk)" if f.points else ""
                    st.markdown(f"**{f.title}**{pts}  \n{f.detail}")

    for n in notes:
        st.info(n)


def main() -> None:
    st.set_page_config(page_title="URL Safety Checker", layout="centered")
    st.title("URL Safety Checker")
    st.write("Paste a link to check it **before** you click. This app never opens the URL.")

    with st.expander("How to use", expanded=False):
        st.markdown(
            "1. Paste the link (right-click → *Copy link address*, don't click it).\n"
            "2. Choose where you got the link from.\n"
            "3. Press **Check URL** and read the explanation.\n\n"
            "**Safe** = no red flags and verified · **Moderate** = be careful / unverified · "
            "**Danger** = do not open."
        )

    vt_key = get_secret("VT_API_KEY")
    gsb_key = get_secret("GSB_API_KEY")

    with st.form("check_form"):
        url_input = st.text_input("URL to check", placeholder="https://example.com/login")
        source = st.selectbox("Where did this link come from?", list(SOURCES.keys()), index=0)
        submitted = st.form_submit_button("Check URL", type="primary")

    if not submitted:
        return
    if not url_input.strip():
        st.warning("Please enter a URL first.")
        return

    with st.spinner("Analysing (the link is NOT being opened)..."):
        result = analyze_url(url_input, source)
        notes = apply_scanners(result, vt_key, gsb_key) if result.host else []
        label, reason = classify(result)

    st.subheader("Link preview")
    render_hover_preview(result.url, result.url)
    st.code(result.url, language=None)

    st.subheader("Result")
    render_result(result, label, reason, notes)
    st.caption("No tool can guarantee a link is safe. Treat this as a helpful second opinion, not a guarantee.")


if __name__ == "__main__":
    main()