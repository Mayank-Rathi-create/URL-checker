"""
External Threat Intelligence Scanners (VirusTotal & Google Safe Browsing).
Includes caching to protect free API quotas and prevent repetitive latency.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import requests
import streamlit as st

from .models import Analysis, FindingSeverity

VT_BASE = "https://www.virustotal.com/api/v3"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


@st.cache_data(ttl=600, show_spinner=False)
def query_virustotal(url: str, api_key: str, max_wait: int = 25) -> dict[str, Any]:
    """
    Submits or retrieves analysis results from VirusTotal v3 API.
    Cached for 10 minutes.
    """
    if not api_key.strip():
        raise ValueError("Empty VirusTotal API key")

    headers = {"x-apikey": api_key.strip()}
    # VirusTotal v3 URL ID is base64 representation without padding '='
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # 1. Check if URL was previously scanned
    resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=12)
    if resp.status_code == 200:
        return resp.json()["data"]["attributes"]["last_analysis_stats"]
    elif resp.status_code not in (404,):
        resp.raise_for_status()

    # 2. Submit URL for scanning if not found
    submit = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=12)
    submit.raise_for_status()
    analysis_id = submit.json()["data"]["id"]

    # 3. Poll for analysis completion
    deadline = time.time() + max_wait
    while time.time() < deadline:
        time.sleep(2.5)
        poll = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=12)
        poll.raise_for_status()
        attrs = poll.json()["data"]["attributes"]
        if attrs.get("status") == "completed":
            return attrs.get("stats", {})

    raise TimeoutError("VirusTotal analysis did not complete within the timeout threshold.")


@st.cache_data(ttl=600, show_spinner=False)
def query_google_safe_browsing(url: str, api_key: str) -> list[dict[str, Any]]:
    """
    Queries Google Safe Browsing v4 threat matches.
    Cached for 10 minutes.
    """
    if not api_key.strip():
        raise ValueError("Empty Google Safe Browsing API key")

    body = {
        "client": {"clientId": "url-safety-checker", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    resp = requests.post(GSB_URL, params={"key": api_key.strip()}, json=body, timeout=12)
    resp.raise_for_status()
    return resp.json().get("matches", [])


def apply_scanners(analysis: Analysis, vt_api_key: str, gsb_api_key: str) -> None:
    """
    Executes configured external threat intelligence checks and updates analysis findings.
    """
    clean_runs = 0
    scanners_active = 0

    # VirusTotal Scanner
    if vt_api_key.strip():
        scanners_active += 1
        analysis.scanners_used.append("VirusTotal")
        try:
            stats = query_virustotal(analysis.url, vt_api_key)
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1

            if malicious >= 3:
                analysis.add(
                    FindingSeverity.BAD,
                    f"VirusTotal: Flagged Malicious ({malicious}/{total} engines)",
                    f"High confidence threat: {malicious} security vendors categorized this URL as malicious.",
                    category="intelligence",
                    points=80,
                )
            elif malicious > 0 or suspicious > 0:
                analysis.add(
                    FindingSeverity.WARN,
                    f"VirusTotal: Suspicious ({malicious} malicious, {suspicious} suspicious)",
                    f"Multiple vendors flagged this URL ({malicious} malicious, {suspicious} suspicious out of {total}).",
                    category="intelligence",
                    points=35,
                )
            else:
                analysis.add(
                    FindingSeverity.GOOD,
                    f"VirusTotal: Clean Verdict (0/{total} engines)",
                    f"None of the {total} security engines flagged this URL as malicious.",
                    category="intelligence",
                    points=0,
                )
                clean_runs += 1
        except Exception as exc:
            analysis.scanner_notes.append(f"VirusTotal scan skipped or failed: {exc}")

    # Google Safe Browsing
    if gsb_api_key.strip():
        scanners_active += 1
        analysis.scanners_used.append("Google Safe Browsing")
        try:
            matches = query_google_safe_browsing(analysis.url, gsb_api_key)
            if matches:
                threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
                analysis.add(
                    FindingSeverity.BAD,
                    f"Google Safe Browsing: Blacklisted ({', '.join(threats)})",
                    f"Identified as an active threat on Google Safe Browsing blacklist: {', '.join(threats)}.",
                    category="intelligence",
                    points=90,
                )
            else:
                analysis.add(
                    FindingSeverity.GOOD,
                    "Google Safe Browsing: Not Listed",
                    "No match found in Google's database of known malware and social engineering sites.",
                    category="intelligence",
                    points=0,
                )
                clean_runs += 1
        except Exception as exc:
            analysis.scanner_notes.append(f"Google Safe Browsing scan skipped or failed: {exc}")

    # Verified clean if all attempted scanners returned zero flags
    successful_scans = scanners_active - len(analysis.scanner_notes)
    if successful_scans > 0 and clean_runs == successful_scans:
        analysis.scanner_clean = True
