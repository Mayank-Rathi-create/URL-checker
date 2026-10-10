"""
Brand registry, reputational whitelists, and threat signatures.
"""

from __future__ import annotations

# Official domains for frequently spoofed organizations across major sectors
OFFICIAL_DOMAINS: dict[str, set[str]] = {
    # Tech & Infrastructure
    "google": {"google.com", "google.co.in", "google.co.uk", "google.ca", "gmail.com", "youtube.com", "android.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "azure.com", "bing.com", "skype.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp", "aws.amazon.com"},
    "github": {"github.com", "github.io"},
    "gitlab": {"gitlab.com"},
    "adobe": {"adobe.com", "photoshop.com"},
    "openai": {"openai.com", "chatgpt.com"},
    "anthropic": {"anthropic.com", "claude.ai"},
    "zoom": {"zoom.us", "zoom.com"},
    "slack": {"slack.com"},
    "dropbox": {"dropbox.com"},
    "cloudflare": {"cloudflare.com"},
    "mozilla": {"mozilla.org", "firefox.com"},
    "reddit": {"reddit.com"},
    "wikipedia": {"wikipedia.org", "wikimedia.org"},

    # Social & Messaging
    "meta": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "telegram": {"telegram.org", "t.me"},
    "twitter": {"twitter.com", "x.com"},
    "linkedin": {"linkedin.com"},
    "discord": {"discord.com", "discord.gg"},
    "tiktok": {"tiktok.com"},
    "snapchat": {"snapchat.com"},
    "pinterest": {"pinterest.com"},
    "signal": {"signal.org"},

    # Financial & Banking (US & Global)
    "paypal": {"paypal.com", "paypal.me"},
    "stripe": {"stripe.com"},
    "wise": {"wise.com"},
    "square": {"squareup.com", "cash.app"},
    "chase": {"chase.com", "jpmorgan.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citi.com", "citibank.com"},
    "capitalone": {"capitalone.com"},
    "americanexpress": {"americanexpress.com", "amex.com"},
    "fidelity": {"fidelity.com"},
    "vanguard": {"vanguard.com"},
    "charlesschwab": {"schwab.com"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},

    # Financial & Banking (India)
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "razorpay": {"razorpay.com"},

    # E-Commerce & Retail
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de"},
    "walmart": {"walmart.com"},
    "target": {"target.com"},
    "aliexpress": {"aliexpress.com", "alibaba.com"},
    "flipkart": {"flipkart.com"},
    "shopify": {"shopify.com", "myshopify.com"},
    "etsy": {"etsy.com"},
    "bestbuy": {"bestbuy.com"},

    # Crypto & Web3
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com", "binance.us"},
    "kraken": {"kraken.com"},
    "metamask": {"metamask.io"},
    "crypto": {"crypto.com"},
    "kucoin": {"kucoin.com"},
    "bybit": {"bybit.com"},
    "okx": {"okx.com"},
    "trezor": {"trezor.io"},
    "ledger": {"ledger.com"},

    # Shipping, Postal & Logistics
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "royalmail": {"royalmail.com"},
    "dpd": {"dpd.com", "dpd.co.uk"},

    # Streaming & Gaming
    "netflix": {"netflix.com"},
    "spotify": {"spotify.com"},
    "disneyplus": {"disneyplus.com"},
    "steampowered": {"steampowered.com", "steamcommunity.com"},
    "epicgames": {"epicgames.com"},
    "playstation": {"playstation.com", "sony.com"},
    "xbox": {"xbox.com"},
    "twitch": {"twitch.tv"},

    # Government & Tax Agencies
    "irs": {"irs.gov"},
    "govuk": {"gov.uk"},
    "who": {"who.int"},
}

# Curated set of reputable global domains for educational/news/tech institutions
REPUTABLE_DOMAINS: set[str] = {
    "wikipedia.org", "wikimedia.org", "w3.org", "ietf.org", "archive.org",
    "stackoverflow.com", "stackexchange.com", "superuser.com",
    "medium.com", "dev.to", "hashnode.com", "substack.com",
    "nytimes.com", "bbc.com", "bbc.co.uk", "cnn.com", "reuters.com",
    "bloomberg.com", "wsj.com", "theguardian.com", "forbes.com",
    "washingtonpost.com", "nature.com", "sciencedirect.com", "springer.com",
    "arxiv.org", "nih.gov", "cdc.gov", "nasa.gov",
    "mit.edu", "stanford.edu", "harvard.edu", "berkeley.edu", "ox.ac.uk", "cam.ac.uk",
    "python.org", "pypi.org", "nodejs.org", "npmjs.com", "rust-lang.org",
    "golang.org", "developer.mozilla.org", "docker.com", "kubernetes.io",
}

# Known URL shortener services that mask the final destination
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
    "t.ly", "clck.ru", "s.id", "v.gd", "soo.gd", "bc.vc", "shorte.st",
    "bl.ink", "trib.al", "linktr.ee", "qr.ae", "urlr.me",
}

# Top-level domains with statistically high abuse and spam registration rates
SUSPICIOUS_TLDS: set[str] = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click",
    "country", "work", "support", "loan", "icu", "cyou", "rest", "monster",
    "quest", "beauty", "hair", "skin", "buzz", "fit", "casa", "cam", "sbs",
    "cfd", "kim", "party", "gdn", "stream", "men", "bid", "date", "racing",
}

# High-risk phishing and credential harvesting keywords
PHISHING_KEYWORDS: set[str] = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "confirmation", "password", "credential",
    "wallet", "billing", "free", "gift", "prize", "reward", "bonus", "claim",
    "otp", "kyc", "suspended", "reactivate", "restore", "unusual", "activity",
    "invoice", "receipt", "payment", "authenticate", "validation", "recover",
}

# Dangerous executable / payload file extensions masquarading in URLs
DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".msi", ".jar",
    ".apk", ".pif", ".hta", ".iso", ".dmg", ".sh", ".ps1", ".wsf",
}

# Parameters typically abused in Open Redirect vulnerabilities
OPEN_REDIRECT_PARAMS: set[str] = {
    "url", "redirect", "redirect_url", "redirect_to", "next", "dest",
    "destination", "target", "return", "return_url", "rurl", "goto", "out",
}

# Where the user acquired the link -> (risk points, explanation)
SOURCES: dict[str, tuple[int, str]] = {
    "A website I am browsing": (0, ""),
    "Someone I know and trust (I confirmed they sent it)": (0, ""),
    "Email from a known sender": (5, "Even legitimate senders can have compromised accounts or spoofed headers."),
    "Social media post or direct message": (10, "Social links and unsolicited DMs are frequent delivery vectors for scams."),
    "Search engine sponsored advertisement": (12, "Malicious actors frequently purchase ads spoofing legitimate brand names."),
    "Unsolicited email, SMS, or QR code": (15, "Unexpected messages are the #1 delivery method for phishing campaigns."),
    "Unknown or suspicious sender": (25, "High risk: Never blindly trust links originating from unknown contacts."),
}
