"""
Central configuration for LTAT.

EVERY tunable number in the project lives here: file paths, heuristic rule
weights, hybrid fusion weights and verdict thresholds. Nothing else in the
codebase hard-codes a weight or a threshold, so the whole scoring policy can be
explained (and tuned) from this one file.
"""

from pathlib import Path
import os

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Paths  (pathlib everywhere so the project works on Windows and Linux alike)
# ---------------------------------------------------------------------------

APP_DIR = Path(__file__).resolve().parent          # .../ltat2/app
BASE_DIR = APP_DIR.parent                          # .../ltat2

ML_DIR = APP_DIR / "ml"
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"
DATA_DIR = BASE_DIR / "data"

DATASET_PATH = ML_DIR / "dataset.csv"
MODEL_PATH = ML_DIR / "model.pkl"
FEATURES_PATH = ML_DIR / "features.json"
METRICS_PATH = ML_DIR / "metrics.json"
DB_PATH = DATA_DIR / "ltat.db"

# The database directory is created eagerly; SQLite will not create it for us.
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Environment (.env)
# ---------------------------------------------------------------------------

load_dotenv(BASE_DIR / ".env")

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 10          # seconds per HTTP call
VT_POLL_ATTEMPTS = 3     # how many times we re-check a fresh analysis
VT_POLL_DELAY = 4        # seconds between polls -> worst case 12s, under the 15s budget
VT_CACHE_TTL = 600       # in-memory cache lifetime in seconds (10 minutes)

APP_VERSION = "2.0.0"
APP_NAME = "Link Threat Analysis Tool"

SERVER_HOST = "127.0.0.1"   # loopback only - never expose this tool on a LAN
SERVER_PORT = int(os.getenv("PORT", "8000"))

# ---------------------------------------------------------------------------
# Scan cache and rate limiting  (see app/ratelimit.py)
# ---------------------------------------------------------------------------

# Repeat scans of the SAME url inside this window are served from memory
# instead of re-running DNS + TLS + the VirusTotal lookup.
SCAN_CACHE_TTL = 300           # seconds (5 minutes)
SCAN_CACHE_MAX_ENTRIES = 256   # hard cap so a long session cannot grow forever

# Sliding-window cap on POST /api/analyze. Generous for a human clicking
# "Analyze", but it stops a runaway loop from burning the VirusTotal daily
# quota (500/day on the free tier) or flooding the history table.
RATE_LIMIT_MAX_REQUESTS = 20   # requests ...
RATE_LIMIT_WINDOW = 60         # ... per this many seconds

CERT_TIMEOUT = 5         # seconds for the TLS handshake
DNS_TIMEOUT = 3          # seconds for hostname resolution

# ---------------------------------------------------------------------------
# Heuristic rule weights (points added to the 0-100 heuristic score)
#
# These are ported straight from the original LTAT.py CLI. Keeping them in a
# plain dict means the viva demo can point at one screen and say "these are the
# rules and this is what each one costs".
# ---------------------------------------------------------------------------

WEIGHTS = {
    # --- host / network shape ---
    "ip_as_host":            25,   # http://192.168.0.1/login - no domain at all
    "url_shortener":         18,   # bit.ly and friends hide the real destination
    "high_risk_tld":         18,   # .tk .ml .xyz ... - free or abuse-heavy TLDs
    "explicit_port":         10,   # https://site.com:8443/ - unusual for real sites
    "deep_subdomains":       15,   # a.b.c.d.evil.com - 4+ levels of nesting
    "some_subdomains":        5,   # 2-3 levels - mildly unusual
    "no_https":              10,   # plain HTTP - unencrypted transport

    # --- string obfuscation ---
    "at_symbol":             25,   # everything left of '@' is ignored by browsers
    "punycode":              20,   # xn-- - IDN homograph attack vector
    "non_ascii":             25,   # raw unicode look-alike characters
    "double_slash_path":     15,   # //redirect trick inside the path
    "heavy_encoding":        15,   # >8 percent-escapes - deliberate obfuscation
    "some_encoding":          5,   # 4-8 percent-escapes
    "very_long_url":         15,   # >200 characters
    "long_url":               8,   # >100 characters

    # --- lexical / semantic ---
    "brand_in_subdomain":    20,   # paypal.secure-login.xyz  <- classic spoof
    "brand_in_domain":       15,   # paypal-secure.tk
    "brand_in_path":         10,   # evil.tk/paypal/login
    "many_keywords":         20,   # 3+ of verify/login/secure/suspended/...
    "keyword_each":           8,   # per keyword when fewer than 3 were found
    "high_entropy":          20,   # >4.0 bits/char - DGA-style random domain
    "medium_entropy":        10,   # >3.3 bits/char
    "redirect_param":        12,   # ?url= / ?next= open-redirect parameters

    # --- TLS / PKI (heuristic only, never fed to the ML model) ---
    "cert_expired":          25,   # certificate validity window is in the past
    "cert_self_signed":      20,   # issuer == subject, no CA anchor
    "cert_untrusted_chain":  15,   # chain does not reach a trusted root
    "cert_hostname_mismatch": 18,  # cert is not valid for the host we asked for
    "cert_expiring_soon":     8,   # <30 days left
    "cert_expiring_urgent":  15,   # <7 days left
    "cert_short_lifetime":   20,   # issued for <=1 day - throwaway certificate
    "cert_free_ca":           5,   # Let's Encrypt etc - free, so trivially obtained
    "cert_weak_tls":         20,   # TLS 1.0 / 1.1 / SSLv3
    "cert_weak_cipher":      20,   # RC4 / DES / EXPORT suites
    "cert_no_tls":           10,   # HTTPS URL but the TLS port never answered
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

HEURISTIC_MAX = 100      # the heuristic score is capped here

# ---------------------------------------------------------------------------
# Hybrid fusion weights
#
#   with VirusTotal:     0.35*heuristic + 0.40*(ml_prob*100) + 0.25*vt_score
#   without VirusTotal:  0.50*heuristic + 0.50*(ml_prob*100)
#   without the model:   heuristic alone
# ---------------------------------------------------------------------------

FUSION_WITH_VT = {"heuristic": 0.35, "ml": 0.40, "vt": 0.25}
FUSION_NO_VT = {"heuristic": 0.50, "ml": 0.50}

# Verdict bands on the final 0-100 score.
THRESHOLD_SAFE = 30          # final < 30            -> Safe
THRESHOLD_MALICIOUS = 60     # 30 <= final <= 60     -> Suspicious, > 60 -> Malicious

VERDICT_SAFE = "Safe"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_MALICIOUS = "Malicious"

# ---------------------------------------------------------------------------
# Knowledge sets - ported verbatim from the original LTAT.py so the offline
# heuristics need no network access at all.
# ---------------------------------------------------------------------------

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".online", ".site",
    ".info", ".biz", ".buzz", ".icu", ".cyou",
    ".shop", ".store", ".live", ".cam", ".pw",
    ".cc", ".su", ".ws", ".work", ".rest", ".monster",
}

IMPERSONATED_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "icloud", "outlook", "office365", "onedrive", "sharepoint",
    "chase", "wellsfargo", "citibank", "bankofamerica", "hsbc",
    "ebay", "alibaba", "aliexpress", "shopify", "stripe",
    "coinbase", "binance", "blockchain", "metamask",
    "dhl", "fedex", "ups", "usps",
    "irs", "medicare",
    "whatsapp", "telegram", "discord", "zoom", "steam",
    # Indian services commonly impersonated locally
    "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe",
    "irctc", "aadhaar", "incometax",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "update", "confirm", "secure", "security", "account",
    "password", "passwd", "credential", "authenticate",
    "banking", "payment", "invoice", "billing",
    "suspended", "locked", "urgent", "alert", "warning",
    "recover", "recovery", "reset", "unlock",
    "free", "win", "winner", "prize", "bonus", "gift",
    "limited", "offer", "expires", "webscr", "wallet",
]

# Real company names that happen to sit within 2 edits of a DIFFERENT brand in
# the list above. Without this exemption the typosquat detector would accuse
# these legitimate businesses of impersonating a competitor:
#   spotify   is 2 edits from shopify
#   icicibank is 2 edits from citibank
# Distance alone cannot tell "attacker mimicking a brand" from "two real
# companies with similar names", so the collisions are listed explicitly.
BRAND_SAFE_LABELS = {
    "spotify", "icicibank", "hdfcbank", "axisbank", "kotak",
    "flipkart", "myntra", "snapdeal", "swiggy", "zomato",
}

FREE_CA_ISSUERS = [
    "let's encrypt", "letsencrypt", "zerossl", "buypass",
    "ssl.com free", "sectigo free",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.io", "rebrand.ly", "cutt.ly", "is.gd", "v.gd",
    "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
}

REDIRECT_PARAM_KEYS = {
    "url", "redirect", "return", "next", "goto", "link",
    "redir", "target", "dest", "destination", "forward",
}

# Only these URL schemes are accepted by the API and the CLI.
ALLOWED_SCHEMES = {"http", "https"}
