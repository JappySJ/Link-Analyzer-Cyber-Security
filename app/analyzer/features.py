"""
URL feature extraction - the single source of truth for the ML model.

IMPORTANT DESIGN RULE
---------------------
Every feature here is computed from the URL STRING ALONE. No DNS lookup, no
TLS handshake, no network access of any kind. That guarantees three things:

  1. Training is possible. Most URLs in any phishing dataset point at domains
     that were taken down long ago, so a certificate simply cannot be fetched
     for them.
  2. Training and serving see exactly the same feature values. There is no
     "the model saw a cert during training but not at prediction time" skew.
  3. Feature extraction is instant and works completely offline.

Certificate signals are still used by the tool - they feed the HEURISTIC
score in heuristics.py, not the ML model. See the README for the full
justification.

Both app/ml/train.py and app/analyzer/predictor.py import extract_vector()
from this module, so the feature code exists in exactly one place.
"""

from __future__ import annotations

import collections
import ipaddress
import math
import re
import urllib.parse

from app.config import (
    BRAND_SAFE_LABELS,
    HIGH_RISK_TLDS,
    IMPERSONATED_BRANDS,
    SUSPICIOUS_KEYWORDS,
    URL_SHORTENERS,
)

# ---------------------------------------------------------------------------
# Fixed feature order.
#
# This list IS the contract between training and serving. train.py writes it to
# features.json; predictor.py reads that file back and refuses to run if the
# order ever drifts. Never reorder these without retraining the model.
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_digits_host",
    "digit_ratio_host",
    "num_special_chars",
    "num_subdomains",
    "path_depth",
    "has_ip_host",
    "has_at_symbol",
    "has_double_slash_path",
    "is_https",
    "is_shortener",
    "high_risk_tld",
    "tld_length",
    "domain_entropy",
    "url_entropy",
    "brand_impersonation",
    "suspicious_keyword_count",
    "has_punycode",
    "has_non_ascii",
    "num_percent_encodings",
    "has_explicit_port",
    "longest_token_len_host",
    # --- typosquat detection (added on top of the 27 required features) ---
    # Nothing in the list above can tell 'google.com' from 'goggle.com': they
    # have almost identical length, entropy and character mix. The difference
    # is dictionary knowledge, so it needs its own feature.
    "is_exact_brand_domain",
    "is_typosquat",
]

# Pre-compiled regexes (compiling once matters when we extract 2000+ rows).
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_SPECIAL_RE = re.compile(r"[@?=&%#~$*+,;:!'\"\\|<>^`(){}\[\]]")
_HOST_TOKEN_RE = re.compile(r"[.\-_]")

# Characters that make up a "normal" URL; anything else counts as special.
_SPECIAL_CHARS = set("@?=&%#~$*+,;:!'\"\\|<>^`(){}[]")


# ---------------------------------------------------------------------------
# Small shared helpers (also imported by heuristics.py so the two modules
# always agree on what "the domain" or "the entropy" means)
# ---------------------------------------------------------------------------


def shannon_entropy(text: str) -> float:
    """
    Shannon entropy in bits per character.

    Randomly generated (DGA) domains such as 'x7fq2mz9plw' spread their
    characters evenly and score high (>4.0 bits); real words such as
    'wikipedia' repeat letters and score lower.
    """
    if not text:
        return 0.0
    counts = collections.Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def normalise_url(raw_url: str) -> str:
    """Trim whitespace and add a scheme if the user omitted one."""
    raw = (raw_url or "").strip()
    if not raw:
        return ""
    if not _SCHEME_RE.match(raw):
        raw = "https://" + raw
    return raw


def parse_url(raw_url: str) -> urllib.parse.ParseResult:
    """Parse a URL, never raising - a broken URL yields empty components."""
    try:
        return urllib.parse.urlparse(normalise_url(raw_url))
    except Exception:
        return urllib.parse.urlparse("https://invalid.invalid/")


def get_hostname(raw_url: str) -> str:
    """Hostname in lower case, or '' when the URL has none."""
    try:
        return (parse_url(raw_url).hostname or "").lower()
    except Exception:
        return ""


def get_tld(hostname: str) -> str:
    """Return the last label with a leading dot, e.g. '.com'. '' if none."""
    parts = [p for p in hostname.split(".") if p]
    return "." + parts[-1] if len(parts) >= 2 else ""


def get_registrable_domain(hostname: str) -> str:
    """
    Approximate registrable domain: the last two labels ('paypal.com').

    A real implementation would consult the Public Suffix List; two labels is a
    deliberate simplification and is documented as a limitation in the README.
    """
    parts = [p for p in hostname.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def get_subdomain_parts(hostname: str) -> list[str]:
    """Labels to the left of the registrable domain."""
    parts = [p for p in hostname.split(".") if p]
    return parts[:-2] if len(parts) > 2 else []


def is_ip_host(hostname: str) -> bool:
    """True when the host is a literal IPv4/IPv6 address instead of a name."""
    if not hostname:
        return False
    candidate = hostname.strip("[]")          # IPv6 URLs look like http://[::1]/
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def brand_impersonation_hits(hostname: str, full_path: str) -> list[tuple[str, str]]:
    """
    Find impersonated brand names and report WHERE each one was found.

    Returns a list of (brand, location) with location in
    {"subdomain", "domain", "path"}.

    The 'domain' case deliberately skips a host whose registrable domain simply
    starts with the brand followed by a dot (paypal.com itself), so the real
    site is never flagged for containing its own name.
    """
    host = (hostname or "").lower()
    domain = get_registrable_domain(host)
    sub = ".".join(get_subdomain_parts(host))
    path = (full_path or "").lower()

    hits: list[tuple[str, str]] = []
    for brand in IMPERSONATED_BRANDS:
        if brand in sub:
            hits.append((brand, "subdomain"))
        elif brand in domain and not domain.startswith(brand + "."):
            hits.append((brand, "domain"))
        elif brand in path:
            hits.append((brand, "path"))
    return hits


def suspicious_keywords_found(hostname: str, full_path: str) -> list[str]:
    """Credential/urgency words present anywhere in host or path."""
    haystack = f"{hostname}{full_path}".lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in haystack]


def build_full_path(parsed: urllib.parse.ParseResult) -> str:
    """Path + query + fragment, reassembled into one string."""
    pieces = [parsed.path or ""]
    if parsed.query:
        pieces.append("?" + parsed.query)
    if parsed.fragment:
        pieces.append("#" + parsed.fragment)
    return "".join(pieces)


# ---------------------------------------------------------------------------
# Typosquat detection
# ---------------------------------------------------------------------------

# Minimum brand length before we look for near-misses. "sbi" and "ups" are only
# three characters, so almost any short word sits within edit distance 1 of
# them and we would flag half the web. Longer brands are safe to fuzzy-match.
_MIN_BRAND_LEN_FOR_TYPO = 5

# Brands of 5-7 characters allow one edit; 8+ characters allow two, because a
# longer word can absorb a second change and still be recognisable to a victim.
_TYPO_MAX_DISTANCE_SHORT = 1
_TYPO_MAX_DISTANCE_LONG = 2
_LONG_BRAND_LEN = 6


def levenshtein(first: str, second: str, max_distance: int = 3) -> int:
    """
    Edit distance between two strings: how many single-character insertions,
    deletions or substitutions turn one into the other.

    'google' -> 'goggle' is 1 (substitute one letter).
    'amazon' -> 'arnazon' is 2 (m becomes r, then insert n).

    Classic dynamic-programming implementation using two rows instead of the
    full matrix, and it stops early once every value exceeds max_distance,
    because a distance of 7 and a distance of 70 mean the same thing to us.
    """
    if first == second:
        return 0
    if abs(len(first) - len(second)) > max_distance:
        return max_distance + 1

    previous = list(range(len(second) + 1))
    for i, char_a in enumerate(first, start=1):
        current = [i]
        for j, char_b in enumerate(second, start=1):
            cost = 0 if char_a == char_b else 1
            current.append(min(
                previous[j] + 1,        # deletion
                current[j - 1] + 1,     # insertion
                previous[j - 1] + cost,  # substitution
            ))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def brand_distance(domain_label: str) -> tuple[int, str]:
    """
    Distance from a domain label to the closest known brand name.

    Returns (distance, brand). A distance of 0 means the label IS a brand
    ('google' in google.com); 1 or 2 means it is a near-miss, which is what a
    typosquat looks like; 3 means unrelated to any brand we know.
    """
    label = (domain_label or "").lower()
    if not label:
        return 3, ""

    # A real company whose name merely resembles another brand is not a
    # typosquat - see BRAND_SAFE_LABELS in config.py.
    if label in BRAND_SAFE_LABELS:
        return 3, ""

    best_distance, best_brand = 3, ""
    for brand in IMPERSONATED_BRANDS:
        if label == brand:
            return 0, brand
        if len(brand) < _MIN_BRAND_LEN_FOR_TYPO:
            continue
        distance = levenshtein(label, brand, max_distance=2)
        if distance < best_distance:
            best_distance, best_brand = distance, brand
    return best_distance, best_brand


def typosquat_check(hostname: str) -> tuple[bool, bool, str, int]:
    """
    Classify a hostname's registrable domain against the brand list.

    Returns (is_exact_brand, is_typosquat, matched_brand, distance).

    is_exact_brand  - the domain label equals a brand ('paypal.com'). Only the
                      real owner can hold that name, so it is a benign signal.
    is_typosquat    - the label is 1-2 edits from a brand without being it
                      ('paypa1', 'goggle', 'arnazon'). Strong phishing signal.
    """
    host = (hostname or "").lower()
    domain = get_registrable_domain(host)
    label = domain.split(".")[0] if domain else ""

    distance, brand = brand_distance(label)

    if distance == 0:
        return True, False, brand, 0

    if brand:
        limit = (_TYPO_MAX_DISTANCE_LONG if len(brand) >= _LONG_BRAND_LEN
                 else _TYPO_MAX_DISTANCE_SHORT)
        if 1 <= distance <= limit:
            return False, True, brand, distance

    return False, False, brand, distance


# ---------------------------------------------------------------------------
# The feature extractor
# ---------------------------------------------------------------------------


def extract_features(url: str) -> dict[str, float]:
    """
    Turn one URL string into the 27 numeric features named in FEATURE_NAMES.

    Every value is a plain int or float. Never returns NaN, never raises: a
    malformed URL degrades to a vector of mostly zeros rather than crashing the
    scan or the training run.
    """
    raw = normalise_url(url)
    parsed = parse_url(raw)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_path = build_full_path(parsed)

    domain = get_registrable_domain(hostname)
    # Entropy is measured on the label the attacker chose, e.g. 'paypal-secure'
    # in 'paypal-secure.tk', not on the whole host.
    domain_label = domain.split(".")[0] if domain else ""
    tld = get_tld(hostname)
    subdomains = get_subdomain_parts(hostname)

    host_digits = sum(1 for c in hostname if c.isdigit())
    host_tokens = [t for t in _HOST_TOKEN_RE.split(hostname) if t]

    # '//' appearing inside the path (not the scheme separator) is a classic
    # open-redirect / path-confusion trick.
    has_double_slash = 1.0 if "//" in path else 0.0

    # An explicit port is legitimate for dev servers but rare on real sites.
    try:
        has_port = 1.0 if parsed.port is not None else 0.0
    except ValueError:
        # urllib raises when the port is not a valid integer (e.g. 'host:abc').
        has_port = 1.0

    try:
        raw.encode("ascii")
        has_non_ascii = 0.0
    except UnicodeEncodeError:
        has_non_ascii = 1.0

    is_exact_brand, is_typosquat, _brand, _distance = typosquat_check(hostname)

    features: dict[str, float] = {
        # --- raw sizes ---
        "url_length": float(len(raw)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        # --- character composition ---
        "num_dots": float(hostname.count(".")),
        "num_hyphens": float(raw.count("-")),
        "num_digits_host": float(host_digits),
        "digit_ratio_host": round(host_digits / max(len(hostname), 1), 4),
        "num_special_chars": float(sum(1 for c in raw if c in _SPECIAL_CHARS)),
        # --- structure ---
        "num_subdomains": float(len(subdomains)),
        "path_depth": float(len([seg for seg in path.split("/") if seg])),
        "has_ip_host": 1.0 if is_ip_host(hostname) else 0.0,
        "has_at_symbol": 1.0 if "@" in raw.split("?")[0] else 0.0,
        "has_double_slash_path": has_double_slash,
        "has_explicit_port": has_port,
        # --- transport / reputation of the name itself ---
        "is_https": 1.0 if parsed.scheme == "https" else 0.0,
        "is_shortener": 1.0 if hostname in URL_SHORTENERS else 0.0,
        "high_risk_tld": 1.0 if tld in HIGH_RISK_TLDS else 0.0,
        "tld_length": float(len(tld)),
        # --- randomness ---
        "domain_entropy": round(shannon_entropy(domain_label), 4),
        "url_entropy": round(shannon_entropy(raw), 4),
        # --- semantics ---
        "brand_impersonation": float(len(brand_impersonation_hits(hostname, full_path))),
        "suspicious_keyword_count": float(len(suspicious_keywords_found(hostname, full_path))),
        # --- obfuscation ---
        "has_punycode": 1.0 if "xn--" in hostname else 0.0,
        "has_non_ascii": has_non_ascii,
        "num_percent_encodings": float(len(_PERCENT_RE.findall(raw))),
        "longest_token_len_host": float(max((len(t) for t in host_tokens), default=0)),
        # --- typosquat ---
        "is_exact_brand_domain": 1.0 if is_exact_brand else 0.0,
        "is_typosquat": 1.0 if is_typosquat else 0.0,
    }

    # Defensive guarantee: no NaN/inf ever reaches scikit-learn.
    for name in FEATURE_NAMES:
        value = features.get(name, 0.0)
        if value is None or not math.isfinite(value):
            value = 0.0
        features[name] = float(value)

    return features


def extract_vector(url: str) -> list[float]:
    """Feature values as a list ordered exactly like FEATURE_NAMES."""
    features = extract_features(url)
    return [features[name] for name in FEATURE_NAMES]


def url_metadata(url: str) -> dict:
    """
    Human-facing facts about a URL for the report card in the web UI.

    This is presentation data, not model input.
    """
    raw = normalise_url(url)
    parsed = parse_url(raw)
    hostname = (parsed.hostname or "").lower()
    domain = get_registrable_domain(hostname)
    domain_label = domain.split(".")[0] if domain else ""
    return {
        "normalised_url": raw,
        "scheme": parsed.scheme or "",
        "hostname": hostname,
        "domain": domain,
        "tld": get_tld(hostname),
        "path": parsed.path or "",
        "query": parsed.query or "",
        "url_length": len(raw),
        "domain_entropy": round(shannon_entropy(domain_label), 2),
        "url_entropy": round(shannon_entropy(raw), 2),
        "is_ip_host": is_ip_host(hostname),
        "subdomain_count": len(get_subdomain_parts(hostname)),
    }
