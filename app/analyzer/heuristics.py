"""
Weighted rule-based scoring - the explainable half of the hybrid engine.

This is the direct port of the rules from the original LTAT.py CLI. Where the
ML model gives one opaque probability, this module gives a score AND a list of
human-readable reasons: "Brand 'paypal' in subdomain - classic spoofing, +20".

Every point value comes from config.WEIGHTS. No number is hard-coded here, so
the whole scoring policy can be shown and tuned from a single screen.

The heuristic score is where CERTIFICATE evidence is consumed. The ML model
deliberately never sees certificate data (see features.py for why), so the TLS
rules below are what make an expired or self-signed certificate count against a
site.
"""

from __future__ import annotations

import urllib.parse

from app.analyzer.features import (
    brand_impersonation_hits,
    build_full_path,
    get_subdomain_parts,
    get_tld,
    parse_url,
    suspicious_keywords_found,
)
from app.config import (
    HEURISTIC_MAX,
    REDIRECT_PARAM_KEYS,
    SEVERITY_ORDER,
    WEIGHTS,
)

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"


def _reason(rule: str, points: int, severity: str, message: str) -> dict:
    """Build one entry of the 'why this verdict' list."""
    return {
        "rule": rule,
        "points": int(points),
        "severity": severity,
        "message": message,
    }


def score_url(url: str, features: dict[str, float], cert_info: dict | None = None) -> tuple[int, list[dict]]:
    """
    Score a URL from 0 (clean) to 100 (many strong phishing indicators).

    Parameters
    ----------
    url        : the raw URL string
    features   : the dict from features.extract_features() - reused rather than
                 recomputed, so the two modules can never disagree
    cert_info  : the dict from certs.inspect_certificate(), or None when the
                 certificate check was skipped or the host was unreachable

    Returns
    -------
    (score, reasons) where score is capped at HEURISTIC_MAX and reasons is a
    list of dicts sorted by points descending.
    """
    reasons: list[dict] = []
    parsed = parse_url(url)
    hostname = (parsed.hostname or "").lower()
    full_path = build_full_path(parsed)
    raw = url or ""

    def add(rule: str, weight_key: str, severity: str, message: str, points: int | None = None) -> None:
        value = WEIGHTS[weight_key] if points is None else points
        reasons.append(_reason(rule, value, severity, message))

    # ---------------------------------------------------------------- host
    if features.get("has_ip_host"):
        add("ip_as_host", "ip_as_host", HIGH,
            "Host is a raw IP address instead of a domain name - legitimate "
            "services do not host login pages on bare IPs")

    if features.get("is_shortener"):
        add("url_shortener", "url_shortener", HIGH,
            f"URL shortener ({hostname}) - the real destination is hidden")

    tld = get_tld(hostname)
    if features.get("high_risk_tld"):
        add("high_risk_tld", "high_risk_tld", HIGH,
            f"High-risk TLD '{tld}' - free or abuse-heavy registry frequently "
            "used for phishing")

    if features.get("has_explicit_port"):
        add("explicit_port", "explicit_port", MEDIUM,
            "URL specifies an explicit port - unusual for a genuine public site")

    subdomain_count = int(features.get("num_subdomains", 0))
    if subdomain_count >= 4:
        add("deep_subdomains", "deep_subdomains", HIGH,
            f"Deep subdomain nesting ({subdomain_count} levels) - used to bury "
            "the real domain out of sight")
    elif subdomain_count >= 2:
        add("some_subdomains", "some_subdomains", LOW,
            f"Multiple subdomain levels ({subdomain_count})")

    if not features.get("is_https"):
        add("no_https", "no_https", MEDIUM,
            "Plain HTTP - traffic is unencrypted and can be read or modified "
            "in transit")

    # -------------------------------------------------------- obfuscation
    if features.get("has_at_symbol"):
        add("at_symbol", "at_symbol", CRITICAL,
            "'@' in the URL - a browser ignores everything before it, so the "
            "visible domain is not where you actually go")

    if features.get("has_punycode"):
        add("punycode", "punycode", HIGH,
            "Punycode ('xn--') hostname - possible homograph attack using "
            "look-alike characters from another alphabet")

    if features.get("has_non_ascii"):
        add("non_ascii", "non_ascii", CRITICAL,
            "Non-ASCII characters in the URL - unicode look-alike (homograph) "
            "attack is likely")

    if features.get("has_double_slash_path"):
        add("double_slash_path", "double_slash_path", MEDIUM,
            "'//' inside the URL path - commonly used to smuggle a redirect")

    percent_count = int(features.get("num_percent_encodings", 0))
    if percent_count > 8:
        add("heavy_encoding", "heavy_encoding", HIGH,
            f"Heavy percent-encoding ({percent_count} escapes) - deliberate "
            "obfuscation of the real path")
    elif percent_count > 3:
        add("some_encoding", "some_encoding", LOW,
            f"Some percent-encoding ({percent_count} escapes)")

    url_length = int(features.get("url_length", 0))
    if url_length > 200:
        add("very_long_url", "very_long_url", HIGH,
            f"Extremely long URL ({url_length} characters) - a common way to "
            "push the real domain off the end of the address bar")
    elif url_length > 100:
        add("long_url", "long_url", LOW,
            f"Long URL ({url_length} characters)")

    # ------------------------------------------------------------ lexical
    for brand, location in brand_impersonation_hits(hostname, full_path):
        if location == "subdomain":
            add(f"brand_in_subdomain:{brand}", "brand_in_subdomain", HIGH,
                f"Brand '{brand}' appears in a subdomain - classic spoofing "
                f"(the real owner of the site is '{hostname.split('.')[-2] if hostname.count('.') >= 1 else hostname}')")
        elif location == "domain":
            add(f"brand_in_domain:{brand}", "brand_in_domain", HIGH,
                f"Brand '{brand}' embedded in the domain but this is not the "
                "brand's official domain")
        else:
            add(f"brand_in_path:{brand}", "brand_in_path", MEDIUM,
                f"Brand '{brand}' used in the URL path to look legitimate")

    keywords = suspicious_keywords_found(hostname, full_path)
    if len(keywords) >= 3:
        add("many_keywords", "many_keywords", HIGH,
            f"Multiple credential/urgency keywords: {', '.join(keywords[:5])}")
    elif keywords:
        add("suspicious_keywords", "keyword_each", MEDIUM,
            f"Suspicious keyword(s): {', '.join(keywords)}",
            points=WEIGHTS["keyword_each"] * len(keywords))

    entropy = float(features.get("domain_entropy", 0.0))
    if entropy > 4.0:
        add("high_entropy", "high_entropy", HIGH,
            f"Domain entropy {entropy:.2f} bits/char - the name looks randomly "
            "generated (DGA), not chosen by a human")
    elif entropy > 3.3:
        add("medium_entropy", "medium_entropy", MEDIUM,
            f"Domain entropy {entropy:.2f} bits/char - somewhat unusual name")

    try:
        query_params = urllib.parse.parse_qs(parsed.query or "")
        redirect_hits = REDIRECT_PARAM_KEYS & {k.lower() for k in query_params}
    except Exception:
        redirect_hits = set()
    if redirect_hits:
        add("redirect_param", "redirect_param", MEDIUM,
            f"Open-redirect style parameter(s): {', '.join(sorted(redirect_hits))}")

    # --------------------------------------------------------------- TLS
    # Certificate evidence is heuristic-only by design; the ML model never sees
    # any of it (see features.py).
    if cert_info:
        status = cert_info.get("status")

        if status == "ok":
            if cert_info.get("is_expired"):
                add("cert_expired", "cert_expired", CRITICAL,
                    f"Certificate is outside its validity window "
                    f"(valid to {cert_info.get('valid_to') or 'unknown'})")

            if cert_info.get("self_signed"):
                add("cert_self_signed", "cert_self_signed", HIGH,
                    "Self-signed certificate - no certificate authority vouches "
                    "for this site, so the padlock is meaningless")
            elif not cert_info.get("chain_trusted"):
                add("cert_untrusted_chain", "cert_untrusted_chain", HIGH,
                    "Certificate chain does not reach a trusted root CA: "
                    f"{cert_info.get('error') or 'verification failed'}")

            if not cert_info.get("hostname_match"):
                add("cert_hostname_mismatch", "cert_hostname_mismatch", HIGH,
                    f"Certificate is not valid for '{hostname}' - it was issued "
                    f"for '{cert_info.get('subject_cn') or 'a different name'}'")

            days_left = cert_info.get("days_to_expiry")
            if isinstance(days_left, int) and not cert_info.get("is_expired"):
                if days_left < 7:
                    add("cert_expiring_urgent", "cert_expiring_urgent", HIGH,
                        f"Certificate expires in {days_left} day(s)")
                elif days_left < 30:
                    add("cert_expiring_soon", "cert_expiring_soon", MEDIUM,
                        f"Certificate expires soon ({days_left} days left)")

            validity_days = cert_info.get("validity_days")
            if isinstance(validity_days, int) and validity_days <= 1:
                add("cert_short_lifetime", "cert_short_lifetime", HIGH,
                    "Certificate lifetime is one day or less - typical of a "
                    "throwaway certificate")

            if cert_info.get("is_free_ca"):
                issuer = cert_info.get("issuer_org") or cert_info.get("issuer_cn") or "free CA"
                add("cert_free_ca", "cert_free_ca", LOW,
                    f"Issued by a free CA ({issuer}) - valid, but anyone can "
                    "obtain one in minutes, so it proves no identity")

            tls_version = (cert_info.get("tls_version") or "").upper()
            if tls_version in {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}:
                add("cert_weak_tls", "cert_weak_tls", HIGH,
                    f"Deprecated TLS version in use: {cert_info.get('tls_version')}")

            cipher = (cert_info.get("cipher") or "").upper()
            if any(weak in cipher for weak in ("RC4", "DES", "EXPORT", "NULL", "MD5")):
                add("cert_weak_cipher", "cert_weak_cipher", HIGH,
                    f"Weak cipher suite negotiated: {cert_info.get('cipher')}")

        elif status in {"unreachable", "no_tls"} and features.get("is_https"):
            # The URL promises HTTPS but nothing served a certificate. Often the
            # domain is already dead or was never real.
            add("cert_no_tls", "cert_no_tls", MEDIUM,
                "URL claims HTTPS but no TLS certificate could be retrieved - "
                "the host may be offline, parked or already taken down")

    # ------------------------------------------------------------- totals
    total = sum(r["points"] for r in reasons)
    score = min(total, HEURISTIC_MAX)

    reasons.sort(
        key=lambda r: (r["points"], SEVERITY_ORDER.get(r["severity"], 0)),
        reverse=True,
    )
    return int(score), reasons
