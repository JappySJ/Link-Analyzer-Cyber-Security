"""
VirusTotal API v3 client (free tier friendly).

Design rules for this module:

  * The API key comes from the environment (.env -> VT_API_KEY). It is NEVER
    hard-coded, and .env is git-ignored. .env.example ships instead.
  * A VirusTotal failure must NEVER break a scan. Every path - missing key,
    rate limit, timeout, malformed response - returns a dict with a "status"
    field the rest of the app can render.
  * The free tier allows 4 requests/minute and 500/day, so successful lookups
    are cached in memory for 10 minutes to protect the quota.
  * Total time spent is bounded: at most 3 polls x 4 seconds = 12 seconds.

Status values: not_configured | ok | not_found | rate_limited | unauthorized |
               unavailable | timeout
"""

from __future__ import annotations

import base64
import threading
import time

import requests

from app.config import (
    VT_API_BASE,
    VT_API_KEY,
    VT_CACHE_TTL,
    VT_POLL_ATTEMPTS,
    VT_POLL_DELAY,
    VT_TIMEOUT,
)

# ---------------------------------------------------------------------------
# In-memory cache: url_id -> (stored_at_epoch, result_dict)
#
# Guarded by a lock because FastAPI runs our blocking routes in a threadpool,
# so two requests really can touch this dict at the same time.
# ---------------------------------------------------------------------------

_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_LOCK = threading.Lock()


def url_to_id(url: str) -> str:
    """
    VirusTotal's URL identifier: unpadded URL-safe base64 of the URL itself.

    This is exactly what the v3 API expects at GET /urls/{id}.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def is_configured() -> bool:
    """True when a VT_API_KEY is present in the environment."""
    return bool(VT_API_KEY)


def _cache_get(url_id: str) -> dict | None:
    with _CACHE_LOCK:
        entry = _CACHE.get(url_id)
        if not entry:
            return None
        stored_at, payload = entry
        if time.time() - stored_at > VT_CACHE_TTL:
            _CACHE.pop(url_id, None)
            return None
        cached = dict(payload)
        cached["cached"] = True
        return cached


def _cache_put(url_id: str, payload: dict) -> None:
    with _CACHE_LOCK:
        _CACHE[url_id] = (time.time(), payload)


def clear_cache() -> None:
    """Drop every cached VT response (used by the test suite)."""
    with _CACHE_LOCK:
        _CACHE.clear()


def _result(status: str, message: str = "", **extra) -> dict:
    """
    Build a result with every key the UI expects always present.

    Keeping the shape identical across success and failure means the frontend
    never has to guard against a missing field.
    """
    payload = {
        "status": status,
        "message": message,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total": 0,
        "vt_score": 0.0,
        "summary": message,
        "permalink": "",
        "cached": False,
    }
    payload.update(extra)
    return payload


def _parse_stats(attributes: dict) -> dict:
    """
    Turn a VT `attributes` block into our normalised result.

    vt_score = (malicious + 0.5 * suspicious) / total * 100
    Suspicious verdicts count half because engines use that category for
    "probably unwanted" rather than "confirmed phishing".
    """
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected

    vt_score = ((malicious + 0.5 * suspicious) / total * 100) if total else 0.0

    if total == 0:
        summary = "No engine results available for this URL"
    elif malicious or suspicious:
        summary = f"{malicious + suspicious}/{total} engines flagged this URL"
    else:
        summary = f"0/{total} engines flagged this URL"

    return _result(
        "ok",
        summary,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        total=total,
        vt_score=round(vt_score, 2),
        summary=summary,
    )


def _request(method: str, endpoint: str, data: dict | None = None):
    """
    One HTTP call to VirusTotal.

    Returns (status_code, json_dict). status_code is None when the request
    never completed (timeout / DNS failure / no internet).
    """
    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    url = f"{VT_API_BASE}{endpoint}"
    try:
        if method == "POST":
            response = requests.post(url, headers=headers, data=data, timeout=VT_TIMEOUT)
        else:
            response = requests.get(url, headers=headers, timeout=VT_TIMEOUT)
        try:
            body = response.json()
        except ValueError:
            body = {}
        return response.status_code, body
    except requests.exceptions.Timeout:
        return None, {"_error": "timeout"}
    except requests.exceptions.RequestException as exc:
        # Covers ConnectionError - i.e. running completely offline.
        return None, {"_error": str(exc)}


def check_url(url: str) -> dict:
    """
    Look a URL up on VirusTotal.

    Flow:
      1. GET /urls/{url_id} - the cached community report (cheap, usually hits).
      2. On 404 the URL is new to VT: POST /urls to submit it, then poll
         GET /analyses/{id} up to VT_POLL_ATTEMPTS times with VT_POLL_DELAY
         second gaps (bounded at ~12s total).

    Always returns a dict; never raises.
    """
    if not is_configured():
        return _result(
            "not_configured",
            "VirusTotal not configured - add VT_API_KEY to .env to enable it",
        )

    url_id = url_to_id(url)

    cached = _cache_get(url_id)
    if cached is not None:
        return cached

    # --- 1. existing report -------------------------------------------------
    status_code, body = _request("GET", f"/urls/{url_id}")

    if status_code == 200:
        attributes = (body.get("data") or {}).get("attributes") or {}
        result = _parse_stats(attributes)
        result["permalink"] = f"https://www.virustotal.com/gui/url/{url_id}"
        _cache_put(url_id, result)
        return result

    if status_code == 429:
        return _result(
            "rate_limited",
            "VirusTotal rate limit reached - the free tier allows 4 requests "
            "per minute and 500 per day. Try again in a minute.",
        )

    if status_code in (401, 403):
        return _result(
            "unauthorized",
            "VirusTotal rejected the API key - check VT_API_KEY in .env",
        )

    if status_code is None:
        return _result(
            "unavailable",
            "VirusTotal unreachable (no internet connection or request timed out)",
        )

    if status_code != 404:
        return _result("unavailable", f"VirusTotal returned HTTP {status_code}")

    # --- 2. unknown URL: submit it for analysis -----------------------------
    status_code, body = _request("POST", "/urls", data={"url": url})

    if status_code == 429:
        return _result(
            "rate_limited",
            "VirusTotal rate limit reached while submitting the URL - the free "
            "tier allows 4 requests per minute.",
        )
    if status_code is None:
        return _result("unavailable", "VirusTotal unreachable while submitting the URL")
    if status_code not in (200, 201) or "data" not in body:
        return _result("unavailable", f"VirusTotal submission failed (HTTP {status_code})")

    analysis_id = (body.get("data") or {}).get("id")
    if not analysis_id:
        return _result("unavailable", "VirusTotal did not return an analysis id")

    # --- 3. poll for the fresh verdict (bounded) ---------------------------
    for _ in range(VT_POLL_ATTEMPTS):
        time.sleep(VT_POLL_DELAY)
        status_code, body = _request("GET", f"/analyses/{analysis_id}")
        if status_code != 200:
            continue
        attributes = (body.get("data") or {}).get("attributes") or {}
        if attributes.get("status") == "completed":
            result = _parse_stats(attributes)
            result["permalink"] = f"https://www.virustotal.com/gui/url/{url_id}"
            _cache_put(url_id, result)
            return result

    return _result(
        "timeout",
        "VirusTotal is still analysing this URL - it was submitted successfully, "
        "so try again in a minute for the result.",
    )
