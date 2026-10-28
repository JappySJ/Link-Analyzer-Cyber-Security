"""
In-memory scan cache and request rate limiter.

Both live in process memory only. That is the right choice for a single-user
local tool: no extra dependency, no Redis, nothing to configure, and the state
resets cleanly when the server restarts.

Why each exists
---------------
CACHE      A scan costs a DNS lookup, a TLS handshake and possibly an HTTPS
           round trip to VirusTotal. Re-scanning the same URL twice in a minute
           should not pay that cost again - and, on the free VirusTotal tier
           (4 requests/minute), repeating it can actually get you rate limited
           by them. Repeat scans inside the TTL are served from memory.

RATE LIMIT A runaway script or a stuck "Analyze" button could fire hundreds of
           scans a second, exhausting the VirusTotal daily quota and filling
           the history table with junk. A fixed cap makes that impossible.

Both structures are guarded by a lock, because FastAPI runs the blocking route
handlers in a threadpool - two requests really can touch these dicts at once.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from app.config import (
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW,
    SCAN_CACHE_TTL,
    SCAN_CACHE_MAX_ENTRIES,
)

# ---------------------------------------------------------------------------
# Scan cache:  normalised_url -> (stored_at_epoch, result_dict)
# ---------------------------------------------------------------------------

_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_LOCK = threading.Lock()


def cache_get(url: str) -> dict | None:
    """
    Return a cached result for `url`, or None when there is no fresh entry.

    The returned dict is a shallow copy carrying two extra keys the UI uses:
        cached      True
        cached_age  whole seconds since the original scan
    """
    now = time.time()
    with _CACHE_LOCK:
        entry = _CACHE.get(url)
        if entry is None:
            return None

        stored_at, payload = entry
        age = now - stored_at
        if age > SCAN_CACHE_TTL:
            _CACHE.pop(url, None)
            return None

        result = dict(payload)

    result["cached"] = True
    result["cached_age"] = int(age)
    return result


def cache_put(url: str, result: dict) -> None:
    """
    Store a scan result under `url`.

    Evicts the oldest entries when the cache grows past SCAN_CACHE_MAX_ENTRIES
    so a long session cannot grow memory without bound.
    """
    payload = dict(result)
    # Never persist the per-request flags - they are recomputed on read.
    payload.pop("cached", None)
    payload.pop("cached_age", None)

    with _CACHE_LOCK:
        _CACHE[url] = (time.time(), payload)

        if len(_CACHE) > SCAN_CACHE_MAX_ENTRIES:
            # Drop the oldest entries first (cheap: this cache stays small).
            for stale_url, _ in sorted(_CACHE.items(), key=lambda kv: kv[1][0])[
                : len(_CACHE) - SCAN_CACHE_MAX_ENTRIES
            ]:
                _CACHE.pop(stale_url, None)


def cache_clear() -> None:
    """Empty the cache (used by the test suite)."""
    with _CACHE_LOCK:
        _CACHE.clear()


def cache_size() -> int:
    """How many entries are currently held."""
    with _CACHE_LOCK:
        return len(_CACHE)


# ---------------------------------------------------------------------------
# Rate limiter: a sliding window of request timestamps per client
# ---------------------------------------------------------------------------

_HITS: dict[str, deque] = {}
_RATE_LOCK = threading.Lock()


def check_rate_limit(client: str = "local") -> tuple[bool, int, int]:
    """
    Record a request from `client` and say whether it is allowed.

    Returns (allowed, remaining, retry_after_seconds).

    Sliding window rather than a fixed bucket: we keep the timestamps of recent
    requests and discard any older than RATE_LIMIT_WINDOW. That avoids the
    fixed-bucket edge case where 2x the limit can pass in a moment by straddling
    a bucket boundary.

    When the request is rejected, retry_after is the number of whole seconds
    until the oldest request in the window ages out and a slot frees up.
    """
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW

    with _RATE_LOCK:
        hits = _HITS.setdefault(client, deque())

        while hits and hits[0] <= cutoff:
            hits.popleft()

        if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
            retry_after = max(1, int(hits[0] + RATE_LIMIT_WINDOW - now) + 1)
            return False, 0, retry_after

        hits.append(now)
        return True, RATE_LIMIT_MAX_REQUESTS - len(hits), 0


def rate_limit_reset() -> None:
    """Forget every recorded request (used by the test suite)."""
    with _RATE_LOCK:
        _HITS.clear()
