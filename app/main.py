"""
FastAPI application - every HTTP route for LTAT.

A NOTE ON `def` VERSUS `async def` (this is deliberate, not an oversight)
------------------------------------------------------------------------
/api/analyze performs BLOCKING work: a TLS handshake, a DNS lookup and possibly
an HTTPS request to VirusTotal. If it were declared `async def`, that blocking
work would run directly on the single asyncio event loop and freeze the entire
server for its duration - no other page would load until the scan finished.

Declared as a plain `def`, FastAPI automatically runs the handler in a worker
threadpool, leaving the event loop free. The pure-database routes are also
plain `def` for the same reason (sqlite3 calls block too).

The server binds to 127.0.0.1 only. This tool sends URLs to VirusTotal and
stores scan history; it is not hardened for exposure to a network.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app import db, ratelimit
from app.analyzer import hybrid, predictor, virustotal
from app.analyzer.features import normalise_url, parse_url
from app.config import (
    ALLOWED_SCHEMES,
    APP_NAME,
    APP_VERSION,
    RATE_LIMIT_MAX_REQUESTS,
    SERVER_HOST,
    SERVER_PORT,
    STATIC_DIR,
    TEMPLATES_DIR,
    THRESHOLD_MALICIOUS,
    THRESHOLD_SAFE,
)

logger = logging.getLogger("ltat")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the database schema on startup and log what is available."""
    db.init_db()
    logger.info("%s v%s starting", APP_NAME, APP_VERSION)
    logger.info("Database ready at %s", db.DB_PATH)
    if predictor.is_loaded():
        logger.info("ML model loaded: %s", predictor.model_name())
    else:
        logger.warning("ML model NOT loaded (%s) - running heuristics only",
                       predictor.load_error())
    logger.info("VirusTotal: %s",
                "configured" if virustotal.is_configured() else "not configured (offline mode)")
    yield
    logger.info("Shutting down")


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Intelligent web-based phishing detection: weighted heuristics + a trained ML model.",
    lifespan=lifespan,
)

# CORS is restricted to localhost. The UI is served from the same origin, so
# this only exists to make local tooling (curl, a second dev port) work.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        f"http://{SERVER_HOST}:{SERVER_PORT}",
        f"http://localhost:{SERVER_PORT}",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """Body of POST /api/analyze."""

    # Deliberately NO min_length here. Pydantic would answer an empty string
    # with its own 422 validation blob; we want validate_url() to handle it and
    # return a friendly 400 that the UI can show verbatim in a toast.
    url: str = Field(..., max_length=2048, description="The URL to analyse.")
    check_cert: bool = Field(True, description="Perform the TLS certificate inspection.")
    check_vt: bool = Field(True, description="Query VirusTotal when a key is configured.")


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: str
    vt_configured: bool
    db_ok: bool
    version: str
    cache_entries: int
    rate_limit: int


class DeleteResponse(BaseModel):
    deleted: int
    message: str


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_url(raw: str) -> str:
    """
    Normalise and validate user input, raising HTTP 400 with a friendly message.

    Accepts 'google.com' (adds https://), rejects empty input, unsupported
    schemes such as javascript: or file:, and anything without a hostname.
    """
    candidate = (raw or "").strip()

    if not candidate:
        raise HTTPException(status_code=400, detail="Please enter a URL to analyse.")

    if len(candidate) > 2048:
        raise HTTPException(
            status_code=400,
            detail="That URL is too long (over 2048 characters).",
        )

    if any(ch in candidate for ch in ("\n", "\r", "\t", " ")):
        # Collapse internal whitespace rather than rejecting a pasted URL.
        candidate = "".join(candidate.split())
        if not candidate:
            raise HTTPException(status_code=400, detail="Please enter a URL to analyse.")

    # Catch a bad scheme BEFORE normalise_url() prepends https:// to it.
    if "://" in candidate:
        scheme = candidate.split("://", 1)[0].lower()
        if scheme not in ALLOWED_SCHEMES:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported scheme '{scheme}://'. Only http:// and https:// URLs "
                       "can be analysed.",
            )
    elif ":" in candidate.split("/", 1)[0]:
        # Things like 'javascript:alert(1)' or 'mailto:a@b.com' have a colon in
        # the first segment but no '//'.
        head = candidate.split(":", 1)[0].lower()
        if head.isalpha() and head not in ALLOWED_SCHEMES and not head.isdigit():
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported scheme '{head}:'. Only http:// and https:// URLs "
                       "can be analysed.",
            )

    normalised = normalise_url(candidate)
    parsed = parse_url(normalised)

    if not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="That does not look like a valid URL - no hostname could be found.",
        )

    # A hostname must contain a dot (a real domain) or be an IP/localhost.
    host = parsed.hostname
    if "." not in host and host not in {"localhost"} and not host.startswith("["):
        raise HTTPException(
            status_code=400,
            detail=f"'{host}' is not a valid hostname - it needs a domain suffix, "
                   "for example example.com",
        )

    if host.startswith(".") or host.endswith(".") or ".." in host:
        raise HTTPException(
            status_code=400,
            detail=f"'{host}' is not a valid hostname.",
        )

    return normalised


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------


def _page_context(request: Request, active: str) -> dict:
    return {
        "request": request,
        "active": active,
        "app_name": APP_NAME,
        "version": APP_VERSION,
        "threshold_safe": THRESHOLD_SAFE,
        "threshold_malicious": THRESHOLD_MALICIOUS,
    }


@app.get("/", include_in_schema=False)
def page_index(request: Request):
    """The analyse page."""
    return templates.TemplateResponse("index.html", _page_context(request, "analyze"))


@app.get("/history", include_in_schema=False)
def page_history(request: Request):
    """Stored scan history with search, filters and pagination."""
    return templates.TemplateResponse("history.html", _page_context(request, "history"))


@app.get("/dashboard", include_in_schema=False)
def page_dashboard(request: Request):
    """Charts and aggregate statistics."""
    return templates.TemplateResponse("dashboard.html", _page_context(request, "dashboard"))


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------


@app.post("/api/analyze")
def api_analyze(payload: AnalyzeRequest, request: Request, response: Response) -> dict:
    """
    Analyse one URL and store the result.

    Declared `def` (not `async def`) on purpose - see the module docstring.

    Order of operations matters here:
      1. RATE LIMIT first, so a flood is rejected before doing any work.
      2. VALIDATE next, so bad input never reaches the analyser.
      3. CACHE last, so a repeat of the same URL inside the TTL skips the DNS
         lookup, the TLS handshake and the VirusTotal call entirely.
    """
    client = request.client.host if request.client else "local"
    allowed, remaining, retry_after = ratelimit.check_rate_limit(client)

    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_MAX_REQUESTS)
    response.headers["X-RateLimit-Remaining"] = str(remaining)

    if not allowed:
        logger.warning("Rate limit hit by %s (retry in %ss)", client, retry_after)
        raise HTTPException(
            status_code=429,
            detail=(
                f"You are scanning too quickly - the limit is "
                f"{RATE_LIMIT_MAX_REQUESTS} scans per minute. "
                f"Please wait {retry_after} second{'' if retry_after == 1 else 's'} "
                "and try again."
            ),
            # These must ride on the exception: the `response` object above is
            # discarded once we raise, so headers set on it never reach the client.
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(RATE_LIMIT_MAX_REQUESTS),
                "X-RateLimit-Remaining": "0",
            },
        )

    url = validate_url(payload.url)

    # --- cache lookup ------------------------------------------------------
    # Only a full scan (certificate + threat intel) is cacheable; a request
    # that deliberately skipped a stage must not be served from, or written
    # to, the shared cache.
    cacheable = payload.check_cert and payload.check_vt
    if cacheable:
        cached = ratelimit.cache_get(url)
        if cached is not None:
            logger.info("Cache hit for %s (age %ss)", url, cached["cached_age"])
            response.headers["X-Cache"] = "HIT"
            return cached
    response.headers["X-Cache"] = "MISS"

    try:
        result = hybrid.analyze_url(
            url,
            check_cert=payload.check_cert,
            check_vt=payload.check_vt,
        )
    except Exception as exc:
        # analyze_url is written not to raise, so reaching here means something
        # genuinely unexpected happened. Log it and answer with a clean 500
        # instead of leaking a traceback to the browser.
        logger.exception("Analysis failed for %s", url)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed unexpectedly: {exc}",
        ) from exc

    try:
        result["id"] = db.insert_scan(result)
    except Exception:
        # A history-write failure must not lose the user's result.
        logger.exception("Could not save scan to the database")
        result["id"] = None
        result["save_error"] = "Result could not be saved to history."

    result["cached"] = False
    result["cached_age"] = 0

    # Cached AFTER the database insert, so the stored copy already carries its
    # row id - a later cache hit therefore links to the same history entry.
    if cacheable:
        ratelimit.cache_put(url, result)

    return result


@app.get("/api/history")
def api_history(
    limit: int = Query(20, ge=1, le=200, description="Rows per page."),
    offset: int = Query(0, ge=0, description="Rows to skip."),
    verdict: str | None = Query(None, description="Safe | Suspicious | Malicious | all"),
    search: str | None = Query(None, max_length=200, description="Substring match on the URL."),
) -> dict:
    """One page of scan history, newest first."""
    try:
        return db.get_scans(limit=limit, offset=offset, verdict_filter=verdict, search=search)
    except Exception as exc:
        logger.exception("History query failed")
        raise HTTPException(status_code=500, detail=f"Could not read history: {exc}") from exc


@app.delete("/api/history", response_model=DeleteResponse)
def api_clear_history() -> DeleteResponse:
    """
    Delete every stored scan.

    The in-memory scan cache MUST be dropped at the same time. A cached entry
    carries the database id of the row it created; once that row is deleted the
    id dangles, and a repeat scan inside the 5-minute TTL would be served from
    the cache and so never re-insert itself - leaving the URL missing from a
    history the user just asked to see rebuilt.
    """
    try:
        deleted = db.delete_all_scans()
        ratelimit.cache_clear()
    except Exception as exc:
        logger.exception("Clearing history failed")
        raise HTTPException(status_code=500, detail=f"Could not clear history: {exc}") from exc

    return DeleteResponse(
        deleted=deleted,
        message=f"Deleted {deleted} scan{'' if deleted == 1 else 's'}.",
    )


@app.get("/api/stats")
def api_stats(days: int = Query(14, ge=1, le=90)) -> dict:
    """Verdict counts, totals and the scans-per-day series for the dashboard."""
    try:
        return db.get_stats(days=days)
    except Exception as exc:
        logger.exception("Stats query failed")
        raise HTTPException(status_code=500, detail=f"Could not read statistics: {exc}") from exc


@app.get("/api/health", response_model=HealthResponse)
def api_health() -> HealthResponse:
    """Liveness plus which optional subsystems are actually available."""
    return HealthResponse(
        status="ok",
        model_loaded=predictor.is_loaded(),
        model_name=predictor.model_name() or "none",
        vt_configured=virustotal.is_configured(),
        db_ok=db.check_db(),
        version=APP_VERSION,
        cache_entries=ratelimit.cache_size(),
        rate_limit=RATE_LIMIT_MAX_REQUESTS,
    )


@app.get("/api/metrics")
def api_metrics() -> dict:
    """The training metrics from metrics.json, for the dashboard footer."""
    return predictor.get_metrics()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Return a consistent {"detail": "..."} shape the frontend can display.

    exc.headers must be forwarded: the 429 from the rate limiter carries a
    Retry-After header, and dropping it here would silently strip it from the
    response.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Last-resort net so an unexpected error never returns an HTML traceback."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred. Check the server log."},
    )


if __name__ == "__main__":
    # Allows `python -m app.main` as an alternative to the uvicorn command.
    import uvicorn

    uvicorn.run("app.main:app", host=SERVER_HOST, port=SERVER_PORT, reload=False)
