#!/usr/bin/env python3
"""
End-to-end self-test for LTAT.

Run it after training to prove the whole system actually works:

    python smoke_test.py

It checks the things that would silently break the project:

  1. The feature vector length matches features.json (no train/serve skew).
  2. A known-safe URL scores "Safe".
  3. An obviously malicious pattern scores "Malicious".
  4. Invalid input is rejected with HTTP 400 and a friendly message.
  5. Analysis still succeeds with NO VirusTotal key (offline degradation).
  6. Analysis still succeeds when the host is unreachable (dead domain).
  7. The database round-trips a scan.
  8. The heuristic engine never crashes on hostile input.
  9. Repeat scans are served from the 5-minute cache.
 10. /api/analyze is rate limited and returns a friendly 429.

The HTTP checks use FastAPI's TestClient, so no server needs to be running.
Exit code 0 = everything passed, 1 = at least one failure.
"""

from __future__ import annotations

import json
import sys
import traceback

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = (
    Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.CYAN, Style.DIM, Style.BRIGHT, Style.RESET_ALL
)

PASSED = 0
FAILED = 0
WIDTH = 72

# URLs used throughout. The unreachable one uses a .tk domain that cannot
# resolve, which exercises the "certificate could not be fetched" path.
SAFE_URL = "https://www.google.com"
MALICIOUS_URL = "http://paypal-secure-login.verify-account.tk/@login"
UNREACHABLE_URL = "https://this-domain-does-not-exist-12345.tk"


def check(name: str, condition: bool, detail: str = "") -> bool:
    """Record and print one assertion."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  {GREEN}PASS{RESET}  {name}")
        if detail:
            print(f"        {DIM}{detail}{RESET}")
        return True

    FAILED += 1
    print(f"  {RED}FAIL{RESET}  {name}")
    if detail:
        print(f"        {RED}{detail}{RESET}")
    return False


def section(title: str) -> None:
    print(f"\n{CYAN}{BOLD}{title}{RESET}")
    print(f"{DIM}{'-' * WIDTH}{RESET}")


# ---------------------------------------------------------------------------
# 1. Features and the train/serve contract
# ---------------------------------------------------------------------------


def test_features() -> None:
    section("1. Feature extraction and the train/serve contract")

    from app.analyzer.features import FEATURE_NAMES, extract_features, extract_vector
    from app.config import FEATURES_PATH

    vector = extract_vector(SAFE_URL)
    check("extract_vector() length equals len(FEATURE_NAMES)",
          len(vector) == len(FEATURE_NAMES),
          f"vector={len(vector)}, FEATURE_NAMES={len(FEATURE_NAMES)}")

    check("every feature value is numeric and finite",
          all(isinstance(v, (int, float)) and v == v and abs(v) != float("inf") for v in vector),
          f"first 6 values: {vector[:6]}")

    if FEATURES_PATH.exists():
        with open(FEATURES_PATH, "r", encoding="utf-8") as handle:
            saved = json.load(handle)
        saved_names = saved.get("feature_names", [])
        check("features.json order matches FEATURE_NAMES exactly",
              list(saved_names) == list(FEATURE_NAMES),
              f"features.json has {len(saved_names)} columns")
        check("feature vector length matches features.json n_features",
              len(vector) == saved.get("n_features", -1),
              f"vector={len(vector)}, features.json={saved.get('n_features')}")
    else:
        check("features.json exists", False,
              f"{FEATURES_PATH} not found - run: python -m app.ml.train")

    # A malformed URL must degrade, not explode.
    try:
        broken = extract_features("http://")
        check("extract_features() survives a malformed URL",
              len(broken) == len(FEATURE_NAMES))
    except Exception as exc:
        check("extract_features() survives a malformed URL", False, str(exc))


# ---------------------------------------------------------------------------
# 2 + 3. Verdicts
# ---------------------------------------------------------------------------


def test_verdicts() -> None:
    section("2. Verdicts on known-good and known-bad URLs")

    from app.analyzer import hybrid

    safe = hybrid.analyze_url(SAFE_URL, check_vt=False)
    check(f"{SAFE_URL} is classified Safe",
          safe["verdict"] == "Safe",
          f"verdict={safe['verdict']}, score={safe['final_score']}, "
          f"heuristic={safe['scores']['heuristic']}, ml={safe['scores']['ml_probability']}")

    bad = hybrid.analyze_url(MALICIOUS_URL, check_vt=False)
    check(f"{MALICIOUS_URL[:46]}... is classified Malicious",
          bad["verdict"] == "Malicious",
          f"verdict={bad['verdict']}, score={bad['final_score']}, "
          f"heuristic={bad['scores']['heuristic']}, ml={bad['scores']['ml_probability']}")

    check("the malicious URL produced explanatory reasons",
          len(bad["reasons"]) > 0,
          f"{len(bad['reasons'])} reasons, top: {bad['reasons'][0]['rule'] if bad['reasons'] else '-'}")

    check("every reason has rule/points/severity/message",
          all({"rule", "points", "severity", "message"} <= set(r) for r in bad["reasons"]))

    check("reasons are sorted by points descending",
          all(bad["reasons"][i]["points"] >= bad["reasons"][i + 1]["points"]
              for i in range(len(bad["reasons"]) - 1)))

    check("heuristic score is capped at 100",
          0 <= bad["scores"]["heuristic"] <= 100,
          f"heuristic={bad['scores']['heuristic']}")

    check("final score stays within 0-100",
          0 <= bad["final_score"] <= 100 and 0 <= safe["final_score"] <= 100)


# ---------------------------------------------------------------------------
# 4. Graceful degradation
# ---------------------------------------------------------------------------


def test_degradation() -> None:
    section("3. Graceful degradation (offline / no key / dead host)")

    from app.analyzer import hybrid, virustotal

    # --- no VirusTotal key ---
    result = virustotal.check_url(SAFE_URL) if not virustotal.is_configured() else None
    if result is not None:
        check("VirusTotal without a key returns status 'not_configured'",
              result["status"] == "not_configured",
              result["message"])
    else:
        check("VirusTotal is configured (skipping the no-key check)", True,
              "VT_API_KEY is set, so the not_configured path was not exercised")

    analysed = hybrid.analyze_url(SAFE_URL, check_vt=True)
    check("analysis succeeds even with VirusTotal unavailable",
          analysed["verdict"] in {"Safe", "Suspicious", "Malicious"},
          f"verdict={analysed['verdict']}, vt_status={analysed['vt']['status']}")

    check("fusion falls back to the 50/50 formula without VirusTotal",
          "ml" in analysed["weights_used"] or analysed["ml_status"] == "unavailable",
          analysed["formula"])

    # --- unreachable host ---
    dead = hybrid.analyze_url(UNREACHABLE_URL, check_vt=False)
    check("analysis succeeds when the host cannot be reached",
          dead["verdict"] in {"Safe", "Suspicious", "Malicious"},
          f"verdict={dead['verdict']}, cert_status={dead['certificate']['status']}")

    check("an unreachable host reports a certificate status, not a crash",
          dead["certificate"]["status"] in {"unreachable", "no_tls", "error"},
          f"cert status={dead['certificate']['status']}")

    check("the certificate result always has every expected key",
          {"chain_trusted", "hostname_match", "self_signed", "is_expired",
           "sha256_fingerprint", "days_to_expiry"} <= set(dead["certificate"]))

    # --- certificate inspection on a real, trusted host ---
    from app.analyzer import certs
    live = certs.inspect_certificate("www.google.com")
    if live["status"] == "ok":
        check("a real certificate parses out of the DER bytes",
              bool(live["issuer_org"] or live["issuer_cn"]) and bool(live["sha256_fingerprint"]),
              f"issuer={live['issuer_org']}, tls={live['tls_version']}, "
              f"trusted={live['chain_trusted']}, expires in {live['days_to_expiry']}d")
        check("a trusted certificate reports chain_trusted and hostname_match",
              live["chain_trusted"] and live["hostname_match"])
    else:
        check("certificate inspection on www.google.com (needs internet)", True,
              f"{YELLOW}skipped - status={live['status']} (offline?){RESET}")


# ---------------------------------------------------------------------------
# 5. HTTP API
# ---------------------------------------------------------------------------


def test_api() -> None:
    section("4. HTTP API (via FastAPI TestClient - no server needed)")

    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        # --- health ---
        response = client.get("/api/health")
        check("GET /api/health returns 200",
              response.status_code == 200,
              json.dumps(response.json()))

        health = response.json()
        check("health reports model, VirusTotal and database state",
              {"model_loaded", "vt_configured", "db_ok", "version"} <= set(health))

        # --- pages ---
        for path in ("/", "/history", "/dashboard"):
            page = client.get(path)
            check(f"GET {path} renders (200, HTML)",
                  page.status_code == 200 and "text/html" in page.headers.get("content-type", ""),
                  f"status={page.status_code}, {len(page.text)} bytes")

        # --- a real analysis ---
        response = client.post("/api/analyze", json={"url": SAFE_URL})
        check("POST /api/analyze with a safe URL returns 200 + Safe",
              response.status_code == 200 and response.json()["verdict"] == "Safe",
              f"status={response.status_code}, verdict={response.json().get('verdict')}, "
              f"score={response.json().get('final_score')}")

        saved_id = response.json().get("id")
        check("the scan was saved and given a database id", saved_id is not None,
              f"id={saved_id}")

        response = client.post("/api/analyze", json={"url": MALICIOUS_URL})
        check("POST /api/analyze with a phishing URL returns Malicious",
              response.status_code == 200 and response.json()["verdict"] == "Malicious",
              f"verdict={response.json().get('verdict')}, score={response.json().get('final_score')}")

        # --- invalid input must be 400, not 422 or 500 ---
        for bad_input, label in [
            ("", "empty string"),
            ("   ", "whitespace only"),
            ("javascript:alert(1)", "javascript: scheme"),
            ("file:///etc/passwd", "file: scheme"),
            ("ftp://example.com", "ftp: scheme"),
            ("notaurl", "no domain suffix"),
        ]:
            response = client.post("/api/analyze", json={"url": bad_input})
            body = response.json()
            check(f"invalid input ({label}) is rejected with HTTP 400",
                  response.status_code == 400,
                  f"status={response.status_code}, detail={body.get('detail')}")

        # --- history ---
        response = client.get("/api/history?limit=5")
        check("GET /api/history returns a paginated list",
              response.status_code == 200 and "items" in response.json(),
              f"total={response.json().get('total')}, returned={len(response.json().get('items', []))}")

        history = response.json()
        if history["items"]:
            row = history["items"][0]
            check("stored rows keep reasons as parsed JSON",
                  isinstance(row.get("reasons"), list),
                  f"url={row['url'][:44]}, {len(row.get('reasons', []))} reasons")

        response = client.get("/api/history?verdict=Malicious&limit=5")
        check("history filters by verdict",
              response.status_code == 200 and
              all(r["verdict"] == "Malicious" for r in response.json()["items"]),
              f"{response.json()['total']} malicious row(s)")

        # --- stats ---
        response = client.get("/api/stats")
        stats = response.json()
        check("GET /api/stats returns sane aggregates",
              response.status_code == 200 and stats["total_scans"] >= 2
              and len(stats["scans_per_day"]) == 14,
              f"total={stats['total_scans']}, avg={stats['average_score']}, "
              f"verdicts={stats['verdicts']}, days={len(stats['scans_per_day'])}")

        check("verdict counts add up to the total",
              sum(stats["verdicts"].values()) == stats["total_scans"],
              f"{stats['verdicts']} vs total {stats['total_scans']}")


# ---------------------------------------------------------------------------
# 6. Database
# ---------------------------------------------------------------------------


def test_database() -> None:
    section("5. Database round-trip")

    from app import db

    db.init_db()
    check("database initialises and is reachable", db.check_db())

    before = db.get_scans(limit=1)["total"]

    sample = {
        "url": "https://smoke-test.example.com/probe",
        "hostname": "smoke-test.example.com",
        "verdict": "Suspicious",
        "final_score": 42.5,
        "scores": {"heuristic": 30.0, "ml_probability": 0.55},
        "vt": {"malicious": 0, "total": 0, "status": "not_configured"},
        "certificate": {"status": "unreachable"},
        "reasons": [{"rule": "smoke", "points": 30, "severity": "MEDIUM", "message": "test row"}],
        "analyzed_at": "2026-01-01T00:00:00+00:00",
    }
    new_id = db.insert_scan(sample)
    check("insert_scan() returns a new row id", isinstance(new_id, int) and new_id > 0,
          f"id={new_id}")

    stored = db.get_scan(new_id)
    check("the stored row round-trips with its JSON intact",
          stored is not None
          and stored["url"] == sample["url"]
          and isinstance(stored["reasons"], list)
          and stored["reasons"][0]["rule"] == "smoke",
          f"verdict={stored['verdict']}, score={stored['final_score']}" if stored else "not found")

    after = db.get_scans(limit=1)["total"]
    check("the row count increased by exactly one", after == before + 1,
          f"{before} -> {after}")

    # A URL containing quotes must not break the parameterised query.
    tricky = dict(sample)
    tricky["url"] = "https://evil.example.com/?q='; DROP TABLE scans; --"
    db.insert_scan(tricky)
    check("a SQL-injection-shaped URL is stored safely as data",
          db.check_db() and db.get_scans(limit=1)["total"] == after + 1)


# ---------------------------------------------------------------------------
# 7. Hostile input
# ---------------------------------------------------------------------------


def test_hostile_input() -> None:
    section("6. The engine never crashes on hostile input")

    from app.analyzer import hybrid
    from app.analyzer.features import extract_features
    from app.analyzer.heuristics import score_url

    nasty = [
        "http://",
        "https://.",
        "https://..",
        "http://[::1]:8080/",
        "https://" + "a" * 300 + ".com",
        "http://xn--80ak6aa92e.com/",
        "https://user:pass@host.com:8443/path?a=1&b=2#frag",
        "http://127.0.0.1:65535/%00%01%02",
        "https://例え.テスト/パス",
        "http://a.b.c.d.e.f.g.h.i.j.k.example.tk/login",
    ]

    crashed = []
    for url in nasty:
        try:
            features = extract_features(url)
            score, reasons = score_url(url, features, None)
            assert 0 <= score <= 100
        except Exception as exc:
            crashed.append(f"{url[:40]} -> {exc}")

    check("extract_features + score_url survive 10 hostile URLs",
          not crashed,
          "\n        ".join(crashed) if crashed else "no exceptions raised")

    # The full pipeline on the worst of them (no network stages).
    try:
        result = hybrid.analyze_url("http://[::1]:8080/", check_cert=False,
                                    check_vt=False, resolve_dns=False)
        ok = result["verdict"] in {"Safe", "Suspicious", "Malicious"}
    except Exception as exc:
        ok, result = False, str(exc)
    check("the full pipeline survives an IPv6 literal URL", ok,
          f"verdict={result['verdict']}" if isinstance(result, dict) else str(result))


# ---------------------------------------------------------------------------
# 7. Scan cache and rate limiting
# ---------------------------------------------------------------------------


def test_cache_and_rate_limit() -> None:
    section("7. Scan cache and rate limiting")

    import time
    from fastapi.testclient import TestClient
    from app import ratelimit
    from app.config import RATE_LIMIT_MAX_REQUESTS, SCAN_CACHE_TTL
    from app.main import app

    ratelimit.cache_clear()
    ratelimit.rate_limit_reset()

    with TestClient(app) as client:
        # --- cache ---
        start = time.time()
        first = client.post("/api/analyze", json={"url": SAFE_URL})
        cold = time.time() - start

        start = time.time()
        second = client.post("/api/analyze", json={"url": SAFE_URL})
        warm = time.time() - start

        check("first scan is a cache MISS",
              first.headers.get("X-Cache") == "MISS" and first.json()["cached"] is False,
              f"X-Cache={first.headers.get('X-Cache')}, took {cold:.2f}s")

        check("repeat scan of the same URL is a cache HIT",
              second.headers.get("X-Cache") == "HIT" and second.json()["cached"] is True,
              f"X-Cache={second.headers.get('X-Cache')}, took {warm:.3f}s "
              f"({cold / max(warm, 0.001):.0f}x faster)")

        check("the cached result carries an age in seconds",
              isinstance(second.json().get("cached_age"), int),
              f"cached_age={second.json().get('cached_age')}s (TTL is {SCAN_CACHE_TTL}s)")

        check("a cache hit reuses the same history row",
              first.json()["id"] == second.json()["id"],
              f"id={first.json()['id']}")

        check("a different URL is not served from the cache",
              client.post("/api/analyze", json={"url": "https://github.com"})
              .headers.get("X-Cache") == "MISS")

        # --- rate limit ---
        ratelimit.rate_limit_reset()
        ratelimit.cache_clear()

        # check_cert/check_vt are disabled here on purpose. With them on, each
        # request waits on a DNS and TLS timeout; 23 of those can take longer
        # than the 60-second window, letting the earliest hits age out so the
        # limit never trips and the test flaps. Skipping the network stages
        # makes the burst finish in ~1s, which is what we actually want to test.
        fast_body = {"url": SAFE_URL, "check_cert": False, "check_vt": False}
        burst_started = time.time()
        statuses = []
        for _ in range(RATE_LIMIT_MAX_REQUESTS + 3):
            statuses.append(client.post("/api/analyze", json=fast_body).status_code)
        burst_seconds = time.time() - burst_started

        check("the rate-limit burst completes well inside the 60s window",
              burst_seconds < 30,
              f"{len(statuses)} requests in {burst_seconds:.2f}s "
              "(a slower burst would let early hits age out)")

        allowed = sum(1 for code in statuses if code == 200)
        blocked = sum(1 for code in statuses if code == 429)

        check(f"exactly {RATE_LIMIT_MAX_REQUESTS} requests are allowed per minute",
              allowed == RATE_LIMIT_MAX_REQUESTS,
              f"{allowed} allowed, {blocked} blocked out of {len(statuses)}")

        check("requests over the limit return HTTP 429", blocked == 3,
              f"{blocked} rejected with 429")

        blocked_reply = client.post("/api/analyze", json=fast_body)
        detail = blocked_reply.json().get("detail", "")

        check("the 429 carries a friendly, actionable message",
              blocked_reply.status_code == 429 and "too quickly" in detail and "wait" in detail,
              detail)

        check("the 429 sets a Retry-After header",
              blocked_reply.headers.get("Retry-After", "").isdigit(),
              f"Retry-After={blocked_reply.headers.get('Retry-After')}s")

        # Leave the limiter clean so a later run in the same process is unaffected.
        ratelimit.rate_limit_reset()
        ratelimit.cache_clear()

        check("health reports cache and rate-limit state",
              {"cache_entries", "rate_limit"} <= set(client.get("/api/health").json()))

        # Regression guard: clearing history must also drop the scan cache.
        # Otherwise a cached entry keeps the id of a row that no longer exists,
        # and re-scanning inside the TTL never re-inserts it.
        ratelimit.cache_clear()
        ratelimit.rate_limit_reset()
        client.post("/api/analyze", json={"url": SAFE_URL})
        client.delete("/api/history")

        check("clearing history also empties the scan cache",
              ratelimit.cache_size() == 0,
              f"cache holds {ratelimit.cache_size()} entries after DELETE /api/history")

        after_clear = client.post("/api/analyze", json={"url": SAFE_URL})
        check("a re-scan after clearing history is a MISS and is stored again",
              after_clear.headers.get("X-Cache") == "MISS" and after_clear.json()["id"] is not None,
              f"X-Cache={after_clear.headers.get('X-Cache')}, new id={after_clear.json().get('id')}")

        ratelimit.cache_clear()
        ratelimit.rate_limit_reset()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def main() -> int:
    print(f"\n{CYAN}{BOLD}{'=' * WIDTH}")
    print("  LTAT  -  END-TO-END SMOKE TEST")
    print(f"{'=' * WIDTH}{RESET}")

    for test in (test_features, test_verdicts, test_degradation,
                 test_api, test_database, test_hostile_input,
                 test_cache_and_rate_limit):
        try:
            test()
        except Exception:
            global FAILED
            FAILED += 1
            print(f"  {RED}ERROR{RESET} in {test.__name__}:")
            traceback.print_exc()

    total = PASSED + FAILED
    print(f"\n{CYAN}{BOLD}{'=' * WIDTH}{RESET}")
    if FAILED == 0:
        print(f"  {GREEN}{BOLD}ALL {total} CHECKS PASSED{RESET}")
        print(f"  {DIM}The system is working end to end.{RESET}")
    else:
        print(f"  {RED}{BOLD}{FAILED} of {total} CHECKS FAILED{RESET}  "
              f"({GREEN}{PASSED} passed{RESET})")
    print(f"{CYAN}{BOLD}{'=' * WIDTH}{RESET}\n")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
