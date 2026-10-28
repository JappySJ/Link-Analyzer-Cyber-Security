# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

**Link Threat Analysis Tool (LTAT)** — a final-year BTech (7th sem IT) project at Bhilai Institute
of Technology, Durg. Group 09: Vedansh Singh Rajput, Ritesh Banjare, Yeeshika Dewangan, Aisha Ansari.

A local web app that classifies a URL as **Safe / Suspicious / Malicious** by fusing three signals:
handwritten heuristic rules, a trained scikit-learn classifier, and (optionally) VirusTotal.
It is the successor to a pure-Python CLI (`LTAT.py`, 6th sem) whose logic was **refactored** into
importable modules here — not copied.

## Hard constraints (do not violate these)

These come from the project brief and are non-negotiable:

1. **Runs 100% locally.** Server binds `127.0.0.1` only (`config.SERVER_HOST`). Never bind `0.0.0.0`.
2. **No Docker, no Node, no npm, no React, no build step.** The frontend is Jinja2 + vanilla
   HTML/CSS/JS served directly. Chart.js comes from a CDN `<script>` tag; nothing is bundled.
3. **Must work fully offline** — no internet, no VirusTotal key, no DNS. Every network stage
   degrades gracefully and is clearly labelled in the UI. The analysis must **never** raise.
4. **Viva-explainable.** Every line has to be defensible by an undergraduate in an oral exam.
   Prefer the obvious implementation over the clever one. Keep the explanatory comments.
5. **No new dependencies** without a strong reason. `requirements.txt` is pinned and deliberate.
6. **Never hardcode secrets.** `VT_API_KEY` comes from `.env` via python-dotenv. `.env` is
   gitignored; `.env.example` is the committed template. The real key lives in `.env` — leave it alone.
7. **No TODOs, stubs, or placeholder functions.** Anything added must be finished and working.

## Commands

The venv lives at `.venv`. On Windows, always call the interpreter directly:

```bash
.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload   # web UI
.venv/Scripts/python.exe cli.py https://example.com                                      # CLI scan
.venv/Scripts/python.exe cli.py --help                                                   # CLI flags
.venv/Scripts/python.exe smoke_test.py                                                   # 59 checks
.venv/Scripts/python.exe -m app.ml.make_dataset                                          # regenerate dataset.csv
.venv/Scripts/python.exe -m app.ml.train                                                 # retrain -> model.pkl + metrics.json
```

`smoke_test.py` uses FastAPI's `TestClient`, so it needs **no running server**. It must exit 0 with
all checks passing before any change is considered done. CLI exit codes: `0` Safe, `1` Suspicious,
`2` Malicious.

## Architecture

```
app/config.py            Single source of truth: paths, weights, thresholds, knowledge sets
app/analyzer/
  features.py            Single source of truth for ML features + shared URL helpers
  certs.py               TLS certificate inspection (two-pass handshake)
  heuristics.py          score_url() -> (0-100, reasons[]) — the rule engine
  virustotal.py          VT API v3 client, never fatal
  predictor.py           Loads model.pkl, enforces the train/serve contract
  hybrid.py              analyze_url() — THE entry point shared by web + CLI
app/ml/                  Dataset generation, training, and artefacts
app/db.py                SQLite (stdlib sqlite3), WAL, per-request connections
app/ratelimit.py         5-min scan cache + 20/min sliding-window limiter
app/main.py              FastAPI routes only — no analysis logic
cli.py                   Terminal front-end only — no analysis logic
```

**The rule that matters most:** `hybrid.analyze_url()` is the *only* way to analyze a URL. Both the
web layer and the CLI call it. If you add analysis behaviour, it goes in the analyzer package —
never in `main.py` or `cli.py`, and never duplicated across them.

Likewise, `config.py` owns every tunable constant and `features.py` owns every feature definition.
Do not scatter magic numbers or redefine a feature locally.

## Correctness rules baked into the code

These fix real bugs in the 6th-sem original or in common Python idioms. Preserve them:

- **`ssl.getpeercert()` returns `{}` on an unverified connection.** `certs.py` does a *two-pass*
  handshake: verified first, then unverified with `getpeercert(binary_form=True)` parsed via
  `x509.load_der_x509_certificate`. Never trust the dict form alone.
- **cryptography >= 42 deprecations.** Use `getattr(cert, f"{field}_utc", None)` with a fallback to
  the naive attribute. All datetimes are timezone-aware — `datetime.now(timezone.utc)`,
  **never** `utcnow()`.
- **Route handlers are `def`, not `async def`.** They do blocking DNS / TLS / HTTP / SQLite I/O, so
  FastAPI must run them in the threadpool. Making `/api/analyze` async would stall the event loop.
- **SQLite: one connection per request** via the `db.get_connection()` contextmanager (WAL mode,
  `row_factory = sqlite3.Row`, commit/rollback/close). No module-level shared connection.
- **Windows:** UTF-8 everywhere, `pathlib` for paths, `colorama.init()` before coloured output.
- **The analysis never crashes.** Every network stage is wrapped; failures become a `status` field
  in the result (`unreachable`, `no_tls`, `not_configured`, `rate_limited`, …), not an exception.

## The ML train/serve contract

`features.json` records the exact feature order used at training time. `predictor.py` **refuses to
predict** if that order drifts from `FEATURE_NAMES` in `features.py` — this is deliberate protection
against train/serve skew, not a bug to work around.

If you change `FEATURE_NAMES`, you must regenerate the dataset **and** retrain, in that order.

Current selected model: **RandomForest** (`n_estimators=300`), chosen over LogisticRegression by
test F1. Accuracy 0.9854 · F1 0.9854 · ROC-AUC 0.9987 · CV F1 0.9887 ± 0.0061 on 2400 rows /
29 features. `train.py` prints a warning if accuracy exceeds 0.99, which usually means leakage.

### Dataset balance constants — read before touching `make_dataset.py`

The generator carries hard-won anti-leakage constants. Three separate leaks were found and fixed by
tuning them; removing any one makes the model look great and behave badly:

| Constant | Guards against |
|---|---|
| `PHISH_TLD_NORMAL_SHARE = 0.50` | TLD alone separating the classes (produced a fake 0.9958) |
| `BENIGN_BARE_DOMAIN_SHARE = 0.32` | `google.com` scoring 0.93 phishing — bare domains were mostly phishing |
| `BENIGN_WWW_SHARE = 0.28` | `www.` acting as a phishing signal |
| DGA digit rate `0.08` | Digits in the host being a giveaway |
| `HARD_FRACTION = 0.15` | Having no near-boundary examples |

`is_exact_brand_domain` and `is_typosquat` (Levenshtein-based) exist because **no other feature can
separate `google.com` from `goggle.com`**. `BRAND_SAFE_LABELS` whitelists real domains that are
coincidentally close to a brand (spotify/shopify, icicibank/citibank). Verified: 0 false positives
across 207 real domains.

## Scoring

Heuristic (0–100, 34 weighted rules in `config.WEIGHTS`) and ML probability are fused:

- With VirusTotal: `0.35 heuristic + 0.40 ml + 0.25 vt`
- Without: `0.50 heuristic + 0.50 ml`

Verdict bands: `< 30` Safe · `30–60` Suspicious · `> 60` Malicious.

Only the heuristic engine reads certificate evidence — the ML model never does, because the dataset
is synthetic and has no certificates to learn from. This asymmetry is intentional and documented in
README §6.2.

## Known intentional oddities (not bugs — don't "fix" them)

- **VirusTotal is hidden from the UI and CLI but still runs in the backend** and still contributes
  its 25% to the score. The user asked for this. Consequence: the two *visible* sub-scores don't sum
  to the final score. Documented in README §4.
- **`APP_VERSION` is `"2.0.0"` while `APP_NAME` is `"Link Threat Analysis Tool"`** (no "2.0"). The
  product was rebranded to drop the "2.0" from the *name only*; the version string is correct, and
  the folder is still `ltat2/`.
- **`[hidden] { display: none !important; }`** in the CSS. Without `!important` the modal's
  `display: grid` beats the UA stylesheet and the confirm dialog shows on page load.
- **The rate-limit smoke check passes `check_cert: false, check_vt: false`.** With network stages on,
  DNS timeouts pushed the 23-request burst past the 60s window and early hits aged out, making the
  test flaky. Keep it network-free.

## Frontend conventions

- **Contrast is measured, not eyeballed.** The palette meets WCAG 2.1 AA: `--text` 15.11:1,
  `--text-muted` 8.10:1, `--text-dim` 5.65:1, `--malicious` `#F26565` 4.85:1 on its soft background.
  Any new colour must clear 4.5:1 (or 3:1 for large text) against the surface it sits on.
- **Media queries must stay in descending order: 860 → 768 → 720 → 480 → 400.** They are a plain
  `max-width` cascade; a smaller breakpoint placed above a larger one gets silently overridden.
- **Long URLs are hostile input in the layout too.** `.meta-val` clamps to 3 lines with the full
  value in `title`. Verify `scrollWidth === clientWidth` at 380 / 768 / 1440 after layout changes.
- Interactive elements need both `:hover` and `:active` states, and `prefers-reduced-motion` is honoured.
- `/` focuses the URL input (or history search); Escape blurs. Guarded so it never hijacks typing.

## Cache and history consistency

`ratelimit.cache_get/put` serve repeat scans of the same URL for 5 minutes and reuse the original
history row id. **`DELETE /api/history` must also call `ratelimit.cache_clear()`** — otherwise cached
results keep returning ids of deleted rows and those scans never get re-inserted. There is a
regression check for this in smoke test section 7.

`/api/analyze` only caches when `check_cert` **and** `check_vt` are both true, so a reduced-scope
scan can never poison a full one.

## Docs

`README.md` (13 sections) is the submission document — keep it in sync when behaviour changes,
especially §6.3 metrics, §7.1 cache/rate limiting, and the §12 decisions table. README §11 still
lists 15 screenshot placeholders that need real captures before submission.
