# Link Threat Analysis Tool

### An Intelligent Web-Based Phishing Detection System

**Group 09 — Bhilai Institute of Technology, Durg**
Department of Information Technology · 7th Semester Major Project

| Team member |
|---|
| Vedansh Singh Rajput |
| Ritesh Banjare |
| Yeeshika Dewangan |
| Aisha Ansari |

---

## 1. What it does

LTAT takes a URL and answers one question — **is this link safe to open?** — with a
score from 0 to 100, a verdict, and a plain-English list of reasons.

It does this by asking three *independent* judges and combining their opinions:

| Signal | What it knows | Works offline? |
|---|---|---|
| **Heuristic rules** | 34 weighted patterns: brand spoofing, high-risk TLDs, `@` tricks, punycode, entropy, TLS certificate problems | Yes |
| **Machine learning** | A RandomForest trained on 29 numeric URL features over 2,400 labelled URLs | Yes |
| **VirusTotal** | Verdicts from ~70 real security vendors | No (needs internet + a free key) |

Why three? Because each one fails differently. The rules miss an attack pattern nobody
wrote a rule for. The model is only as good as its training data. VirusTotal knows
nothing about a domain registered ten minutes ago. Averaging them means **one blind spot
does not decide the outcome**.

This is version 2.0 of a project that began last year as a pure-Python CLI (`LTAT.py`).
Version 1 had heuristics only. Version 2 adds the trained model, the web interface, the
hybrid verdict and persistent scan history — and all of the original heuristic logic has
been **refactored into importable modules**, not copied.

### What is new in 2.0

| | v1.0 (6th sem) | v2.0 (7th sem) |
|---|---|---|
| Interface | CLI only | Web UI + CLI (both share one engine) |
| ML | none (or an untrained stub) | Trained RandomForest, reproducible dataset, honest metrics |
| Verdict | heuristic score | Hybrid fusion of 3 signals with a confidence margin |
| History | none | SQLite database + searchable history + dashboard |
| Structure | one 1,600-line file | 10 focused modules, single source of truth per concern |
| Certificates | **buggy** (see §8) | Two-pass handshake, DER parsed with `cryptography` |

---

## 2. Architecture

```
                        ┌──────────────────────────────────┐
                        │   Browser  (localhost:8000)      │
                        │  index / history / dashboard     │
                        │  vanilla HTML + CSS + JS         │
                        └────────────────┬─────────────────┘
                                         │  JSON over HTTP
                        ┌────────────────▼─────────────────┐
                        │  FastAPI  (app/main.py)          │
                        │  POST /api/analyze   GET /api/*  │
                        └────────────────┬─────────────────┘
                                         │
                        ┌────────────────▼─────────────────┐
                        │  hybrid.analyze_url()            │
                        │  the ONE entry point             │
                        └───┬──────────┬──────────┬────────┘
                            │          │          │
             ┌──────────────▼──┐  ┌────▼──────┐  ┌▼──────────────┐
             │ heuristics.py   │  │predictor  │  │ virustotal.py │
             │ weighted rules  │  │ model.pkl │  │  API v3       │
             │      ▲          │  │     ▲     │  │  (optional)   │
             │      │          │  │     │     │  └───────────────┘
             │  ┌───┴─────┐    │  │  ┌──┴────────────┐
             │  │certs.py │    │  │  │ features.py   │
             │  │TLS/PKI  │    │  │  │ 29 features   │◄── ALSO used by
             │  └─────────┘    │  │  └───────────────┘    ml/train.py
             └─────────────────┘  └───────────┘
                            │
                        ┌───▼──────────────────────────────┐
                        │  db.py  →  data/ltat.db (SQLite) │
                        └──────────────────────────────────┘

                 cli.py  ──────────────► hybrid.analyze_url()
                 (same engine, terminal output only)
```

**The key structural idea:** `features.py` is the *only* place feature extraction is
written, and `hybrid.analyze_url()` is the *only* place a verdict is produced. Training,
serving, the web API and the CLI all call into those same functions, so they can never
drift apart.

### File map

```
ltat2/
├── app/
│   ├── config.py             every path, weight and threshold — ONE file
│   ├── db.py                 SQLite schema + helpers (WAL, per-request connections)
│   ├── ratelimit.py          5-minute scan cache + sliding-window rate limiter
│   ├── main.py               FastAPI app, all routes, input validation
│   ├── analyzer/
│   │   ├── features.py       29 URL-string features  ← single source of truth
│   │   ├── certs.py          TLS two-pass handshake + X.509 parsing
│   │   ├── heuristics.py     weighted rules → (score, reasons)
│   │   ├── virustotal.py     API v3 client, cached, never fatal
│   │   ├── predictor.py      loads model.pkl, guards against train/serve skew
│   │   └── hybrid.py         fuses the three signals into the final verdict
│   ├── ml/
│   │   ├── make_dataset.py   generates dataset.csv
│   │   ├── train.py          trains + compares LogReg vs RandomForest
│   │   ├── dataset.csv       2,400 rows (generated)
│   │   ├── model.pkl         trained model (generated)
│   │   ├── features.json     the feature-order contract (generated)
│   │   └── metrics.json      all metrics, for the report (generated)
│   ├── templates/            base / index / history / dashboard
│   └── static/               css/style.css, js/{app,history,dashboard}.js
├── cli.py                    the v1 terminal experience, on the v2 engine
├── smoke_test.py             59-check end-to-end self-test
├── requirements.txt
├── .env.example              copy to .env and add your VirusTotal key
└── data/ltat.db              created on first run
```

---

## 3. Setup

Requires **Python 3.10 or newer**. Nothing else — no Docker, no Node, no npm, no build step.

### Windows (PowerShell or CMD)

```bat
cd ltat2

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt

copy .env.example .env

python -m app.ml.make_dataset
python -m app.ml.train
python smoke_test.py

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Linux / macOS

```bash
cd ltat2

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env

python -m app.ml.make_dataset
python -m app.ml.train
python smoke_test.py

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then open **<http://127.0.0.1:8000>**. Stop the server with `Ctrl+C`.

> The server binds to `127.0.0.1` only. It is a local analysis tool and is deliberately
> not reachable from anywhere else on the network.

### Command-line usage

```bash
python cli.py https://example.com                  # full report
python cli.py https://example.com --json           # machine-readable
python cli.py --batch urls.txt -o report.json      # scan a file of URLs
python cli.py https://example.com --no-cert -q     # fast, offline, one line
```

`cli.py` exits with code **2** when anything scored Malicious, so it can be used in a script.

---

## 4. VirusTotal (optional)

Everything works without this. Skip it and the tool runs in offline mode.

> **Note on the interface.** VirusTotal is deliberately **not shown** in the web UI or
> the CLI report. It still runs on every scan and still contributes its 25% share to the
> final score — the numbers are simply not displayed. They remain available in the API
> response (`vt` object), in `cli.py --json`, and in the `vt_malicious` / `vt_total` /
> `vt_status` columns of the database. One consequence worth knowing for the viva: the
> two visible sub-scores will not always add up to the final score, because the hidden
> third term is still in the average.

1. Sign up free at <https://www.virustotal.com/gui/join-us>
2. Click your avatar (top right) → **API key**
3. Copy the 64-character key
4. Open `.env` and set it:

```ini
VT_API_KEY=paste_your_key_here
```

5. Restart the server. The header pill will change from `VT off` to `VT on`.

**Free-tier limits: 4 requests/minute, 500/day.** LTAT protects that quota by caching
every successful lookup in memory for 10 minutes. If you hit the limit the UI shows a
clear "rate limited" state and the score simply re-weights itself — a VirusTotal failure
can never block or fail a scan.

`.env` is listed in `.gitignore`, so the key is never committed.

---

## 5. How the hybrid score works (plain English)

Each engine produces a number from 0 (clean) to 100 (definitely phishing):

- **Heuristic score** — add up the points of every rule that fired, cap at 100.
- **ML score** — the model's phishing probability × 100.
- **VirusTotal score** — `(malicious + 0.5 × suspicious) ÷ total_engines × 100`.
  Suspicious counts half because engines use that category for "probably unwanted"
  rather than "confirmed phishing".

They are then blended by a weighted average. The weights live in `config.py`:

```
VirusTotal available:   final = 0.35 × heuristic + 0.40 × ML + 0.25 × VirusTotal
VirusTotal unavailable: final = 0.50 × heuristic + 0.50 × ML
No trained model:       final = heuristic                    (ml_status = "unavailable")
```

The ML model carries the largest single weight when all three are present, because it
generalises across patterns; the heuristics are close behind because they are the part
that can *explain itself*; VirusTotal gets the smallest share because it is often blind
to brand-new URLs.

The verdict bands:

| Final score | Verdict |
|---|---|
| below 30 | **Safe** |
| 30 – 60 | **Suspicious** |
| above 60 | **Malicious** |

**Confidence** is *not* a probability — it is the **margin**, i.e. how far the score sits
from the nearest band boundary, normalised to 0–100. A score of 5 is deep inside Safe and
reports high confidence. A score of 29 is one point from flipping to Suspicious and
reports low confidence. It answers "how close was this call?", which is the honest thing
to show a user.

*Worked example — `http://paypal-secure-login.verify-account.tk/@login`*

```
Heuristic  100  (@ symbol +25, brand in subdomain +20, 4 keywords +20,
                 .tk TLD +18, plain HTTP +10, entropy +10  → capped at 100)
ML         100  (RandomForest probability 1.00)
VirusTotal  --  (no key configured)

final = 0.50 × 100 + 0.50 × 100 = 100.0  →  MALICIOUS  (confidence 100%)
```

---

## 6. Machine learning

### 6.1 The dataset

`app/ml/dataset.csv` — **2,400 rows, 1,200 benign / 1,200 phishing (perfectly balanced)**.

> **Stated plainly:** this dataset is **programmatically generated from real-world
> phishing patterns**, not scraped from a live PhishTank feed. That is a deliberate
> trade-off. It makes the project **fully reproducible offline** — anyone marking this
> can regenerate the identical file with one command and no internet, and it can never go
> stale or 404. The cost is that the model learns the patterns encoded in the generator,
> so it will not recognise a novel trick that no pattern represents. The metrics in §6.3
> should be read as "how well the model learned these patterns", **not** as a claim about
> live phishing traffic.

**To train on real data instead**, drop in any CSV with `url,label` columns
(`label`: 0 = benign, 1 = phishing) and run:

```bash
python -m app.ml.train --csv path/to/phishtank.csv
```

No code changes are needed — the feature pipeline is identical either way.

**Benign rows** are built from 180+ genuinely popular domains (google.com, github.com,
wikipedia.org, sbi.co.in, irctc.co.in, amazon.in, uidai.gov.in, bitdurg.ac.in …) combined
with realistic paths and query strings.

**Phishing rows** are synthesised from twelve real attack patterns: brand-in-subdomain
(`paypal.secure-login.xyz`), brand-in-path, typosquats (`arnazon`, `faceb00k`, `g00gle`,
`micros0ft`), IP-as-host, high-risk TLDs, DGA-style random hosts, punycode (`xn--`),
`@`-symbol tricks, heavy percent-encoding, credential keywords, shortener look-alikes and
deep subdomain nesting.

#### Why the dataset is deliberately *hard*

A naive generator makes benign URLs short and clean and phishing URLs long and ugly. A
single length threshold then scores 99% and the model has learned nothing. Three
deliberate design decisions prevent that, and each one was added after seeing the model
fail without it:

1. **~15% hard rows on both sides.** Hard benign = real bank and government URLs
   containing `login` / `secure` / `verify` (83 such rows). Hard phishing = short, clean,
   `https` typosquats with no keywords at all (415 rows under 40 characters).
   Mean URL length ends up **58.8 (benign) vs 56.9 (phishing)** — length alone is useless.
2. **Only ~41% of phishing uses a high-risk TLD.** In reality most phishing sits on
   ordinary `.com` domains. Drawing every phishing row from `.tk`/`.xyz` would have made
   "`.tk` means phishing" a perfect rule that does not exist in the real world.
3. **Benign homepages and `www.` are well represented.** Because the hard-phishing rows
   are short path-less URLs, an early version of this dataset taught the model that
   *any* bare domain was phishing — it scored `https://www.google.com` at **0.93**.
   Balancing bare-domain and `www.` URLs across both classes fixed it.

### 6.2 The features — and why certificates are NOT among them

`features.py` extracts **29 numeric features from the URL string alone**:

```
url_length, hostname_length, path_length, query_length, num_dots, num_hyphens,
num_digits_host, digit_ratio_host, num_special_chars, num_subdomains, path_depth,
has_ip_host, has_at_symbol, has_double_slash_path, is_https, is_shortener,
high_risk_tld, tld_length, domain_entropy, url_entropy, brand_impersonation,
suspicious_keyword_count, has_punycode, has_non_ascii, num_percent_encodings,
has_explicit_port, longest_token_len_host, is_exact_brand_domain, is_typosquat
```

> ### Why no certificate features in the ML model — the design justification
>
> This is the most important design decision in the project, and it is a deliberate
> trade-off rather than an omission.
>
> **The problem.** Most URLs in any phishing dataset point at domains that were taken
> down long ago. You cannot open a TLS connection to a dead domain, so a certificate
> simply cannot be fetched for the majority of training rows.
>
> **Why including them anyway would be worse than useless.** You would face three bad
> options: (a) drop every row without a certificate — which throws away most of the
> phishing class and biases what remains towards *still-live* sites; (b) impute a
> placeholder — which teaches the model that "no certificate" is a label artefact rather
> than a security signal; or (c) fetch certificates at training time — thousands of
> network timeouts, hours of runtime, and results that change every time you retrain.
>
> Worse, it would create **train/serve skew**: the model would be trained on rows where a
> certificate was available, but at prediction time it must handle URLs where the fetch
> times out. The same URL could score differently depending on whether the network
> happened to respond.
>
> **The decision.** The ML model sees **URL-string features only** — instant, fully
> offline, and identical at training and serving time. Certificate evidence is not
> discarded; it feeds the **heuristic** score instead, through eleven dedicated rules
> (expired, self-signed, untrusted chain, hostname mismatch, short lifetime, free CA,
> weak TLS version, weak cipher …).
>
> **Why this is defensible.** The heuristic layer is exactly where certificate evidence
> belongs. PKI failures are *deterministic facts*, not statistical patterns — an expired
> certificate is objectively wrong, and it needs no training data to interpret. Putting
> it in a rule also means the tool can **explain** it ("Self-signed certificate — no CA
> vouches for this site"), which a probability from a forest never could.
>
> **The cost, stated honestly.** The model cannot learn *interactions* between certificate
> state and URL shape — for example "a Let's Encrypt certificate issued 2 hours ago on a
> `.tk` domain". The hybrid layer only adds those signals together; it cannot multiply
> them. Capturing that would require a live-fetched dataset, which is future work.

Two of the 29 features (`is_exact_brand_domain`, `is_typosquat`) were added beyond the
original specification for a concrete reason: **nothing else in the list can tell
`google.com` from `goggle.com`.** They have near-identical length, entropy and character
mix; the difference is dictionary knowledge. These features use Levenshtein edit distance
to the nearest known brand — distance 0 means it *is* the brand (a benign signal, since
only the real owner can hold that name), distance 1–2 means a near-miss typosquat. Short
brands (under 5 characters) are excluded from fuzzy matching, and real companies whose
names legitimately sit close to another brand (`spotify` ↔ `shopify`,
`icicibank` ↔ `citibank`) are exempted in `config.BRAND_SAFE_LABELS`. Measured across
207 real domains this gives **zero false positives** while catching 53 of 62 typosquats.

Adding these two features moved `https://www.google.com` from a 0.93 phishing probability
to **0.02**.

### 6.3 Results

Stratified 80/20 split (1,920 train / 480 test), `random_state=42`, plus 5-fold
stratified cross-validation on the full dataset.

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | CV F1 (5-fold) |
|---|---|---|---|---|---|---|
| LogisticRegression (scaled) | 0.9750 | 0.9831 | 0.9667 | 0.9748 | 0.9950 | 0.9840 ± 0.0087 |
| **RandomForest (300 trees)** ← selected | **0.9854** | **0.9874** | **0.9833** | **0.9854** | **0.9987** | **0.9887 ± 0.0061** |

**Confusion matrices (480 test URLs)**

| RandomForest | predicted benign | predicted phishing |
|---|---|---|
| **actual benign** | 237 | 3 ← false alarms |
| **actual phishing** | 4 ← missed attacks | 236 |

| LogisticRegression | predicted benign | predicted phishing |
|---|---|---|
| **actual benign** | 236 | 4 |
| **actual phishing** | 8 | 232 |

RandomForest is selected automatically by the higher test F1.

**Top 10 features by RandomForest importance**

| # | Feature | Importance |
|---|---|---|
| 1 | high_risk_tld | 0.1379 |
| 2 | suspicious_keyword_count | 0.1272 |
| 3 | brand_impersonation | 0.1030 |
| 4 | digit_ratio_host | 0.0887 |
| 5 | num_digits_host | 0.0856 |
| 6 | is_https | 0.0744 |
| 7 | is_typosquat | 0.0666 |
| 8 | query_length | 0.0511 |
| 9 | domain_entropy | 0.0383 |
| 10 | num_special_chars | 0.0351 |

**Top LogisticRegression coefficients** (positive pushes towards phishing)

| Feature | Coefficient | Direction |
|---|---|---|
| high_risk_tld | +3.146 | → phishing |
| digit_ratio_host | +3.041 | → phishing |
| num_digits_host | +2.642 | → phishing |
| is_typosquat | +2.052 | → phishing |
| brand_impersonation | +2.009 | → phishing |
| num_percent_encodings | +1.973 | → phishing |
| domain_entropy | +1.538 | → phishing |
| path_length | −1.388 | → benign |

Note that no single feature dominates — importance is spread across TLD reputation,
lexical content, brand similarity and host composition. That is the sign of a model that
is combining evidence rather than exploiting one shortcut.

> **On honesty:** `train.py` prints an explicit warning and records it in `metrics.json`
> if test accuracy exceeds 0.99, because on a synthetic dataset that indicates the data is
> too separable rather than that the model is excellent. At 0.9854 the warning does not
> fire — but 98.5% on *generated* data would still not survive contact with live phishing
> traffic. Expect meaningfully lower numbers on a real PhishTank corpus.

---

## 7. The database

One table, created automatically on first run, in `data/ltat.db`:

```sql
CREATE TABLE scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    hostname        TEXT,
    verdict         TEXT    NOT NULL,
    final_score     REAL    NOT NULL,
    heuristic_score REAL,
    ml_probability  REAL,
    vt_malicious    INTEGER,
    vt_total        INTEGER,
    vt_status       TEXT,
    cert_status     TEXT,
    reasons         TEXT,      -- JSON
    cert_info       TEXT,      -- JSON
    created_at      TEXT    NOT NULL   -- ISO-8601 UTC
);
CREATE INDEX idx_scans_created_at ON scans (created_at);
CREATE INDEX idx_scans_verdict    ON scans (verdict);
```

`reasons` and `cert_info` are stored as JSON text so the history page can re-render an old
scan in full without re-analysing the URL.

**Threading note:** FastAPI runs the blocking route handlers in a threadpool, and a
`sqlite3` connection cannot be shared across threads. Every operation therefore opens its
own short-lived connection through a context manager (`db.get_connection()`) which enables
WAL mode, sets `row_factory = sqlite3.Row`, commits on success, rolls back on exception and
always closes.

---

### 7.1 Scan cache and rate limiting

Both live in `app/ratelimit.py`, in process memory only — no Redis, no extra dependency,
and the state resets cleanly when the server restarts. That is the right trade-off for a
single-user local tool.

**Cache — 5 minutes, keyed by normalised URL.** A scan costs a DNS lookup, a TLS
handshake and possibly an HTTPS round trip to VirusTotal. Re-scanning the same URL twice
in a minute should not pay that cost again, and on the free VirusTotal tier
(4 requests/minute) repeating it can actually get you throttled by them. Measured effect:

```
first scan   0.16s   X-Cache: MISS
repeat scan  0.001s  X-Cache: HIT     ~158x faster
```

A cache hit reuses the original history row rather than inserting a duplicate, and the
report card shows a small `cached Ns ago` badge so the instant result is never mysterious.
Only a **full** scan is cacheable — a request that skipped the certificate or threat-intel
stage is neither served from nor written to the cache, so the two can never be confused.
The cache is capped at 256 entries and evicts oldest-first.

**Rate limit — 20 requests per minute, sliding window.** A runaway script or a stuck
Analyze button could otherwise exhaust the VirusTotal daily quota (500/day) and flood the
history table. A *sliding* window is used rather than a fixed bucket, because a fixed
bucket lets 2x the limit through when requests straddle a bucket boundary.

Over the limit the API returns **HTTP 429** with a friendly, actionable message — never a
raw error:

> You are scanning too quickly - the limit is 20 scans per minute. Please wait 43 seconds
> and try again.

plus a `Retry-After` header. The UI renders it as a dismissible toast, not an `alert()`.

---

## 8. Bugs from version 1 that this version fixes

These were real defects in last year's `LTAT.py`, and fixing them properly is a
substantial part of the 2.0 work.

**1. `ssl.getpeercert()` returns an empty dict under `CERT_NONE`.**
The old code read certificate fields from the dict returned by `getpeercert()`. That dict
is **empty** whenever the socket was wrapped with `verify_mode = CERT_NONE` — which is
exactly the case for self-signed and expired certificates, i.e. the ones that matter most.
The tool therefore reported nothing precisely when there was something to report.
*Fix:* always take the certificate as raw DER via `getpeercert(binary_form=True)` and parse
it with `cryptography.x509.load_der_x509_certificate()`, which does not care whether
verification succeeded.

**2. No two-pass handshake.**
*Fix:* `certs.py` now does a strict verifying handshake first — success proves both that
the chain reaches a trusted root *and* that the hostname matches. Only if that fails does
it reconnect with `check_hostname=False, CERT_NONE` purely to **read** the offered
certificate, recording *why* the strict pass failed. The result reports `chain_trusted`
and `hostname_match` separately, plus the failure reason.

**3. Deprecated and timezone-naive datetimes.**
`cryptography` ≥ 42 deprecates `not_valid_after` in favour of `not_valid_after_utc`.
*Fix:* `getattr()` picks the new name when present and falls back on older releases; every
datetime is timezone-aware (`datetime.now(timezone.utc)`); `datetime.utcnow()` is not used
anywhere in the project.

**4. A hard-coded API key in the source.**
v1 had a 64-character hex string sitting in a module-level constant (assigned, confusingly,
to a variable named `VT_API_BASE`). *Fix:* the key is read from `.env` via `python-dotenv`,
`.env` is git-ignored, and `.env.example` ships in its place.

**5. Blocking I/O on the event loop** *(new in 2.0, avoided by design).*
`/api/analyze` performs a TLS handshake, a DNS lookup and possibly an HTTPS call. It is
declared as a plain `def`, **not** `async def`, so FastAPI runs it in a worker threadpool
instead of freezing the single event loop for the duration of the scan.

---

## 9. Verification

`python smoke_test.py` runs **59 checks** and exits non-zero on any failure:

```
1. Feature extraction and the train/serve contract   — vector length matches features.json
2. Verdicts on known-good and known-bad URLs         — google.com Safe, phishing URL Malicious
3. Graceful degradation                              — no VT key, dead host, real cert parsing
4. HTTP API                                          — all pages 200, invalid input → 400
5. Database round-trip                               — insert, read back, SQL-injection-shaped URL
6. Hostile input                                     — 10 malformed URLs, IPv6 literals
7. Scan cache and rate limiting                      — cache HIT/MISS, 20/min cap, friendly 429
```

Observed behaviour on this machine:

| URL | Verdict | Score | Heuristic | ML |
|---|---|---|---|---|
| `https://www.google.com` | Safe | 1.0 | 0 | 0.02 |
| `https://github.com` | Safe | 0.0 | 0 | 0.00 |
| `https://sbi.co.in/personal-banking/login` | Safe | 27.5 | 36 | 0.19 |
| `https://this-domain-does-not-exist-12345.tk` | Malicious | 66.7 | 38 | 0.95 |
| `http://185.23.44.9/paypal/verify/index.php` | Malicious | 78.8 | 63 | 1.00 |
| `http://paypal-secure-login.verify-account.tk/@login` | Malicious | 100.0 | 100 | 1.00 |

### 9.1 Accessibility — measured, not assumed

Every colour token was checked against **WCAG 2.1 AA** (4.5:1 for normal text, 3:1 for
large text) on all four surface colours, and then re-measured in a real browser across
all three pages:

```
244 rendered text nodes measured   →   0 failures
```

The audit found and fixed 12 genuine failures in the original palette:

| Token | Before | Contrast | After | Contrast |
|---|---|---|---|---|
| `--text-dim` (labels, captions) | `#5C6878` | 3.15:1 ✗ | `#8792A1` | **5.65:1** ✓ |
| `--text-muted` (secondary text) | `#8A97A8` | 6.00:1 ✓ | `#A4B0C0` | **8.10:1** ✓ |
| `--malicious` (small pills) | `#EF4444` | 4.15:1 ✗ | `#F26565` | **4.85:1** ✓ |

`--text-muted` was brightened even though it already passed, so the three-step type
ramp (15.11 / 8.10 / 5.65) stays visually distinct after `--text-dim` moved up.

Two elements are flagged by automated scanners but are **not** real failures: the hero
heading and the Analyze button both use gradient fills, which report a transparent
computed background. Measured against their actual gradient stops they score 6.29:1 to
10.70:1.

### 9.2 Responsive layout

Checked at **380px, 768px and 1440px** on all three pages, including a deliberately
hostile 248-character URL:

```
scrollWidth === clientWidth at every width   →   no horizontal page scroll anywhere
```

Wide content (the history table) scrolls inside its own `overflow-x: auto` container
rather than widening the page. Long hostnames are clamped to three lines with the full
value on hover, so one 118-character host cannot stretch the metadata row.

---

## 10. Known limitations

Stated honestly — these are the things to be ready to discuss.

1. **The dataset is synthetic.** See §6.1. The 98.5% accuracy measures pattern learning on
   generated data, not performance on live phishing. Use `--csv` with a real corpus for a
   trustworthy number.
2. **The model cannot use certificate evidence.** See §6.2. Interactions between PKI state
   and URL shape are invisible to it; the hybrid layer only sums the two signals.
3. **Registrable domain is approximated as the last two labels.** A proper implementation
   would consult the Public Suffix List, so multi-part suffixes like `co.in` or `ac.uk` are
   handled imperfectly (`sbi.co.in` is treated as domain `co.in`). This mainly affects
   subdomain counting and entropy on such hosts.
4. **The brand list is finite and hand-written.** A brand not in `config.IMPERSONATED_BRANDS`
   cannot be detected as impersonated or typosquatted.
5. **No page-content analysis.** LTAT never fetches the page body, so it cannot see a cloned
   login form, obfuscated JavaScript or a redirect chain. It judges the URL and its TLS
   certificate only.
6. **URL shorteners are not expanded.** A `bit.ly` link is flagged as *hiding* its
   destination, but the destination itself is never resolved.
7. **Single-user, no authentication.** The history database is shared by anyone who can
   reach the port; the server binds to `127.0.0.1` for exactly this reason.
8. **VirusTotal free tier is slow and limited.** 4 requests/minute means a brand-new URL
   can take up to ~12 seconds while its analysis is polled.
9. **Heuristic weights are hand-tuned, not learned.** They come from the v1 tool and
   domain reading, not from optimisation against a labelled set.

### Possible future work

- Train on a live PhishTank / OpenPhish corpus and publish the honest gap
- Expand shortener destinations before scoring
- Add a WHOIS domain-age signal (very strong in practice — most phishing domains are days old)
- Fetch and analyse page content and redirect chains
- Learn the heuristic weights instead of hand-tuning them

---

## 11. Screenshots

> **Placeholders — replace with your own captures before submitting.**
> Create the folder `docs/screenshots/` next to this README and save the files with the
> exact names below, and the table will render them in your report.
>
> To get good captures: start the server, scan 8–10 URLs (use the example chips plus a
> couple of safe sites) so the dashboard charts and history table have real data, then
> capture at a **1440px** browser width unless the row says otherwise.

| # | Screen | What to capture | File |
|---|---|---|---|
| 1 | Home page | Hero, pill search bar with the `/` hint, example chips | `docs/screenshots/01-home.png` |
| 2 | Loading state | Skeleton card mid-scan + the cyan nav bar at the top | `docs/screenshots/02-loading.png` |
| 3 | **Malicious** result | Red gauge, both sub-score cards, 6–7 reasons | `docs/screenshots/03-result-malicious.png` |
| 4 | **Safe** result | Green gauge on `https://www.google.com` | `docs/screenshots/04-result-safe.png` |
| 5 | Certificate table | Issuer, validity, TLS version, SHA-256 with copy button | `docs/screenshots/05-certificate.png` |
| 6 | "Why this verdict" | Expanded reasons list with severity dots and points chips | `docs/screenshots/06-reasons.png` |
| 7 | Cached badge | Re-scan the same URL — the `cached Ns ago` pill appears | `docs/screenshots/07-cached.png` |
| 8 | Rate limit | Click Analyze rapidly until the friendly 429 toast shows | `docs/screenshots/08-rate-limit.png` |
| 9 | History | Filter tabs with counts, search box, one expanded row | `docs/screenshots/09-history.png` |
| 10 | Dashboard | 4 stat tiles, doughnut + line charts, model info panel | `docs/screenshots/10-dashboard.png` |
| 11 | CLI report | Full terminal output of `python cli.py <phishing-url>` | `docs/screenshots/11-cli.png` |
| 12 | Training run | `python -m app.ml.train` — the model comparison table | `docs/screenshots/12-training.png` |
| 13 | Smoke test | All **59 checks passing** | `docs/screenshots/13-smoke-test.png` |
| 14 | Mobile — 380px | Home + result card stacked (use DevTools device toolbar) | `docs/screenshots/14-mobile-380.png` |
| 15 | Tablet — 768px | Dashboard with charts stacked | `docs/screenshots/15-tablet-768.png` |

---

## 12. Decisions made while building (and why)

Recorded here because the brief asked for them to be stated rather than asked about.

| Decision | Reasoning |
|---|---|
| **Virtual environment (`.venv`) inside the project** | Keeps the four ML/web dependencies off the system Python. Standard practice and easy to delete. |
| **RandomForest allowed to win over LogisticRegression** | Selection is automatic by test F1. RF won (0.9854 vs 0.9748). LogReg is still trained and reported every run because its coefficients are far easier to explain in a viva. |
| **2,400 dataset rows** | Above the 2,000 minimum, still trains in ~10 seconds so it can be re-run live during a demo. |
| **29 features instead of the 27 specified** | The brief said "at least these". The two extra typosquat features fixed a real misclassification — see §6.2. |
| **Verdict thresholds 30 / 60** | As specified. Note these differ from v1's 25/50/75 four-band scheme; three bands map more cleanly onto a UI. |
| **Confidence = distance from the boundary** | As specified, and honest: it reports decision margin, not a calibrated probability. |
| **Chart.js from CDN** | The only external asset. If there is no internet the dashboard detects the missing library and shows a clean message instead of a broken canvas — the stat tiles still work. |
| **`data/` git-ignored** | The scan database is per-machine runtime state, not source. |
| **`model.pkl` git-ignored** | It is reproducible in ~10 seconds from two commands. Delete that line from `.gitignore` if your submission requires the binary to be committed. |
| **Extra `/api/metrics` route** | Not in the brief, but it lets the dashboard display the real training metrics instead of hard-coding them into the HTML. |
| **CLI exit code 2 on Malicious** | Makes `cli.py` usable inside a shell script. |
| **VirusTotal hidden from the UI/CLI** | Requested. The lookup still runs and still carries its 25% weight; only the display was removed. Documented in §4 because it makes the visible sub-scores stop summing to the final score. |
| **Cache and rate limit in memory, not SQLite** | A single-user local tool does not need durable counters, and in-memory state means zero configuration and no schema migration. Both reset on restart, which is the desired behaviour. |
| **Rate limit set at 20/minute** | Far above what a human clicking Analyze will ever hit, far below what would burn the 500/day VirusTotal quota. |
| **`--text-muted` brightened even though it passed** | Raising `--text-dim` to meet AA pushed it close to `--text-muted`. Brightening muted too preserves a visible three-step type hierarchy (15.11 / 8.10 / 5.65). |
| **Long hostnames clamped to 3 lines** | A 118-character host wrapped to eight lines and stretched the whole metadata row. The full value is still available on hover via `title`. |
| **`httpx` included, Playwright not** | `httpx` is in `requirements.txt` because FastAPI's `TestClient` needs it for `smoke_test.py`'s API checks. Playwright was used only during development to verify the UI in a real browser and is deliberately not a dependency. |

---

## 13. Quick reference

```bash
python -m app.ml.make_dataset          # regenerate dataset.csv
python -m app.ml.train                 # retrain, print metrics, save model.pkl
python -m app.ml.train --csv real.csv  # train on an external dataset
python smoke_test.py                   # 46-check self-test
python cli.py <url>                    # terminal scan
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

| Endpoint | Method | Purpose |
|---|---|---|
| `/` `/history` `/dashboard` | GET | The three pages |
| `/api/analyze` | POST | `{"url": "..."}` → full result JSON |
| `/api/history` | GET | `?limit=&offset=&verdict=&search=` |
| `/api/history` | DELETE | Clear all stored scans |
| `/api/stats` | GET | Verdict counts, 14-day series, recent scans |
| `/api/health` | GET | Model / VirusTotal / database state |
| `/api/metrics` | GET | Training metrics from `metrics.json` |
| `/docs` | GET | Auto-generated OpenAPI documentation |

**Response headers on `/api/analyze`**

| Header | Meaning |
|---|---|
| `X-Cache: HIT` / `MISS` | Whether the result came from the 5-minute in-memory cache |
| `X-RateLimit-Limit` | Requests allowed per minute (20) |
| `X-RateLimit-Remaining` | Requests left in the current window |
| `Retry-After` | Seconds to wait, sent only with a 429 |

**Keyboard shortcuts**

| Key | Action |
|---|---|
| `/` | Focus the URL field (or the search box on History) |
| `Enter` | Submit the scan |
| `Esc` | Blur the focused field / close the confirm modal |

---

*Link Threat Analysis Tool — Group 09, Department of Information Technology,
Bhilai Institute of Technology, Durg.*
*Scores are advisory. Always verify a suspicious link through an independent channel.*
