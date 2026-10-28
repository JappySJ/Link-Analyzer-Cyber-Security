"""
SQLite persistence for scan history.

THREADING RULE (this is why there is no global connection object)
-----------------------------------------------------------------
A sqlite3 connection object may not be shared between threads. FastAPI runs our
blocking `def` route handlers in a threadpool, so consecutive requests really do
land on different threads. A single module-level connection would eventually
raise "SQLite objects created in a thread can only be used in that same thread"
under concurrent use.

Instead every operation opens its own short-lived connection through the
get_connection() context manager, which also:
  * enables WAL journal mode so a reader never blocks a writer,
  * sets row_factory = sqlite3.Row so rows behave like dicts,
  * commits on success and rolls back on an exception,
  * always closes the connection.

Only the standard-library sqlite3 module is used - no ORM, so every SQL
statement in the project is visible and explainable.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

from app.config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
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
    reasons         TEXT,
    cert_info       TEXT,
    created_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at);
CREATE INDEX IF NOT EXISTS idx_scans_verdict    ON scans (verdict);
"""


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """
    Yield a fresh SQLite connection for exactly one unit of work.

    Commits if the block succeeds, rolls back if it raises, and always closes.
    """
    connection = sqlite3.connect(str(DB_PATH), timeout=10.0)
    try:
        connection.row_factory = sqlite3.Row
        # WAL lets readers and the writer work concurrently instead of locking
        # each other out - important because the dashboard polls while a scan
        # may be writing.
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    """Create the table and indexes if they do not exist. Safe to call often."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as connection:
        connection.executescript(SCHEMA)


def check_db() -> bool:
    """True when the database is reachable and the scans table is queryable."""
    try:
        with get_connection() as connection:
            connection.execute("SELECT COUNT(*) FROM scans").fetchone()
        return True
    except Exception:
        return False


def insert_scan(result: dict) -> int:
    """
    Persist one analysis result and return its new row id.

    `reasons` and `cert_info` are stored as JSON text: SQLite has no native
    structured type, and keeping the full detail means the history page can
    re-render an old scan without re-analysing the URL.
    """
    scores = result.get("scores", {}) or {}
    vt = result.get("vt", {}) or {}
    certificate = result.get("certificate", {}) or {}

    row = (
        result.get("url", ""),
        result.get("hostname", ""),
        result.get("verdict", ""),
        float(result.get("final_score", 0.0)),
        float(scores.get("heuristic", 0.0) or 0.0),
        scores.get("ml_probability"),          # may legitimately be NULL
        int(vt.get("malicious", 0) or 0),
        int(vt.get("total", 0) or 0),
        vt.get("status", ""),
        certificate.get("status", ""),
        json.dumps(result.get("reasons", []), ensure_ascii=False),
        json.dumps(certificate, ensure_ascii=False),
        result.get("analyzed_at") or datetime.now(timezone.utc).isoformat(),
    )

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                url, hostname, verdict, final_score, heuristic_score,
                ml_probability, vt_malicious, vt_total, vt_status,
                cert_status, reasons, cert_info, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )
        return int(cursor.lastrowid)


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a stored row back into a JSON-friendly dict."""
    record = dict(row)
    for field in ("reasons", "cert_info"):
        raw = record.get(field)
        try:
            record[field] = json.loads(raw) if raw else ([] if field == "reasons" else {})
        except (json.JSONDecodeError, TypeError):
            record[field] = [] if field == "reasons" else {}
    return record


def get_scans(limit: int = 20, offset: int = 0, verdict_filter: str | None = None,
              search: str | None = None) -> dict:
    """
    Return a page of scan history, newest first.

    Returns {"items": [...], "total": N, "limit": L, "offset": O} so the UI can
    render pagination without a second round trip.

    All values are bound as SQL parameters - never string-formatted into the
    query - so a URL containing quotes cannot alter the statement.
    """
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))

    where: list[str] = []
    params: list = []

    if verdict_filter and verdict_filter.lower() != "all":
        where.append("verdict = ?")
        params.append(verdict_filter)

    if search:
        where.append("url LIKE ?")
        params.append(f"%{search}%")

    clause = f"WHERE {' AND '.join(where)}" if where else ""

    with get_connection() as connection:
        total = connection.execute(
            f"SELECT COUNT(*) AS n FROM scans {clause}", params
        ).fetchone()["n"]

        rows = connection.execute(
            f"""
            SELECT * FROM scans {clause}
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()

    return {
        "items": [_row_to_dict(r) for r in rows],
        "total": int(total),
        "limit": limit,
        "offset": offset,
    }


def get_scan(scan_id: int) -> dict | None:
    """Fetch one stored scan by id, or None."""
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _row_to_dict(row) if row else None


def delete_all_scans() -> int:
    """Delete every row and return how many were removed."""
    with get_connection() as connection:
        count = connection.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        connection.execute("DELETE FROM scans")
        # Reset AUTOINCREMENT so a cleared history starts again at id 1.
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'scans'")
    return int(count)


def get_stats(days: int = 14) -> dict:
    """
    Aggregates for the dashboard.

    Returns verdict counts, total scans, average score, scans per day for the
    last `days` days (with zero-filled gaps so the chart has no holes) and the
    five most recent scans.
    """
    with get_connection() as connection:
        verdict_rows = connection.execute(
            "SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict"
        ).fetchall()

        totals = connection.execute(
            "SELECT COUNT(*) AS n, AVG(final_score) AS avg_score FROM scans"
        ).fetchone()

        # substr(created_at,1,10) pulls 'YYYY-MM-DD' out of the ISO timestamp.
        daily_rows = connection.execute(
            """
            SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS n
            FROM scans
            WHERE substr(created_at, 1, 10) >= ?
            GROUP BY day
            ORDER BY day
            """,
            ((datetime.now(timezone.utc) - timedelta(days=days - 1)).date().isoformat(),),
        ).fetchall()

        recent_rows = connection.execute(
            """
            SELECT id, url, hostname, verdict, final_score, created_at
            FROM scans
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 5
            """
        ).fetchall()

    counts = {row["verdict"]: int(row["n"]) for row in verdict_rows}
    by_day = {row["day"]: int(row["n"]) for row in daily_rows}

    # Zero-fill every day in the window so the line chart is continuous.
    today = datetime.now(timezone.utc).date()
    series = []
    for offset in range(days - 1, -1, -1):
        day = (today - timedelta(days=offset)).isoformat()
        series.append({"date": day, "count": by_day.get(day, 0)})

    total = int(totals["n"] or 0)
    average = float(totals["avg_score"] or 0.0)

    return {
        "total_scans": total,
        "average_score": round(average, 2),
        "verdicts": {
            "Safe": counts.get("Safe", 0),
            "Suspicious": counts.get("Suspicious", 0),
            "Malicious": counts.get("Malicious", 0),
        },
        "scans_per_day": series,
        "days": days,
        "recent": [dict(row) for row in recent_rows],
    }
