"""SQLite state store for OpenPlow.

Every stage writes here, keyed by ``(run_id, repo, stage)``. Findings stream in
as they are produced, so a crash loses only the task in flight. Any stage can
resume or retry from what is already persisted.

The store deliberately uses only the standard library.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    repo        TEXT NOT NULL,
    adapter     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

-- One row per unit of work. The orchestrator is a queue over this table.
-- task_id is unique WITHIN a run, not globally, so task ids may repeat across
-- runs (e.g. several benchmark targets sharing one database).
CREATE TABLE IF NOT EXISTS tasks (
    task_id     TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    repo        TEXT NOT NULL,
    stage       TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'pending',   -- pending|running|done|failed
    attempts    INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    PRIMARY KEY (run_id, task_id),
    UNIQUE (run_id, repo, stage, payload)
);

-- Findings stream in as hunters produce them, before validation.
CREATE TABLE IF NOT EXISTS findings (
    finding_id  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    repo        TEXT NOT NULL,
    stage       TEXT NOT NULL,
    verdict     TEXT NOT NULL DEFAULT 'needs_validation',
    data        TEXT NOT NULL,                      -- full finding JSON
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    PRIMARY KEY (run_id, finding_id)
);

-- Free-form log of what an agent needed but did not have. The most-used
-- signal in Cloudflare's system; here it tells us what to build next.
CREATE TABLE IF NOT EXISTS wishlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    repo        TEXT NOT NULL,
    stage       TEXT NOT NULL,
    item        TEXT NOT NULL,
    created_at  REAL NOT NULL
);

-- One row per model call, for cost accounting.
CREATE TABLE IF NOT EXISTS usage (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    repo            TEXT NOT NULL,
    role            TEXT NOT NULL,                 -- finder|validator
    model           TEXT NOT NULL,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    cache_read      INTEGER NOT NULL DEFAULT 0,
    cache_creation  INTEGER NOT NULL DEFAULT 0,
    created_at      REAL NOT NULL
);

-- Lesson signals: typed failures the feedback loop turns into prompt guidance.
-- source is 'learned' (this run) or 'imported' (from a lessons file).
CREATE TABLE IF NOT EXISTS lessons (
    run_id       TEXT NOT NULL,
    attack_class TEXT NOT NULL,
    kind         TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT 'learned',
    count        INTEGER NOT NULL DEFAULT 0,
    updated_at   REAL NOT NULL,
    PRIMARY KEY (run_id, attack_class, kind, source)
);

CREATE INDEX IF NOT EXISTS idx_tasks_run_status ON tasks (run_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (run_id);
CREATE INDEX IF NOT EXISTS idx_usage_run ON usage (run_id);
"""


@dataclass
class Task:
    task_id: str
    run_id: str
    repo: str
    stage: str
    payload: dict[str, Any]
    status: str
    attempts: int
    error: str | None


def _now() -> float:
    return time.time()


class Store:
    """A thin, well-indexed wrapper over a SQLite file."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ---- runs -----------------------------------------------------------

    def create_run(self, run_id: str, repo: str, adapter: str) -> None:
        now = _now()
        with self._tx() as c:
            c.execute(
                "INSERT OR IGNORE INTO runs (run_id, repo, adapter, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'running', ?, ?)",
                (run_id, repo, adapter, now, now),
            )

    def set_run_status(self, run_id: str, status: str) -> None:
        with self._tx() as c:
            c.execute(
                "UPDATE runs SET status = ?, updated_at = ? WHERE run_id = ?",
                (status, _now(), run_id),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    # ---- tasks ----------------------------------------------------------

    def add_task(self, task_id: str, run_id: str, repo: str, stage: str,
                 payload: dict[str, Any] | None = None) -> bool:
        """Enqueue a task. Returns False if an identical task already exists."""
        now = _now()
        payload_json = json.dumps(payload or {}, sort_keys=True)
        with self._tx() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO tasks "
                "(task_id, run_id, repo, stage, payload, status, attempts, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?)",
                (task_id, run_id, repo, stage, payload_json, now, now),
            )
            return cur.rowcount > 0

    def next_pending(self, run_id: str, stage: str | None = None) -> Task | None:
        """Claim the next pending task atomically and mark it running.

        Validations are claimed first so a hunt's failures are recorded before
        the next hunt's prompt is built. ``rowid`` breaks ``created_at`` ties
        (on Windows ``time.time()`` steps ~15 ms), keeping enqueue order.
        """
        with self._tx() as c:
            q = "SELECT * FROM tasks WHERE run_id = ? AND status = 'pending'"
            args: list[Any] = [run_id]
            if stage is not None:
                q += " AND stage = ?"
                args.append(stage)
            q += (" ORDER BY CASE stage WHEN 'validate' THEN 0 ELSE 1 END, created_at, rowid"
                  " LIMIT 1")
            row = c.execute(q, args).fetchone()
            if row is None:
                return None
            c.execute(
                "UPDATE tasks SET status = 'running', attempts = attempts + 1, updated_at = ? "
                "WHERE run_id = ? AND task_id = ?",
                (_now(), run_id, row["task_id"]),
            )
            return Task(
                task_id=row["task_id"], run_id=row["run_id"], repo=row["repo"],
                stage=row["stage"], payload=json.loads(row["payload"]),
                status="running", attempts=row["attempts"] + 1, error=None,
            )

    def finish_task(self, run_id: str, task_id: str, status: str,
                    error: str | None = None) -> None:
        with self._tx() as c:
            c.execute(
                "UPDATE tasks SET status = ?, error = ?, updated_at = ? "
                "WHERE run_id = ? AND task_id = ?",
                (status, error, _now(), run_id, task_id),
            )

    def requeue_stale_running(self, run_id: str) -> int:
        """On resume, any task left 'running' from a crashed session goes back to pending."""
        with self._tx() as c:
            cur = c.execute(
                "UPDATE tasks SET status = 'pending', updated_at = ? "
                "WHERE run_id = ? AND status = 'running'",
                (_now(), run_id),
            )
            return cur.rowcount

    def task_counts(self, run_id: str) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) n FROM tasks WHERE run_id = ? GROUP BY status",
            (run_id,),
        ).fetchall()
        return {r["status"]: r["n"] for r in rows}

    # ---- findings -------------------------------------------------------

    def upsert_finding(self, run_id: str, repo: str, stage: str, finding: dict[str, Any]) -> None:
        now = _now()
        fid = finding["id"]
        verdict = finding.get("verdict", "needs_validation")
        with self._tx() as c:
            c.execute(
                "INSERT INTO findings (finding_id, run_id, repo, stage, verdict, data, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id, finding_id) DO UPDATE SET "
                "verdict = excluded.verdict, data = excluded.data, "
                "stage = excluded.stage, updated_at = excluded.updated_at",
                (fid, run_id, repo, stage, verdict, json.dumps(finding), now, now),
            )

    def findings(self, run_id: str, verdict: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT data FROM findings WHERE run_id = ?"
        args: list[Any] = [run_id]
        if verdict is not None:
            q += " AND verdict = ?"
            args.append(verdict)
        q += " ORDER BY created_at"
        rows = self._conn.execute(q, args).fetchall()
        return [json.loads(r["data"]) for r in rows]

    # ---- wishlist -------------------------------------------------------

    def add_wish(self, run_id: str, repo: str, stage: str, item: str) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO wishlist (run_id, repo, stage, item, created_at) VALUES (?, ?, ?, ?, ?)",
                (run_id, repo, stage, item, _now()),
            )

    def wishes(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT stage, item, created_at FROM wishlist WHERE run_id = ? ORDER BY created_at",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- lessons --------------------------------------------------------

    def add_lesson_signal(self, run_id: str, attack_class: str, kind: str, *,
                          source: str = "learned", n: int = 1) -> None:
        """Add ``n`` to a lesson count (the first signal inserts the row)."""
        with self._tx() as c:
            c.execute(
                "INSERT INTO lessons (run_id, attack_class, kind, source, count, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id, attack_class, kind, source) DO UPDATE SET "
                "count = count + excluded.count, updated_at = excluded.updated_at",
                (run_id, attack_class, kind, source, n, _now()),
            )

    def set_lesson_signal(self, run_id: str, attack_class: str, kind: str, *,
                          source: str = "imported", count: int) -> None:
        """Set a lesson count outright, so re-importing a lessons file is idempotent."""
        with self._tx() as c:
            c.execute(
                "INSERT INTO lessons (run_id, attack_class, kind, source, count, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id, attack_class, kind, source) DO UPDATE SET "
                "count = excluded.count, updated_at = excluded.updated_at",
                (run_id, attack_class, kind, source, count, _now()),
            )

    def lesson_signals(self, run_id: str, *,
                       sources: tuple[str, ...] = ("learned", "imported")) -> list[dict[str, Any]]:
        """Lesson rows of a run from the given sources, in a stable order."""
        if not sources:
            return []
        marks = ", ".join("?" for _ in sources)
        rows = self._conn.execute(
            "SELECT attack_class, kind, source, count FROM lessons "
            f"WHERE run_id = ? AND source IN ({marks}) "
            "ORDER BY attack_class, kind, source",
            (run_id, *sources),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- usage ----------------------------------------------------------

    def add_usage(self, run_id: str, repo: str, role: str, model: str,
                  input_tokens: int, output_tokens: int,
                  cache_read: int, cache_creation: int) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO usage (run_id, repo, role, model, input_tokens, output_tokens, "
                "cache_read, cache_creation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, repo, role, model, input_tokens, output_tokens,
                 cache_read, cache_creation, _now()),
            )

    def usage_by_model(self, run_id: str) -> list[dict[str, Any]]:
        """Aggregated token usage per (role, model) for a run."""
        rows = self._conn.execute(
            "SELECT role, model, COUNT(*) calls, "
            "SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens, "
            "SUM(cache_read) cache_read, SUM(cache_creation) cache_creation "
            "FROM usage WHERE run_id = ? GROUP BY role, model",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]
