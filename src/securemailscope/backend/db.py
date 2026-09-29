"""
SQLite catalog: connection, schema, migration and transactions (doc 21 §5, ADR-0017).

**This module holds no security logic and the schema expresses no security opinion.**
There is no `findings` table, no `severity` column and no `risk` column. The canonical
assessment is stored as the JSON document the posture engine produced, plus a small set
of metadata projections used for listing and filtering only — never read back as an
authority. Decomposing a conclusion into columns would create a second,
independently-writable representation of it, which ADR-0016 forbids.

Durability settings are chosen for a forensic store: `synchronous=FULL` trades
throughput for the guarantee that a committed assessment survives power loss.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator, Optional

from securemailscope.backend.errors import PersistenceFailed, SchemaVersionUnsupported

#: Bumped when the backend schema shape changes. Independent of the posture schema
#: version, which the assessment document carries itself.
BACKEND_SCHEMA_VERSION = "1.0"

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The canonical assessment, stored as a document. See module docstring.
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id    TEXT PRIMARY KEY,
    content_sha256   TEXT NOT NULL,
    capture_id       TEXT NOT NULL,
    document         TEXT NOT NULL,
    -- projections: listing and filtering only, never an authority
    overall_posture  TEXT,
    score_value      REAL,
    ai_enabled       INTEGER NOT NULL DEFAULT 0,
    schema_version   TEXT,
    engine_version   TEXT,
    sessions_total   INTEGER,
    sessions_assessed INTEGER,
    generated_at     TEXT,
    stored_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assessments_capture ON assessments(capture_id);

CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    capture_id      TEXT,
    state           TEXT NOT NULL,
    previous_state  TEXT,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    completed_at    TEXT,
    ai_enabled      INTEGER NOT NULL DEFAULT 0,
    formula_id      TEXT,
    assessment_id   TEXT REFERENCES assessments(assessment_id),
    ingest_status   TEXT,
    error_code      TEXT,
    error_message   TEXT,
    source_filename TEXT,
    duration_ms     INTEGER,
    backend_version TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_capture ON runs(capture_id);
CREATE INDEX IF NOT EXISTS idx_runs_state   ON runs(state);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at DESC);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id       TEXT PRIMARY KEY,
    run_id            TEXT NOT NULL REFERENCES runs(run_id),
    kind              TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    size_bytes        INTEGER NOT NULL,
    relative_path     TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    original_filename TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id);

-- Append-only transition trail: distinguishes "crashed" from "failed during analysis".
CREATE TABLE IF NOT EXISTS run_events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT NOT NULL REFERENCES runs(run_id),
    from_state TEXT,
    to_state   TEXT NOT NULL,
    at         TEXT NOT NULL,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_run ON run_events(run_id);
"""


class Database:
    """A SQLite catalog. One writer, many readers (WAL)."""

    def __init__(self, path: str) -> None:
        self.path = path
        # check_same_thread=False: the service serialises writes with its own lock, and
        # FastAPI may service requests from a threadpool.
        self._conn = sqlite3.connect(path, check_same_thread=False,
                                     isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._migrate()

    def _configure(self) -> None:
        cur = self._conn.cursor()
        # WAL: readers never block behind the single writer.
        if self.path != ":memory:":
            cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        # Durability over throughput: a committed forensic conclusion must survive a
        # power loss, which is exactly the case NORMAL does not cover.
        cur.execute("PRAGMA synchronous=FULL")
        cur.execute("PRAGMA busy_timeout=5000")

    def _migrate(self) -> None:
        with self.transaction() as cur:
            cur.executescript(SCHEMA)
            row = cur.execute(
                "SELECT value FROM schema_meta WHERE key='backend_schema_version'"
            ).fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO schema_meta(key, value) VALUES(?,?)",
                    ("backend_schema_version", BACKEND_SCHEMA_VERSION))
                return
            found = row["value"]
            if found == BACKEND_SCHEMA_VERSION:
                return
            # A database written by a newer backend is refused rather than guessed at:
            # silently reinterpreting unknown columns is how stored evidence gets
            # misread. Older versions would migrate here; none exist yet.
            if found > BACKEND_SCHEMA_VERSION:
                raise SchemaVersionUnsupported(
                    "database was written by a newer backend schema",
                    detail={"found": found, "supported": BACKEND_SCHEMA_VERSION})
            raise SchemaVersionUnsupported(
                "no migration path from the stored backend schema",
                detail={"found": found, "supported": BACKEND_SCHEMA_VERSION})

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """All-or-nothing unit of work.

        The lifecycle depends on this: marking a run COMPLETED and inserting its
        assessment happen inside one of these, so no crash window can leave a run
        claiming a result that was never stored (ADR-0018 Decision 2).
        """
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            yield cur
        except Exception:
            self._conn.rollback()
            raise
        else:
            self._conn.commit()
        finally:
            cur.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Cursor]:
        cur = self._conn.cursor()
        try:
            yield cur
        finally:
            cur.close()

    def schema_version(self) -> Optional[str]:
        with self.read() as cur:
            row = cur.execute(
                "SELECT value FROM schema_meta WHERE key='backend_schema_version'"
            ).fetchone()
            return row["value"] if row else None

    def healthy(self) -> bool:
        try:
            with self.read() as cur:
                cur.execute("SELECT 1 FROM schema_meta LIMIT 1")
            return True
        except sqlite3.Error:
            return False

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise PersistenceFailed("failed to close database",
                                    detail={"reason": type(exc).__name__})
