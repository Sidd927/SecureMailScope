"""
Repository: runs, assessments, artifacts and events (doc 21 §5).

The repository stores and returns bytes the posture engine produced. It never inspects,
derives or recomputes a security conclusion. `overall_posture` and `score_value` are
written from the document inside the same transaction and exist so that listing can sort
and filter; **retrieval always returns the stored document**, never a reconstruction
from columns.

Identity discipline (ADR-0017 Decision 4): `assessment_id` is the canonical key, stored
untouched. `content_sha256` accompanies it because the id excludes `model_summary` and
`limitations`, which differ between AI-enabled and AI-disabled runs. Identical content
re-persists idempotently; divergent content under an existing id raises
`AssessmentIdentityConflict` rather than overwriting a stored conclusion.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from securemailscope import __version__ as SMS_VERSION
from securemailscope.backend.db import Database
from securemailscope.backend.errors import (
    AssessmentIdentityConflict, NotFound, PersistenceFailed,
)
from securemailscope.backend.lifecycle import JobState, check_transition, parse


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(document: Dict[str, Any]) -> str:
    """Stable serialisation: sorted keys, compact separators.

    Determinism matters because `content_sha256` is computed over this string. Two
    equal documents must produce one hash regardless of dict ordering.
    """
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


#: Fields the posture contract generates fresh on every invocation. `assessment_id`
#: deliberately excludes them (posture/engine.py `_assessment_id`) so that re-analysing
#: one capture reproduces one id; the integrity guard must use the same notion of
#: "content", or a legitimate re-run would look like a conflict.
RUNTIME_FIELDS = ("run_id", "generated_at")


def security_content(document: Dict[str, Any]) -> Dict[str, Any]:
    """The document minus its runtime-generated fields."""
    return {k: v for k, v in document.items() if k not in RUNTIME_FIELDS}


def content_hash(document: Dict[str, Any]) -> str:
    """Hash of the security content. Two runs of one capture agree; a genuine
    divergence (a different `model_summary`, different `limitations`) does not."""
    return hashlib.sha256(
        canonical_json(security_content(document)).encode("utf-8")).hexdigest()


@dataclass
class RunRecord:
    """Backend-owned metadata about one execution attempt."""
    run_id: str
    capture_id: Optional[str] = None
    state: JobState = JobState.CREATED
    previous_state: Optional[JobState] = None
    created_at: str = field(default_factory=_now)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    ai_enabled: bool = False
    formula_id: Optional[str] = None
    assessment_id: Optional[str] = None
    ingest_status: Optional[str] = None        # Phase-2 RunStatus, verbatim
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    source_filename: Optional[str] = None      # display only; never builds a path
    duration_ms: Optional[int] = None
    backend_version: str = SMS_VERSION

    @classmethod
    def new(cls, ai_enabled: bool = False, formula_id: Optional[str] = None,
            source_filename: Optional[str] = None) -> "RunRecord":
        return cls(run_id=uuid.uuid4().hex, ai_enabled=ai_enabled,
                   formula_id=formula_id, source_filename=source_filename)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id, "capture_id": self.capture_id,
            "state": self.state.value,
            "previous_state": self.previous_state.value if self.previous_state else None,
            "created_at": self.created_at, "started_at": self.started_at,
            "completed_at": self.completed_at,
            "ai_enabled": self.ai_enabled, "formula_id": self.formula_id,
            "assessment_id": self.assessment_id,
            "ingest_status": self.ingest_status,
            "error_code": self.error_code, "error_message": self.error_message,
            "source_filename": self.source_filename,
            "duration_ms": self.duration_ms,
            "backend_version": self.backend_version,
        }


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    run_id: str
    kind: str
    sha256: str
    size_bytes: int
    relative_path: str
    created_at: str
    original_filename: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id, "run_id": self.run_id,
            "kind": self.kind, "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "relative_path": self.relative_path,
            "created_at": self.created_at,
            "original_filename": self.original_filename,
        }


def _row_to_run(row: sqlite3.Row) -> RunRecord:
    return RunRecord(
        run_id=row["run_id"], capture_id=row["capture_id"],
        state=parse(row["state"]),
        previous_state=parse(row["previous_state"]) if row["previous_state"] else None,
        created_at=row["created_at"], started_at=row["started_at"],
        completed_at=row["completed_at"], ai_enabled=bool(row["ai_enabled"]),
        formula_id=row["formula_id"], assessment_id=row["assessment_id"],
        ingest_status=row["ingest_status"], error_code=row["error_code"],
        error_message=row["error_message"], source_filename=row["source_filename"],
        duration_ms=row["duration_ms"], backend_version=row["backend_version"])


class Repository:
    """CRUD over the catalog. Contains no security logic."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------ runs
    def create_run(self, run: RunRecord) -> RunRecord:
        with self.db.transaction() as cur:
            cur.execute(
                "INSERT INTO runs(run_id, capture_id, state, previous_state, "
                "created_at, started_at, completed_at, ai_enabled, formula_id, "
                "assessment_id, ingest_status, error_code, error_message, "
                "source_filename, duration_ms, backend_version) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run.run_id, run.capture_id, run.state.value, None, run.created_at,
                 run.started_at, run.completed_at, int(run.ai_enabled),
                 run.formula_id, run.assessment_id, run.ingest_status,
                 run.error_code, run.error_message, run.source_filename,
                 run.duration_ms, run.backend_version))
            self._event(cur, run.run_id, None, run.state, "run created")
        return run

    def get_run(self, run_id: str) -> RunRecord:
        with self.db.read() as cur:
            row = cur.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise NotFound("no such analysis run", detail={"run_id": run_id})
        return _row_to_run(row)

    def find_run(self, run_id: str) -> Optional[RunRecord]:
        try:
            return self.get_run(run_id)
        except NotFound:
            return None

    def list_runs(self, limit: int = 20, offset: int = 0,
                  state: Optional[JobState] = None,
                  capture_id: Optional[str] = None) -> Tuple[List[RunRecord], int]:
        where, params = [], []  # type: (List[str], List[Any])
        if state is not None:
            where.append("state=?")
            params.append(state.value)
        if capture_id:
            where.append("capture_id=?")
            params.append(capture_id)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self.db.read() as cur:
            total = cur.execute(
                "SELECT COUNT(*) AS n FROM runs" + clause, tuple(params)).fetchone()["n"]
            rows = cur.execute(
                "SELECT * FROM runs" + clause +
                " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                tuple(params) + (limit, offset)).fetchall()
        return [_row_to_run(r) for r in rows], int(total)

    def transition(self, run: RunRecord, target: JobState, *,
                   detail: str = "", cursor: Optional[sqlite3.Cursor] = None,
                   **updates: Any) -> RunRecord:
        """Move a run to `target`, validating the edge first.

        Accepts an existing cursor so a caller can make the transition part of a larger
        transaction — which is exactly how COMPLETED is committed together with the
        assessment row (ADR-0018 Decision 2).
        """
        check_transition(run.state, target, run.run_id)
        run.previous_state = run.state
        run.state = target
        if target is JobState.RUNNING and run.started_at is None:
            run.started_at = _now()
        if target in (JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED):
            run.completed_at = _now()
        for key, value in updates.items():
            setattr(run, key, value)

        def _write(cur: sqlite3.Cursor) -> None:
            cur.execute(
                "UPDATE runs SET capture_id=?, state=?, previous_state=?, started_at=?, "
                "completed_at=?, assessment_id=?, ingest_status=?, error_code=?, "
                "error_message=?, duration_ms=? WHERE run_id=?",
                (run.capture_id, run.state.value,
                 run.previous_state.value if run.previous_state else None,
                 run.started_at, run.completed_at, run.assessment_id,
                 run.ingest_status, run.error_code, run.error_message,
                 run.duration_ms, run.run_id))
            self._event(cur, run.run_id, run.previous_state, run.state, detail)

        if cursor is not None:
            _write(cursor)
        else:
            with self.db.transaction() as cur:
                _write(cur)
        return run

    def _event(self, cur: sqlite3.Cursor, run_id: str,
               from_state: Optional[JobState], to_state: JobState,
               detail: str = "") -> None:
        cur.execute(
            "INSERT INTO run_events(run_id, from_state, to_state, at, detail) "
            "VALUES(?,?,?,?,?)",
            (run_id, from_state.value if from_state else None, to_state.value,
             _now(), detail or None))

    def events(self, run_id: str) -> List[Dict[str, Any]]:
        with self.db.read() as cur:
            rows = cur.execute(
                "SELECT from_state, to_state, at, detail FROM run_events "
                "WHERE run_id=? ORDER BY event_id ASC", (run_id,)).fetchall()
        return [dict(r) for r in rows]

    def interrupted_runs(self) -> List[RunRecord]:
        """Runs left in a non-terminal state. Only a crash can produce these."""
        from securemailscope.backend.lifecycle import INTERRUPTIBLE
        placeholders = ",".join("?" for _ in INTERRUPTIBLE)
        with self.db.read() as cur:
            rows = cur.execute(
                "SELECT * FROM runs WHERE state IN (%s)" % placeholders,
                tuple(s.value for s in INTERRUPTIBLE)).fetchall()
        return [_row_to_run(r) for r in rows]

    # ----------------------------------------------------------- assessments
    def store_assessment(self, document: Dict[str, Any], *,
                         cursor: Optional[sqlite3.Cursor] = None) -> str:
        """Persist a canonical assessment document. Idempotent on identical content.

        Returns the `assessment_id`. Raises `AssessmentIdentityConflict` when an
        existing row shares the id but not the content.
        """
        assessment_id = document.get("assessment_id")
        if not assessment_id:
            raise PersistenceFailed("assessment document has no assessment_id")
        # The document is stored whole and verbatim; only the integrity digest is
        # computed over the run-independent subset.
        payload = canonical_json(document)
        digest = content_hash(document)
        coverage = document.get("coverage") or {}
        score = document.get("score") or {}
        versions = document.get("versions") or {}
        row = (
            assessment_id, digest, document.get("capture_id", ""), payload,
            document.get("overall_posture"), score.get("value"),
            int(bool(document.get("ai_enabled"))),
            versions.get("schema"), versions.get("engine"),
            coverage.get("sessions_total"), coverage.get("sessions_assessed"),
            document.get("generated_at"), _now())

        def _write(cur: sqlite3.Cursor) -> str:
            existing = cur.execute(
                "SELECT content_sha256 FROM assessments WHERE assessment_id=?",
                (assessment_id,)).fetchone()
            if existing is not None:
                if existing["content_sha256"] == digest:
                    return assessment_id          # idempotent replay
                raise AssessmentIdentityConflict(
                    "an assessment with this id is already stored with different "
                    "content",
                    detail={"assessment_id": assessment_id,
                            "stored_content_sha256": existing["content_sha256"],
                            "incoming_content_sha256": digest})
            cur.execute(
                "INSERT INTO assessments(assessment_id, content_sha256, capture_id, "
                "document, overall_posture, score_value, ai_enabled, schema_version, "
                "engine_version, sessions_total, sessions_assessed, generated_at, "
                "stored_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
            return assessment_id

        if cursor is not None:
            return _write(cursor)
        with self.db.transaction() as cur:
            return _write(cur)

    def get_assessment(self, assessment_id: str) -> Dict[str, Any]:
        """Return the stored document verbatim. Never rebuilt from columns."""
        with self.db.read() as cur:
            row = cur.execute(
                "SELECT document FROM assessments WHERE assessment_id=?",
                (assessment_id,)).fetchone()
        if row is None:
            raise NotFound("no such assessment",
                           detail={"assessment_id": assessment_id})
        return json.loads(row["document"])

    def assessment_meta(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        with self.db.read() as cur:
            row = cur.execute(
                "SELECT assessment_id, content_sha256, capture_id, overall_posture, "
                "score_value, ai_enabled, schema_version, engine_version, "
                "sessions_total, sessions_assessed, generated_at, stored_at "
                "FROM assessments WHERE assessment_id=?", (assessment_id,)).fetchone()
        return dict(row) if row else None

    def find_completed_run_for(self, capture_id: str, ai_enabled: bool,
                               formula_id: Optional[str]) -> Optional[RunRecord]:
        """Idempotency lookup (ADR-0018 Decision 4). Keys on content, never filename."""
        with self.db.read() as cur:
            row = cur.execute(
                "SELECT * FROM runs WHERE capture_id=? AND state=? AND ai_enabled=? "
                "AND (formula_id IS ? OR formula_id=?) AND assessment_id IS NOT NULL "
                "ORDER BY created_at ASC LIMIT 1",
                (capture_id, JobState.COMPLETED.value, int(ai_enabled),
                 formula_id, formula_id)).fetchone()
        return _row_to_run(row) if row else None

    # ------------------------------------------------------------- artifacts
    def add_artifact(self, artifact: ArtifactRecord, *,
                     cursor: Optional[sqlite3.Cursor] = None) -> ArtifactRecord:
        params = (artifact.artifact_id, artifact.run_id, artifact.kind,
                  artifact.sha256, artifact.size_bytes, artifact.relative_path,
                  artifact.created_at, artifact.original_filename)
        sql = ("INSERT INTO artifacts(artifact_id, run_id, kind, sha256, size_bytes, "
               "relative_path, created_at, original_filename) VALUES(?,?,?,?,?,?,?,?)")
        if cursor is not None:
            cursor.execute(sql, params)
        else:
            with self.db.transaction() as cur:
                cur.execute(sql, params)
        return artifact

    def list_artifacts(self, run_id: str) -> List[ArtifactRecord]:
        with self.db.read() as cur:
            rows = cur.execute(
                "SELECT * FROM artifacts WHERE run_id=? ORDER BY created_at ASC",
                (run_id,)).fetchall()
        return [ArtifactRecord(
            artifact_id=r["artifact_id"], run_id=r["run_id"], kind=r["kind"],
            sha256=r["sha256"], size_bytes=r["size_bytes"],
            relative_path=r["relative_path"], created_at=r["created_at"],
            original_filename=r["original_filename"]) for r in rows]
