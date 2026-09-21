"""Phase-8 tests: lifecycle, persistence, identity discipline (doc 21 §5, §6, §17)."""
import json
import sqlite3

import pytest

from securemailscope.backend.db import BACKEND_SCHEMA_VERSION, Database
from securemailscope.backend.errors import (
    AssessmentIdentityConflict, InvalidTransition, NotFound, SchemaVersionUnsupported,
)
from securemailscope.backend.lifecycle import (
    INTERRUPTIBLE, TERMINAL, TRANSITIONS, JobState, can_transition, check_transition,
    is_terminal,
)
from securemailscope.backend.limits import Limits
from securemailscope.backend.repository import (
    ArtifactRecord, Repository, RunRecord, canonical_json, content_hash,
)
from securemailscope.config import Config


def _db(tmp_path) -> Database:
    return Database(str(tmp_path / "t.db"))


def _repo(tmp_path) -> Repository:
    return Repository(_db(tmp_path))


def _doc(assessment_id="aaa111", capture_id="cap1", posture="ADEQUATE", score=80.0,
         ai=False, **extra):
    doc = {
        "assessment_id": assessment_id, "capture_id": capture_id, "run_id": "r1",
        "generated_at": "2026-01-01T00:00:00Z",
        "versions": {"schema": "1.0", "engine": "0.7.0"},
        "ai_enabled": ai, "overall_posture": posture,
        "score": {"value": score, "band": posture},
        "coverage": {"sessions_total": 4, "sessions_assessed": 3},
        "limitations": ["a limitation"], "model_summary": None,
    }
    doc.update(extra)
    return doc


# ------------------------------------------------------------------ lifecycle
def test_transition_table_is_closed():
    """Every target in the table is itself a key: no edge leads out of the machine."""
    for source, targets in TRANSITIONS.items():
        assert isinstance(source, JobState)
        for target in targets:
            assert target in TRANSITIONS


def test_terminal_states_have_no_outgoing_edges():
    for state in TERMINAL:
        assert TRANSITIONS[state] == frozenset()
        assert is_terminal(state)


def test_completed_is_reachable_only_from_finalizing():
    sources = [s for s, t in TRANSITIONS.items() if JobState.COMPLETED in t]
    assert sources == [JobState.FINALIZING]


def test_completed_cannot_return_to_running():
    """The case the Phase-8 brief names explicitly. Phase-2 advance() would allow it."""
    assert not can_transition(JobState.COMPLETED, JobState.RUNNING)
    with pytest.raises(InvalidTransition):
        check_transition(JobState.COMPLETED, JobState.RUNNING, "run-x")


def test_invalid_transition_reports_what_was_allowed():
    with pytest.raises(InvalidTransition) as exc:
        check_transition(JobState.CREATED, JobState.COMPLETED)
    assert exc.value.detail["allowed"] == sorted(
        s.value for s in TRANSITIONS[JobState.CREATED])
    assert exc.value.http_status == 409


def test_every_non_terminal_state_can_fail():
    for state in INTERRUPTIBLE:
        assert JobState.FAILED in TRANSITIONS[state]


def test_recovery_required_leads_only_to_failed():
    assert TRANSITIONS[JobState.RECOVERY_REQUIRED] == frozenset({JobState.FAILED})


def test_interruptible_and_terminal_are_disjoint():
    assert not (INTERRUPTIBLE & TERMINAL)


def test_job_state_is_not_run_status():
    """Phase-2 RunStatus describes evidence quality; JobState describes scheduling."""
    from securemailscope.evidence.run import RunStatus
    assert not hasattr(JobState, "PARTIAL")
    assert not hasattr(JobState, "EMPTY")
    assert not hasattr(RunStatus, "QUEUED")


# --------------------------------------------------------------------- schema
def test_schema_version_recorded(tmp_path):
    assert _db(tmp_path).schema_version() == BACKEND_SCHEMA_VERSION


def test_reopen_is_idempotent(tmp_path):
    p = str(tmp_path / "t.db")
    Database(p).close()
    assert Database(p).schema_version() == BACKEND_SCHEMA_VERSION


def test_newer_schema_is_refused(tmp_path):
    """A database from a newer backend is refused, not reinterpreted."""
    p = str(tmp_path / "t.db")
    Database(p).close()
    conn = sqlite3.connect(p)
    conn.execute("UPDATE schema_meta SET value='9.9' WHERE key='backend_schema_version'")
    conn.commit()
    conn.close()
    with pytest.raises(SchemaVersionUnsupported):
        Database(p)


def test_database_holds_no_security_tables(tmp_path):
    """ADR-0017 Decision 1: the schema must not express a security opinion."""
    db = _db(tmp_path)
    with db.read() as cur:
        tables = {r["name"] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        columns = set()
        for table in tables:
            for row in cur.execute("PRAGMA table_info(%s)" % table).fetchall():
                columns.add(row["name"].lower())
    for forbidden in ("findings", "severities", "risks", "remediations", "anomalies"):
        assert forbidden not in tables
    for forbidden in ("severity", "risk", "certainty", "anomaly_score"):
        assert forbidden not in columns


def test_transaction_rolls_back(tmp_path):
    repo = _repo(tmp_path)
    run = repo.create_run(RunRecord.new())
    with pytest.raises(RuntimeError):
        with repo.db.transaction() as cur:
            cur.execute("UPDATE runs SET error_message='x' WHERE run_id=?", (run.run_id,))
            raise RuntimeError("boom")
    assert repo.get_run(run.run_id).error_message is None


# ----------------------------------------------------------------------- runs
def test_run_round_trip(tmp_path):
    repo = _repo(tmp_path)
    run = repo.create_run(RunRecord.new(ai_enabled=True, source_filename="a.pcap"))
    got = repo.get_run(run.run_id)
    assert got.run_id == run.run_id and got.ai_enabled is True
    assert got.state is JobState.CREATED and got.source_filename == "a.pcap"


def test_missing_run_raises_not_found(tmp_path):
    with pytest.raises(NotFound):
        _repo(tmp_path).get_run("nope")


def test_transition_persists_and_audits(tmp_path):
    repo = _repo(tmp_path)
    run = repo.create_run(RunRecord.new())
    repo.transition(run, JobState.VALIDATING, detail="validating")
    repo.transition(run, JobState.QUEUED)
    repo.transition(run, JobState.RUNNING)
    stored = repo.get_run(run.run_id)
    assert stored.state is JobState.RUNNING
    assert stored.previous_state is JobState.QUEUED
    assert stored.started_at is not None
    trail = [e["to_state"] for e in repo.events(run.run_id)]
    assert trail == ["CREATED", "VALIDATING", "QUEUED", "RUNNING"]


def test_invalid_transition_does_not_persist(tmp_path):
    repo = _repo(tmp_path)
    run = repo.create_run(RunRecord.new())
    with pytest.raises(InvalidTransition):
        repo.transition(run, JobState.COMPLETED)
    assert repo.get_run(run.run_id).state is JobState.CREATED


def test_list_runs_pagination_and_filter(tmp_path):
    repo = _repo(tmp_path)
    for i in range(5):
        r = repo.create_run(RunRecord.new())
        r.capture_id = "cap%d" % (i % 2)
        repo.transition(r, JobState.VALIDATING, capture_id=r.capture_id)
    rows, total = repo.list_runs(limit=2)
    assert total == 5 and len(rows) == 2
    rows, total = repo.list_runs(capture_id="cap0")
    assert total == 3 and all(r.capture_id == "cap0" for r in rows)
    rows, total = repo.list_runs(state=JobState.COMPLETED)
    assert total == 0 and rows == []


def test_interrupted_runs_reports_non_terminal(tmp_path):
    repo = _repo(tmp_path)
    live = repo.create_run(RunRecord.new())
    repo.transition(live, JobState.VALIDATING)
    repo.transition(live, JobState.QUEUED)
    repo.transition(live, JobState.RUNNING)
    done = repo.create_run(RunRecord.new())
    repo.transition(done, JobState.FAILED)
    assert [r.run_id for r in repo.interrupted_runs()] == [live.run_id]


# ---------------------------------------------------------------- assessments
def test_canonical_json_is_order_independent():
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert content_hash(a) == content_hash(b)


def test_assessment_document_round_trips_verbatim(tmp_path):
    repo = _repo(tmp_path)
    doc = _doc()
    repo.store_assessment(doc)
    assert repo.get_assessment("aaa111") == doc


def test_assessment_projections_written(tmp_path):
    repo = _repo(tmp_path)
    repo.store_assessment(_doc(posture="WEAK", score=61.5))
    meta = repo.assessment_meta("aaa111")
    assert meta["overall_posture"] == "WEAK" and meta["score_value"] == 61.5
    assert meta["sessions_total"] == 4 and meta["sessions_assessed"] == 3
    assert meta["content_sha256"] == content_hash(_doc(posture="WEAK", score=61.5))


def test_identical_content_is_idempotent(tmp_path):
    repo = _repo(tmp_path)
    assert repo.store_assessment(_doc()) == "aaa111"
    assert repo.store_assessment(_doc()) == "aaa111"
    with repo.db.read() as cur:
        assert cur.execute("SELECT COUNT(*) AS n FROM assessments").fetchone()["n"] == 1


def test_same_id_different_content_fails_closed(tmp_path):
    """ADR-0017 Decision 4. A stored conclusion is never silently overwritten."""
    repo = _repo(tmp_path)
    repo.store_assessment(_doc(posture="ADEQUATE"))
    with pytest.raises(AssessmentIdentityConflict) as exc:
        repo.store_assessment(_doc(posture="CRITICAL"))
    assert exc.value.http_status == 409
    assert repo.get_assessment("aaa111")["overall_posture"] == "ADEQUATE"


def test_insufficient_evidence_is_stored_unchanged(tmp_path):
    """The band must never be normalised into UNKNOWN or a success value."""
    repo = _repo(tmp_path)
    repo.store_assessment(_doc(posture="INSUFFICIENT_EVIDENCE", score=100.0))
    got = repo.get_assessment("aaa111")
    assert got["overall_posture"] == "INSUFFICIENT_EVIDENCE"
    assert repo.assessment_meta("aaa111")["overall_posture"] == "INSUFFICIENT_EVIDENCE"


def test_null_score_survives(tmp_path):
    repo = _repo(tmp_path)
    doc = _doc()
    doc["score"] = None
    doc["overall_posture"] = "INSUFFICIENT_EVIDENCE"
    repo.store_assessment(doc)
    assert repo.get_assessment("aaa111")["score"] is None


def test_missing_assessment_raises(tmp_path):
    with pytest.raises(NotFound):
        _repo(tmp_path).get_assessment("nope")


def test_idempotency_lookup_keys_on_capture_not_filename(tmp_path):
    repo = _repo(tmp_path)
    run = repo.create_run(RunRecord.new(source_filename="original.pcap"))
    repo.store_assessment(_doc())
    run.capture_id = "cap1"
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        repo.transition(run, target, capture_id="cap1")
    repo.transition(run, JobState.COMPLETED, assessment_id="aaa111")
    found = repo.find_completed_run_for("cap1", False, None)
    assert found is not None and found.run_id == run.run_id
    assert repo.find_completed_run_for("cap1", True, None) is None
    assert repo.find_completed_run_for("other", False, None) is None


def test_completion_and_assessment_commit_atomically(tmp_path):
    """ADR-0018 Decision 2: no window where COMPLETED exists without its assessment."""
    repo = _repo(tmp_path)
    run = repo.create_run(RunRecord.new())
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        repo.transition(run, target)
    with pytest.raises(RuntimeError):
        with repo.db.transaction() as cur:
            repo.store_assessment(_doc(), cursor=cur)
            repo.transition(run, JobState.COMPLETED, cursor=cur, assessment_id="aaa111")
            raise RuntimeError("crash before commit")
    assert repo.get_run(run.run_id).state is JobState.FINALIZING
    with pytest.raises(NotFound):
        repo.get_assessment("aaa111")


# ------------------------------------------------------------------ artifacts
def test_artifact_round_trip(tmp_path):
    repo = _repo(tmp_path)
    run = repo.create_run(RunRecord.new())
    repo.add_artifact(ArtifactRecord(
        artifact_id="art1", run_id=run.run_id, kind="pcap", sha256="d" * 64,
        size_bytes=10, relative_path="ab/cap/art1.pcap",
        created_at="2026-01-01T00:00:00Z", original_filename="../../evil.pcap"))
    got = repo.list_artifacts(run.run_id)
    assert len(got) == 1 and got[0].sha256 == "d" * 64
    # The hostile name is retained as a label only; it never built the stored path.
    assert got[0].original_filename == "../../evil.pcap"
    assert ".." not in got[0].relative_path


def test_artifact_requires_existing_run(tmp_path):
    repo = _repo(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        repo.add_artifact(ArtifactRecord(
            artifact_id="a", run_id="ghost", kind="pcap", sha256="e" * 64,
            size_bytes=1, relative_path="x", created_at="t"))


# --------------------------------------------------------------------- limits
def test_upload_ceiling_clamped_to_capture_ceiling():
    """Raising the upload limit alone must not bypass the Phase-2 capture ceiling."""
    limits = Limits(max_upload_bytes=10 * 1024**3)
    assert limits.effective_upload_ceiling(Config()) == Config().max_capture_bytes


def test_upload_ceiling_honours_unlimited_capture():
    limits = Limits(max_upload_bytes=1234)
    assert limits.effective_upload_ceiling(Config(max_capture_bytes=0)) == 1234


def test_page_size_bounds():
    limits = Limits()
    assert limits.page_size(0) == limits.default_page_size
    assert limits.page_size(10_000) == limits.max_page_size
    assert limits.page_size(5) == 5


def test_limits_reject_analysis_budget_below_subprocess_budget(monkeypatch):
    monkeypatch.setenv("SMS_MAX_ANALYSIS_SECONDS", "1")
    with pytest.raises(ValueError):
        Limits.load()


def test_default_concurrency_is_one():
    """Documented invariant (doc 21 §12), asserted so it cannot drift silently."""
    assert Limits().max_concurrent_analyses == 1
