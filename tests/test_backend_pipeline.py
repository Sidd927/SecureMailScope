"""
Phase-8 tests: orchestration, artifacts, service lifecycle (doc 21 §4, §8, §13, §14).

The load-bearing test here is `test_backend_matches_direct_invocation` (§28 of the
Phase-8 brief): the canonical security semantics reaching a client through the backend
must equal those of calling the engines directly. Everything else in Phase 8 is
plumbing; if that equality breaks, the plumbing has started lying.
"""
import io
import json
import os
import sqlite3

import pytest

from securemailscope.analysis import SecurityAnalysisEngine
from securemailscope.backend.artifacts import ArtifactStore, safe_display_name
from securemailscope.backend.errors import (
    ArtifactIntegrityError, CaptureTooLarge, CaptureValidationFailed, NotFound,
    PersistenceFailed,
)
from securemailscope.backend.lifecycle import JobState
from securemailscope.backend.limits import Limits
from securemailscope.backend.pipeline import run_pipeline
from securemailscope.backend.service import AnalysisService
from securemailscope.crosssession import CrossSessionEngine
from securemailscope.dissect import TsharkAdapter
from securemailscope.ingest import analyze_capture
from securemailscope.posture import PostureConfig, PostureEngine
from securemailscope.session import reconstruct_sessions

PCAP_DIR = "research/experiments/oq33r/out"
PLAINTEXT = os.path.join(PCAP_DIR, "postfix_smtp_plaintext_session.pcap")
STARTTLS = os.path.join(PCAP_DIR, "postfix_smtp_starttls_upgrade.pcap")


def _tshark() -> bool:
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark(), reason="tshark not installed")
needs_pcaps = pytest.mark.skipif(not os.path.isfile(PLAINTEXT),
                                 reason="OQ-33r captures absent")


def _service(tmp_path) -> AnalysisService:
    return AnalysisService(str(tmp_path / "data"))


# ------------------------------------------------------------------ artifacts
def test_display_name_neutralises_traversal():
    assert safe_display_name("../../../etc/passwd") == "passwd"
    assert safe_display_name("/abs/path/x.pcap") == "x.pcap"
    assert safe_display_name("C:\\windows\\evil.pcap") == "evil.pcap"
    assert safe_display_name("bad\x00name.pcap") == "badname.pcap"
    assert safe_display_name("") == "capture.pcap"
    assert safe_display_name("...") == "capture.pcap"


def test_stored_path_is_built_from_generated_ids_only(tmp_path):
    """A hostile filename must never reach the filesystem."""
    store = ArtifactStore(str(tmp_path / "art"))
    record = store.store_stream(io.BytesIO(b"abc"), run_id="r1", capture_id="c1" * 8,
                                original_filename="../../../../etc/passwd")
    assert ".." not in record.relative_path
    assert "passwd" not in record.relative_path
    assert record.original_filename == "passwd"
    resolved = store.absolute(record.relative_path)
    assert resolved.startswith(store.root + os.sep)
    assert os.path.isfile(resolved)


def test_absolute_refuses_escaping_path(tmp_path):
    store = ArtifactStore(str(tmp_path / "art"))
    with pytest.raises(PersistenceFailed):
        store.absolute("../../etc/passwd")


def test_artifact_hash_describes_written_bytes(tmp_path):
    import hashlib
    store = ArtifactStore(str(tmp_path / "art"))
    payload = b"\x00\x01binary\xff" * 100
    record = store.store_stream(io.BytesIO(payload), run_id="r", capture_id="cc")
    assert record.sha256 == hashlib.sha256(payload).hexdigest()
    assert record.size_bytes == len(payload)
    store.verify(record)


def test_tampered_artifact_is_detected(tmp_path):
    """Integrity is re-checked by re-reading, never inferred from a filename."""
    store = ArtifactStore(str(tmp_path / "art"))
    record = store.store_stream(io.BytesIO(b"original"), run_id="r", capture_id="cc")
    with open(store.absolute(record.relative_path), "wb") as fh:
        fh.write(b"tampered")
    assert not store.is_intact(record)
    with pytest.raises(ArtifactIntegrityError) as exc:
        store.verify(record)
    assert exc.value.detail["recorded_sha256"] == record.sha256


def test_missing_artifact_is_detected(tmp_path):
    store = ArtifactStore(str(tmp_path / "art"))
    record = store.store_stream(io.BytesIO(b"x"), run_id="r", capture_id="cc")
    os.remove(store.absolute(record.relative_path))
    with pytest.raises(ArtifactIntegrityError):
        store.verify(record)


def test_oversized_stream_rejected_and_discarded(tmp_path):
    store = ArtifactStore(str(tmp_path / "art"))
    with pytest.raises(CaptureTooLarge):
        store.store_stream(io.BytesIO(b"x" * 5000), run_id="r", capture_id="cc",
                           max_bytes=1000)
    count, _ = store.size_on_disk()
    assert count == 0          # the partial write is not left behind


# ------------------------------------------------------------------- service
def test_rejects_empty_capture(tmp_path):
    svc = _service(tmp_path)
    with pytest.raises(CaptureValidationFailed):
        svc.submit_stream(io.BytesIO(b""), filename="empty.pcap")
    runs, total = svc.list_runs(10, 0)
    assert total == 1 and runs[0].state is JobState.FAILED
    assert runs[0].error_code == "CAPTURE_VALIDATION_FAILED"


def test_rejects_malformed_capture(tmp_path):
    svc = _service(tmp_path)
    with pytest.raises((CaptureValidationFailed, Exception)):
        svc.submit_stream(io.BytesIO(b"this is not a pcap at all" * 10),
                          filename="junk.pcap")
    runs, _ = svc.list_runs(10, 0)
    assert runs[0].state is JobState.FAILED


def test_missing_path_fails(tmp_path):
    svc = _service(tmp_path)
    with pytest.raises(CaptureValidationFailed):
        svc.submit_path(str(tmp_path / "absent.pcap"))


def test_oversized_upload_rejected(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"), limits=Limits(max_upload_bytes=64))
    with pytest.raises(CaptureTooLarge):
        svc.submit_stream(io.BytesIO(b"y" * 5000), filename="big.pcap")
    runs, _ = svc.list_runs(10, 0)
    assert runs[0].state is JobState.FAILED and runs[0].error_code == "CAPTURE_TOO_LARGE"


def test_failed_run_has_no_assessment(tmp_path):
    svc = _service(tmp_path)
    with pytest.raises(CaptureValidationFailed):
        svc.submit_stream(io.BytesIO(b""), filename="e.pcap")
    run = svc.list_runs(10, 0)[0][0]
    with pytest.raises(NotFound):
        svc.get_assessment(run.run_id)


def test_health_reports_database(tmp_path):
    health = _service(tmp_path).health()
    assert health["database"] == "ok" and health["schema_version"] == "1.0"
    assert health["limits"]["max_concurrent_analyses"] == 1


# --------------------------------------------------------- end-to-end (real)
@needs_tshark
@needs_pcaps
def test_submit_path_completes_and_persists(tmp_path):
    svc = _service(tmp_path)
    result = svc.submit_path(PLAINTEXT)
    run = result.run
    assert run.state is JobState.COMPLETED
    assert run.assessment_id and run.capture_id and run.duration_ms is not None
    assert run.ingest_status == "COMPLETED"

    document = svc.get_assessment(run.run_id)
    assert document["assessment_id"] == run.assessment_id
    assert document["capture_id"] == run.capture_id
    assert document["coverage"] is not None
    assert document["limitations"]

    trail = [e["to_state"] for e in svc.events(run.run_id)]
    assert trail == ["CREATED", "VALIDATING", "QUEUED", "RUNNING", "FINALIZING",
                     "COMPLETED"]


@needs_tshark
@needs_pcaps
def test_capture_id_is_sha256_of_stored_artifact(tmp_path):
    """The forensic chain: stored bytes -> sha256 -> capture_id -> assessment."""
    import hashlib
    svc = _service(tmp_path)
    run = svc.submit_path(PLAINTEXT).run
    expected = hashlib.sha256(open(PLAINTEXT, "rb").read()).hexdigest()
    assert run.capture_id == expected
    artifacts = svc.list_artifacts(run.run_id, verify=True)
    assert len(artifacts) == 1
    assert artifacts[0]["sha256"] == expected
    assert artifacts[0]["integrity"] == "OK"
    assert "relative_path" not in artifacts[0]     # internal location is not exposed


@needs_tshark
@needs_pcaps
def test_backend_matches_direct_invocation(tmp_path):
    """§28: backend semantics must equal a direct engine invocation.

    Compares the canonical fields, excluding only the deliberately runtime-generated
    `run_id` and `generated_at`.
    """
    svc = _service(tmp_path)
    run = svc.submit_path(PLAINTEXT).run
    via_backend = svc.get_assessment(run.run_id)

    ingest, frames = analyze_capture(PLAINTEXT)
    capture_id = ingest.capture.capture_id
    sessions = reconstruct_sessions(frames, capture_id)
    findings = SecurityAnalysisEngine().analyse(sessions, capture_id).findings
    cross = CrossSessionEngine().analyse(sessions, capture_id).findings
    direct = PostureEngine(PostureConfig(ai_enabled=False)).assess(
        sessions, findings, cross, (), capture_id=capture_id).to_dict()

    assert via_backend["assessment_id"] == direct["assessment_id"]
    assert via_backend["capture_id"] == direct["capture_id"]
    for field in ("overall_posture", "score", "coverage", "risk_summary",
                  "issue_groups", "prioritised", "abstentions", "protocol_posture",
                  "standards_summary", "remediation_summary", "model_summary",
                  "limitations", "versions", "ai_enabled"):
        assert via_backend[field] == direct[field], field

    # provenance excluding any runtime identifier
    assert json.dumps(via_backend["provenance"], sort_keys=True) == \
        json.dumps(direct["provenance"], sort_keys=True)


@needs_tshark
@needs_pcaps
def test_no_ai_equivalence_through_backend(tmp_path):
    """The --no-ai guarantee must survive the backend (doc 21 §15)."""
    a = _service(tmp_path / "a")
    b = _service(tmp_path / "b")
    plain = a.get_assessment(a.submit_path(PLAINTEXT, ai_enabled=False).run.run_id)
    with_ai = b.get_assessment(b.submit_path(PLAINTEXT, ai_enabled=True).run.run_id)

    assert plain["score"]["value"] == with_ai["score"]["value"]
    assert plain["overall_posture"] == with_ai["overall_posture"]
    assert plain["standards_summary"] == with_ai["standards_summary"]
    assert plain["remediation_summary"] == with_ai["remediation_summary"]
    penalising = lambda d: [g for g in d["issue_groups"] if g["penalising"]]
    assert penalising(plain) == penalising(with_ai)

    # The ML lane declares itself and its own limits, and never gains a severity.
    assert plain["ai_enabled"] is False and with_ai["ai_enabled"] is True
    assert with_ai["model_summary"]["role"] == "secondary prioritisation signal only"
    assert len(with_ai["limitations"]) > len(plain["limitations"])


@needs_tshark
@needs_pcaps
def test_no_ai_run_never_touches_ml_engine(tmp_path, monkeypatch):
    """`ai_enabled=False` must not construct a model at all, not merely discard it."""
    import securemailscope.ml.engine as ml_engine
    calls = []
    original = ml_engine.AnomalyEngine.__init__

    def spy(self, *a, **kw):
        calls.append(1)
        return original(self, *a, **kw)

    monkeypatch.setattr(ml_engine.AnomalyEngine, "__init__", spy)
    run_pipeline(PLAINTEXT, ai_enabled=False)
    assert calls == []


@needs_tshark
@needs_pcaps
def test_idempotent_resubmission_returns_existing_run(tmp_path):
    svc = _service(tmp_path)
    first = svc.submit_path(PLAINTEXT)
    second = svc.submit_path(PLAINTEXT)
    assert second.replayed is True
    assert second.run.run_id == first.run.run_id
    # exactly one completed run, and one cancelled duplicate
    completed, n = svc.list_runs(10, 0, state=JobState.COMPLETED)
    assert n == 1
    cancelled, n = svc.list_runs(10, 0, state=JobState.CANCELLED)
    assert n == 1 and cancelled[0].previous_state is JobState.VALIDATING


@needs_tshark
@needs_pcaps
def test_force_creates_independent_run_with_same_assessment(tmp_path):
    svc = _service(tmp_path)
    first = svc.submit_path(PLAINTEXT)
    forced = svc.submit_path(PLAINTEXT, force=True)
    assert forced.replayed is False
    assert forced.run.run_id != first.run.run_id
    # Deterministic pipeline: same content, same conclusion, stored once.
    assert forced.run.assessment_id == first.run.assessment_id
    with svc.db.read() as cur:
        assert cur.execute("SELECT COUNT(*) AS n FROM assessments").fetchone()["n"] == 1


@needs_tshark
@needs_pcaps
def test_different_captures_yield_different_assessments(tmp_path):
    svc = _service(tmp_path)
    a = svc.submit_path(PLAINTEXT).run
    b = svc.submit_path(STARTTLS).run
    assert a.capture_id != b.capture_id
    assert a.assessment_id != b.assessment_id


@needs_tshark
@needs_pcaps
def test_assessment_survives_restart(tmp_path):
    """Durability: a completed assessment is readable by a fresh process (§20)."""
    data = str(tmp_path / "data")
    svc = AnalysisService(data)
    run_id = svc.submit_path(PLAINTEXT).run.run_id
    before = svc.get_assessment(run_id)
    svc.close()

    reopened = AnalysisService(data)
    assert reopened.recover() == []        # nothing was interrupted
    assert reopened.get_run(run_id).state is JobState.COMPLETED
    assert reopened.get_assessment(run_id) == before


@needs_tshark
@needs_pcaps
def test_interrupted_run_is_never_reported_completed(tmp_path):
    """Simulate a crash mid-analysis, then restart (§20, ADR-0018 Decision 2)."""
    data = str(tmp_path / "data")
    svc = AnalysisService(data)

    # Leave a run stranded in RUNNING, exactly as a killed process would.
    from securemailscope.backend.repository import RunRecord
    stranded = svc.repo.create_run(RunRecord.new())
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING):
        svc.repo.transition(stranded, target)
    svc.close()

    reopened = AnalysisService(data)
    assert reopened.recover() == [stranded.run_id]
    recovered = reopened.get_run(stranded.run_id)
    assert recovered.state is JobState.FAILED
    assert recovered.error_code == "ANALYSIS_INTERRUPTED"
    assert recovered.assessment_id is None
    trail = [e["to_state"] for e in reopened.events(stranded.run_id)]
    assert trail[-2:] == ["RECOVERY_REQUIRED", "FAILED"]
    # and it is not counted as a success
    _, completed = reopened.list_runs(10, 0, state=JobState.COMPLETED)
    assert completed == 0


@needs_tshark
@needs_pcaps
def test_document_round_trip_preserves_evidence_nuance(tmp_path):
    """§29: no security nuance may disappear through persistence."""
    svc = _service(tmp_path)
    run = svc.submit_path(STARTTLS).run
    stored = svc.get_assessment(run.run_id)

    ingest, frames = analyze_capture(STARTTLS)
    cid = ingest.capture.capture_id
    sessions = reconstruct_sessions(frames, cid)
    direct = PostureEngine(PostureConfig()).assess(
        sessions,
        SecurityAnalysisEngine().analyse(sessions, cid).findings,
        CrossSessionEngine().analyse(sessions, cid).findings,
        (), capture_id=cid).to_dict()

    assert stored["abstentions"] == direct["abstentions"]
    assert stored["coverage"] == direct["coverage"]
    assert stored["provenance"] == direct["provenance"]
    assert stored["limitations"] == direct["limitations"]
    # frame references survive: they are what makes a finding auditable
    frames_in = lambda d: [p["representative_finding"]["frames"] for p in d["prioritised"]]
    assert frames_in(stored) == frames_in(direct)


@needs_tshark
@needs_pcaps
def test_stage_timings_recorded(tmp_path):
    result = run_pipeline(PLAINTEXT, ai_enabled=False)
    for stage in ("ingest", "sessions", "analysis", "crosssession", "posture"):
        assert stage in result.stage_ms
    assert "ml" not in result.stage_ms
