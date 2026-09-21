"""
Phase-10 tests: the additive history-list projection (doc 23 §6, ADR-0022 Decision 3).

Two things are defended. First, that the two new fields carry the values the assessment
already stored rather than anything recomputed. Second — and more important — that the
Phase-8/9 response contract is **unchanged**: every field an existing client relied on
keeps its name, type and meaning, so the 697-test baseline stays valid untouched.
"""
import pytest

fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
from fastapi.testclient import TestClient                       # noqa: E402

from securemailscope.backend.api import create_app               # noqa: E402
from securemailscope.backend.lifecycle import JobState           # noqa: E402
from securemailscope.backend.repository import RunRecord         # noqa: E402
from securemailscope.backend.service import AnalysisService      # noqa: E402
from tests.reporting_fixtures import (                           # noqa: E402
    base_assessment, insufficient_evidence,
)

#: Exactly the fields Phase 8 and Phase 9 shipped. Adding to this list is allowed;
#: removing or renaming one is a breaking change and this test is the tripwire.
PHASE9_RUN_FIELDS = {
    "run_id", "state", "capture_id", "assessment_id", "ai_enabled", "formula_id",
    "created_at", "started_at", "completed_at", "duration_ms", "ingest_status",
    "error_code", "error_message", "source_filename", "backend_version", "replayed",
    "stages",
}
PHASE10_ADDED = {"overall_posture", "score_value"}


def _seeded(tmp_path, assessment=None, state=JobState.COMPLETED):
    assessment = assessment or base_assessment()
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.repo.create_run(RunRecord.new())
    if state is JobState.COMPLETED:
        svc.repo.store_assessment(assessment)
        for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                       JobState.FINALIZING):
            svc.repo.transition(run, target, capture_id=assessment["capture_id"])
        svc.repo.transition(run, JobState.COMPLETED,
                            assessment_id=assessment["assessment_id"])
    else:
        svc.repo.transition(run, JobState.VALIDATING)
        if state is not JobState.VALIDATING:
            svc.repo.transition(run, state,
                                error_code="ANALYSIS_FAILED"
                                if state is JobState.FAILED else None)
    return svc, run.run_id, assessment


def _client(svc):
    return TestClient(create_app(service=svc), raise_server_exceptions=False)


# ------------------------------------------------- backward compatibility
def test_every_phase9_field_is_still_present(tmp_path):
    svc, _, _ = _seeded(tmp_path)
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    missing = PHASE9_RUN_FIELDS - set(item)
    assert missing == set(), missing


def test_only_the_two_documented_fields_were_added(tmp_path):
    svc, _, _ = _seeded(tmp_path)
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    added = set(item) - PHASE9_RUN_FIELDS
    assert added == PHASE10_ADDED, added


def test_detail_endpoint_contract_also_unchanged(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    item = _client(svc).get("/api/v1/analyses/%s" % run_id).json()
    assert PHASE9_RUN_FIELDS - set(item) == set()
    assert set(item) - PHASE9_RUN_FIELDS == PHASE10_ADDED


def test_existing_field_types_are_unchanged(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    item = _client(svc).get("/api/v1/analyses/%s" % run_id).json()
    assert isinstance(item["run_id"], str)
    assert isinstance(item["state"], str)
    assert isinstance(item["ai_enabled"], bool)
    assert isinstance(item["replayed"], bool)
    assert isinstance(item["duration_ms"], (int, type(None)))
    assert isinstance(item["ingest_status"], (str, type(None)))


def test_new_fields_are_optional_in_the_schema(tmp_path):
    """An older client that ignores them, and a run that has none, both still work."""
    svc, _, _ = _seeded(tmp_path)
    schema = _client(svc).get("/openapi.json").json()
    props = schema["components"]["schemas"]["RunResponse"]
    required = set(props.get("required", []))
    assert not (PHASE10_ADDED & required)


def test_assessment_endpoint_remains_the_canonical_source(tmp_path):
    """doc 23 §6: the detail source is unchanged and complete."""
    svc, run_id, assessment = _seeded(tmp_path)
    body = _client(svc).get("/api/v1/analyses/%s/assessment" % run_id).json()
    assert body["assessment"] == assessment


# ----------------------------------------------- the projection is not computed
def test_listing_values_come_from_the_stored_assessment(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    stored = svc.repo.assessment_meta(assessment["assessment_id"])
    assert item["overall_posture"] == stored["overall_posture"]
    assert item["score_value"] == stored["score_value"]
    # and they agree with the canonical document
    assert item["overall_posture"] == assessment["overall_posture"]
    assert item["score_value"] == assessment["score"]["value"]


def test_withheld_band_and_null_score_survive_the_listing(tmp_path):
    """A withheld band must not become a pass, and a null score must not become 0."""
    svc, _, _ = _seeded(tmp_path, insufficient_evidence())
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    assert item["overall_posture"] == "INSUFFICIENT_EVIDENCE"
    assert item["score_value"] is None


@pytest.mark.parametrize("state", [JobState.FAILED, JobState.CANCELLED])
def test_runs_without_an_assessment_report_no_posture(tmp_path, state):
    """A run that produced nothing must not display a posture from anywhere."""
    svc, _, _ = _seeded(tmp_path, state=state)
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    assert item["state"] == state.value
    assert item["overall_posture"] is None
    assert item["score_value"] is None


def test_interrupted_run_is_swept_and_shows_no_posture(tmp_path):
    """A non-terminal run cannot survive app startup: Phase-8 recovery sweeps it to
    FAILED (doc 21 §13). It must still carry no posture afterwards."""
    svc, _, _ = _seeded(tmp_path, state=JobState.VALIDATING)
    item = _client(svc).get("/api/v1/analyses").json()["items"][0]
    assert item["state"] == "FAILED"
    assert item["error_code"] == "ANALYSIS_INTERRUPTED"
    assert item["overall_posture"] is None
    assert item["score_value"] is None


def test_one_request_serves_a_whole_history_page(tmp_path):
    """The point of the addition: no N+1 fetch for a list of postures."""
    svc = AnalysisService(str(tmp_path / "d"))
    for index in range(3):
        doc = base_assessment()
        doc["assessment_id"] = "aid%013d" % index
        doc["capture_id"] = ("%02d" % index) + "f" * 62
        doc["overall_posture"] = ["STRONG", "WEAK", "CRITICAL"][index]
        doc["score"] = {"value": float(90 - index * 20), "band": doc["overall_posture"]}
        run = svc.repo.create_run(RunRecord.new())
        svc.repo.store_assessment(doc)
        for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                       JobState.FINALIZING):
            svc.repo.transition(run, target, capture_id=doc["capture_id"])
        svc.repo.transition(run, JobState.COMPLETED,
                            assessment_id=doc["assessment_id"])

    body = _client(svc).get("/api/v1/analyses").json()
    assert body["total"] == 3
    postures = {i["overall_posture"] for i in body["items"]}
    assert postures == {"STRONG", "WEAK", "CRITICAL"}
    assert all(i["score_value"] is not None for i in body["items"])


# --------------------------------------------------- filtering still works
def test_state_and_capture_filters_still_work_after_the_join(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    client = _client(svc)
    completed = client.get("/api/v1/analyses", params={"state": "COMPLETED"}).json()
    assert completed["total"] == 1
    failed = client.get("/api/v1/analyses", params={"state": "FAILED"}).json()
    assert failed["total"] == 0
    by_capture = client.get("/api/v1/analyses",
                            params={"capture_id": assessment["capture_id"]}).json()
    assert by_capture["total"] == 1
    other = client.get("/api/v1/analyses",
                       params={"capture_id": "0" * 64}).json()
    assert other["total"] == 0


def test_pagination_still_correct_after_the_join(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"))
    for _ in range(4):
        svc.repo.create_run(RunRecord.new())
    client = _client(svc)
    page = client.get("/api/v1/analyses", params={"limit": 2}).json()
    assert page["total"] == 4 and len(page["items"]) == 2
    page2 = client.get("/api/v1/analyses", params={"limit": 2, "offset": 2}).json()
    assert len({i["run_id"] for i in page["items"] + page2["items"]}) == 4


def test_recovery_sweep_still_finds_interrupted_runs(tmp_path):
    """interrupted_runs() uses the joined select; it must still work."""
    data = str(tmp_path / "d")
    svc = AnalysisService(data)
    run = svc.repo.create_run(RunRecord.new())
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING):
        svc.repo.transition(run, target)
    svc.close()
    reopened = AnalysisService(data)
    assert reopened.recover() == [run.run_id]
    assert reopened.get_run(run.run_id).state is JobState.FAILED


def test_idempotency_lookup_still_works_after_the_join(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    found = svc.repo.find_completed_run_for(assessment["capture_id"], False, None)
    assert found is not None and found.run_id == run_id
    assert found.overall_posture == assessment["overall_posture"]
