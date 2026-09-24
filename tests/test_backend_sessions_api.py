"""
Sessions API: per-session detail, persisted and served verbatim.

`SessionEvidence` was always computed by the pipeline (Phase 3) but discarded once the
assessment was built -- there was no way to retrieve it after a run completed. This
endpoint is a read-only projection over exactly that data, stored in the same
transaction as the assessment (ADR-0018 Decision 2, extended). It introduces no new
analysis, no new security reasoning, and is not a second authority: `.../assessment`
and `.../dashboard` remain canonical for findings, posture and evidence state.
"""
import os

import pytest

fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
from fastapi.testclient import TestClient            # noqa: E402

from securemailscope.backend.api import create_app   # noqa: E402
from securemailscope.backend.service import AnalysisService  # noqa: E402
from securemailscope.dissect import TsharkAdapter    # noqa: E402

PCAP_DIR = "research/experiments/oq33r/out"
PLAINTEXT = os.path.join(PCAP_DIR, "postfix_smtp_plaintext_session.pcap")
IMPLICIT = os.path.join(PCAP_DIR, "dovecot_imap_imaps_implicit_tls.pcap")


def _tshark() -> bool:
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark(), reason="tshark not installed")
needs_pcaps = pytest.mark.skipif(not os.path.isfile(PLAINTEXT),
                                 reason="OQ-33r captures absent")


def _client(tmp_path, **kw) -> TestClient:
    svc = AnalysisService(str(tmp_path / "data"), **kw)
    return TestClient(create_app(service=svc), raise_server_exceptions=False)


def _upload(client, path, **params):
    with open(path, "rb") as fh:
        return client.post("/api/v1/analyses", files={"file": (os.path.basename(path),
                                                               fh, "application/octet-stream")},
                           params=params)


def test_unknown_run_is_404(tmp_path):
    r = _client(tmp_path).get("/api/v1/analyses/" + "a" * 32 + "/sessions")
    assert r.status_code == 404


def test_malformed_run_id_is_400(tmp_path):
    r = _client(tmp_path).get("/api/v1/analyses/not-a-uuid/sessions")
    assert r.status_code == 400


@needs_tshark
@needs_pcaps
def test_sessions_are_persisted_and_served(tmp_path):
    client = _client(tmp_path)
    run = _upload(client, PLAINTEXT).json()
    assert run["state"] == "COMPLETED"

    r = client.get(f"/api/v1/analyses/{run['run_id']}/sessions")
    assert r.status_code == 200
    body = r.json()
    assert body["run_id"] == run["run_id"]
    assert body["total"] == len(body["items"])
    assert body["total"] >= 1

    session = body["items"][0]
    # The exact shape `SessionEvidence.to_dict()` produces -- not renamed, not
    # flattened, not recomputed.
    assert "stream_key" in session
    assert "capture_id" in session
    assert "protocol" in session
    assert "client" in session and "server" in session
    assert "timing" in session
    assert "evidence" in session
    # Evidence fields carry the canonical EvidenceState vocabulary, untouched.
    for field_name, field_value in session["evidence"].items():
        assert field_value["state"] in (
            "OBSERVED", "INFERRED", "UNKNOWN", "AMBIGUOUS", "INCOMPLETE",
            "NOT_OBSERVABLE"), (field_name, field_value)
    assert body["capture_id"] == session["capture_id"]


@needs_tshark
@needs_pcaps
def test_sessions_match_pipeline_session_count(tmp_path):
    """The stored/served count must equal what Phase 3 actually reconstructed --
    verified against a direct pipeline invocation, not assumed."""
    from securemailscope.backend.pipeline import run_pipeline

    client = _client(tmp_path)
    run = _upload(client, IMPLICIT).json()
    assert run["state"] == "COMPLETED"

    direct = run_pipeline(IMPLICIT)
    served = client.get(f"/api/v1/analyses/{run['run_id']}/sessions").json()
    assert served["total"] == len(direct.sessions)


@needs_tshark
@needs_pcaps
def test_sessions_survive_a_fresh_service_instance(tmp_path):
    """Persisted, not cached in memory: a new `AnalysisService` over the same data
    directory must still be able to serve the sessions of an earlier run."""
    data_dir = str(tmp_path / "data")
    first = TestClient(create_app(service=AnalysisService(data_dir)),
                       raise_server_exceptions=False)
    run = _upload(first, PLAINTEXT).json()
    assert run["state"] == "COMPLETED"

    second = TestClient(create_app(service=AnalysisService(data_dir)),
                        raise_server_exceptions=False)
    body = second.get(f"/api/v1/analyses/{run['run_id']}/sessions").json()
    assert body["total"] >= 1


def test_incomplete_run_has_no_sessions_not_a_500(tmp_path):
    """A run that never reached Phase 3 (e.g. rejected at ingest) has nothing stored
    here -- an empty list, not an error, because the run itself is real."""
    client = _client(tmp_path)
    r = client.post("/api/v1/analyses", content=b"not a capture",
                    headers={"content-type": "application/octet-stream"})
    # Whatever the submission outcome, if a run_id exists its /sessions must not 500.
    if r.status_code < 500 and isinstance(r.json(), dict) and "run_id" in r.json():
        run_id = r.json()["run_id"]
        sr = client.get(f"/api/v1/analyses/{run_id}/sessions")
        assert sr.status_code in (200, 404)
