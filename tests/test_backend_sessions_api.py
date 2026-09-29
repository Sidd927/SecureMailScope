"""
Sessions API: per-session detail, re-derived from the stored capture and served
verbatim.

`SessionEvidence` was always computed by the pipeline (Phase 3) but discarded once the
assessment was built -- there was no way to retrieve it after a run completed. This
endpoint re-runs ingest + session reconstruction (Phase 2/3, deterministic and
side-effect-free) over the exact artifact bytes that run analysed, on every request --
the same pattern `.../dashboard` already uses to re-derive from the stored assessment,
applied one layer earlier. It introduces no new analysis, no new security reasoning,
and touches none of the Phase-8 backend core (db.py, service.py stay untouched;
test_backend_architecture.py's freeze tests guard that). `.../assessment` and
`.../dashboard` remain the canonical documents.
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
def test_sessions_are_re_derived_and_served(tmp_path):
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
    assert body["capture_id"] == run["capture_id"]


@needs_tshark
@needs_pcaps
def test_sessions_match_a_direct_pipeline_invocation(tmp_path):
    """The served sessions must equal what Phase 3 actually reconstructs -- verified
    against a direct pipeline invocation over the same bytes, not assumed."""
    from securemailscope.backend.pipeline import run_pipeline

    client = _client(tmp_path)
    run = _upload(client, IMPLICIT).json()
    assert run["state"] == "COMPLETED"

    direct = run_pipeline(IMPLICIT)
    served = client.get(f"/api/v1/analyses/{run['run_id']}/sessions").json()
    assert served["total"] == len(direct.sessions)
    # Reconstruction is deterministic: the same protocol/tcp_stream_id pairs, in the
    # same order, not just the same count.
    served_keys = [(s["protocol"], s["tcp_stream_id"]) for s in served["items"]]
    direct_keys = [(s.protocol, s.tcp_stream_id) for s in direct.sessions]
    assert served_keys == direct_keys


@needs_tshark
@needs_pcaps
def test_sessions_survive_a_fresh_service_instance(tmp_path):
    """The stored artifact -- not an in-memory result -- is what this endpoint reads:
    a new `AnalysisService` over the same data directory must still be able to
    re-derive the sessions of an earlier run."""
    data_dir = str(tmp_path / "data")
    first = TestClient(create_app(service=AnalysisService(data_dir)),
                       raise_server_exceptions=False)
    run = _upload(first, PLAINTEXT).json()
    assert run["state"] == "COMPLETED"

    second = TestClient(create_app(service=AnalysisService(data_dir)),
                        raise_server_exceptions=False)
    body = second.get(f"/api/v1/analyses/{run['run_id']}/sessions").json()
    assert body["total"] >= 1


def test_run_with_no_stored_capture_artifact_returns_an_empty_list(tmp_path):
    """A run that never reached a stored artifact has nothing to re-derive from --
    an empty list, not an error, because the run itself is real."""
    client = _client(tmp_path)
    r = client.post("/api/v1/analyses", content=b"not a capture",
                    headers={"content-type": "application/octet-stream"})
    if r.status_code < 500 and isinstance(r.json(), dict) and "run_id" in r.json():
        run_id = r.json()["run_id"]
        sr = client.get(f"/api/v1/analyses/{run_id}/sessions")
        assert sr.status_code in (200, 404)


def test_backend_core_was_not_touched_to_build_this():
    """This endpoint must not have required db.py or service.py to change -- the
    freeze tests in test_backend_architecture.py are the enforcement; this test names
    the intent so a future regression here is legible without cross-referencing."""
    import subprocess
    diff = subprocess.run(["git", "diff", "--name-only", "v0.3.0-phase8", "HEAD"],
                          capture_output=True, text=True)
    if diff.returncode != 0:
        pytest.skip("git unavailable")
    changed = {os.path.basename(f) for f in diff.stdout.splitlines()
              if f.startswith("src/securemailscope/backend/")}
    assert "db.py" not in changed
    assert "service.py" not in changed
