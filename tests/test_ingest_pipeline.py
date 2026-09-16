"""Phase-2 test matrix: ingest pipeline, validation, protocol/TLS evidence (§27)."""
import json
import os

import pytest

from securemailscope.config import Config
from securemailscope.dissect import TsharkAdapter, DissectStatus
from securemailscope.evidence import RunStatus
from securemailscope.ingest import analyze_capture, validate_capture, ValidationResult

P = "research/experiments/oq28/pcaps"


def _tshark_available() -> bool:
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark_available(), reason="tshark not installed")


# --------------------------------------------------------------- validation
def test_validate_missing(tmp_path):
    v = validate_capture(str(tmp_path / "nope.pcap"))
    assert v.result is ValidationResult.NOT_FOUND and not v.ok


def test_validate_directory_is_not_a_file(tmp_path):
    v = validate_capture(str(tmp_path))
    assert v.result is ValidationResult.NOT_A_FILE


def test_validate_zero_byte_file_is_empty_file(tmp_path):
    p = tmp_path / "e.pcap"; p.write_bytes(b"")
    v = validate_capture(str(p))
    # EMPTY_FILE (zero bytes) is distinct from EMPTY (parsed, zero packets).
    assert v.result is ValidationResult.EMPTY_FILE


def test_validate_oversized(tmp_path):
    p = tmp_path / "big.pcap"; p.write_bytes(b"\x00" * 2048)
    v = validate_capture(str(p), Config(max_capture_bytes=1024))
    assert v.result is ValidationResult.TOO_LARGE


def test_validate_unreadable(tmp_path):
    p = tmp_path / "locked.pcap"; p.write_bytes(b"\x00" * 32)
    os.chmod(p, 0o000)
    try:
        v = validate_capture(str(p))
        # root can read anything; skip the assertion in that case
        if os.geteuid() != 0:
            assert v.result is ValidationResult.UNREADABLE
    finally:
        os.chmod(p, 0o644)


def test_validate_ok_resolves_path():
    v = validate_capture(f"{P}/C_normal_tls.pcap")
    assert v.ok and os.path.isabs(v.resolved_path) and v.size_bytes > 0


# --------------------------------------------------------------- happy path
@needs_tshark
@pytest.mark.parametrize("name,proto", [
    ("C_normal_tls", "smtp"), ("P_imap_tls", "imap"), ("P_pop3_tls", "pop3"),
])
def test_protocol_identified_end_to_end(name, proto):
    run, frames = analyze_capture(f"{P}/{name}.pcap")
    assert run.status is RunStatus.COMPLETED
    assert run.evidence_summary["app_protocols"].get(proto, 0) > 0
    assert run.packet_count == len(frames) > 0


@needs_tshark
def test_tls_evidence_without_verdicts():
    run, frames = analyze_capture(f"{P}/C_normal_tls.pcap")
    tls = [f for f in frames if f.tls.present]
    assert tls, "expected TLS evidence"
    # handshake types 1 (ClientHello) and 2 (ServerHello) observed
    types = {f.tls.handshake_type for f in tls if f.tls.handshake_type is not None}
    assert {1, 2} <= types
    assert any(f.tls.sni for f in tls)          # SNI observed
    assert any(f.tls.cipher_suite for f in tls)  # cipher suite observed
    # Evidence only: no security field leaks into ingestion (Phase-2 §9/§18).
    forbidden = {"severity", "verdict", "risk", "finding", "secure", "insecure"}
    assert not (forbidden & set(vars(frames[0]).keys()))
    assert not (forbidden & set(run.to_dict().keys()))


@needs_tshark
def test_x509_absent_is_not_invalid():
    """TLS 1.3 / synthetic handshakes may expose no certificate. Absence must be
    represented as absence, never as an invalid-certificate conclusion (§21)."""
    run, frames = analyze_capture(f"{P}/C_normal_tls.pcap")
    # No certificate evidence in this corpus -> no cert fields asserted anywhere,
    # and crucially no finding of any kind is produced by ingestion.
    assert run.evidence_summary["tls_frames"] > 0
    assert "certificate_invalid" not in json.dumps(run.to_dict())


@needs_tshark
def test_implicit_tls_port_evidence_recorded():
    """Implicit-TLS ports are corroborating evidence for later phases (§22)."""
    from securemailscope.dissect import fields as F
    assert F.MAIL_PORTS[993] == ("imap", True)
    assert F.MAIL_PORTS[465] == ("smtp", True)
    assert F.MAIL_PORTS[587] == ("smtp", False)


# --------------------------------------------------------------- provenance
@needs_tshark
def test_every_frame_has_provenance():
    run, frames = analyze_capture(f"{P}/C_normal_tls.pcap")
    for f in frames:
        assert f.capture_id == run.capture.capture_id
        assert f.frame_number is not None
        assert f.timestamp_epoch is not None
    # stream identity is capture-scoped, not just the 4-tuple (§23)
    keys = {f.stream_key for f in frames if f.stream_key}
    assert keys and all(k.startswith(run.capture.capture_id + ":") for k in keys)
    assert len(keys) == run.evidence_summary["tcp_streams"]


# --------------------------------------------------------------- failure paths
def test_missing_file_fails_cleanly():
    run, frames = analyze_capture("/nonexistent/path/x.pcap")
    assert run.status is RunStatus.FAILED and frames == []
    assert any("NOT_FOUND" in e for e in run.errors)


@needs_tshark
def test_malformed_capture_fails_not_crashes(tmp_path):
    p = tmp_path / "junk.pcap"; p.write_bytes(os.urandom(512))
    run, _ = analyze_capture(str(p))
    assert run.status is RunStatus.FAILED
    assert run.dissection_status == DissectStatus.MALFORMED.value


@needs_tshark
def test_truncated_capture_is_partial_with_evidence(tmp_path):
    p = tmp_path / "trunc.pcap"
    with open(f"{P}/C_normal_tls.pcap", "rb") as f:
        p.write_bytes(f.read(400))  # valid header, cut mid-packet
    run, frames = analyze_capture(str(p))
    # Usable evidence is preserved; completeness is flagged, not discarded (§25).
    assert run.status is RunStatus.PARTIAL
    assert run.capture.truncated is True
    assert len(frames) > 0
    assert any("truncated" in w for w in run.warnings)


def test_missing_tshark_fails_cleanly():
    bad = Config(tshark_path="/nonexistent/tshark_xyz")
    run, frames = analyze_capture(f"{P}/C_normal_tls.pcap", config=bad,
                                  adapter=TsharkAdapter(bad))
    assert run.status is RunStatus.FAILED and frames == []
    assert any("tshark unavailable" in e for e in run.errors)


# --------------------------------------------------------------- security
@needs_tshark
def test_hostile_filename_is_not_executed(tmp_path):
    """Shell metacharacters in a filename must be a literal path, never a command."""
    marker = tmp_path / "pwned"
    # NOTE: a filename cannot contain "/", so the injected command uses a bare name;
    # we assert nothing was created anywhere under tmp_path.
    evil = tmp_path / "a; touch pwned ;.pcap"
    with open(f"{P}/C_normal_tls.pcap", "rb") as src:
        evil.write_bytes(src.read())
    run, frames = analyze_capture(str(evil))
    assert not marker.exists(), "shell injection executed"
    assert not (tmp_path / "pwned").exists()
    assert run.status is RunStatus.COMPLETED and len(frames) > 0


def test_path_traversal_is_resolved_not_followed_blindly(tmp_path):
    v = validate_capture(str(tmp_path / ".." / ".." / "etc" / "passwd_nonexistent"))
    assert ".." not in (v.resolved_path or ""), "path not normalised"


# --------------------------------------------------------------- reproducibility
@needs_tshark
def test_same_capture_same_versions_equivalent_evidence():
    r1, f1 = analyze_capture(f"{P}/C_normal_tls.pcap")
    r2, f2 = analyze_capture(f"{P}/C_normal_tls.pcap")
    assert r1.capture.sha256 == r2.capture.sha256
    assert r1.evidence_summary == r2.evidence_summary
    assert [x.stream_key for x in f1] == [x.stream_key for x in f2]
    assert [x.tls.handshake_type for x in f1] == [x.tls.handshake_type for x in f2]
    # run_id and timestamps differ by design; evidence does not.
    assert r1.run_id != r2.run_id


@needs_tshark
def test_run_serializes_with_versions():
    run, _ = analyze_capture(f"{P}/C_normal_tls.pcap")
    d = run.to_dict()
    assert d["versions"]["tshark"] and d["versions"]["schema"] and d["versions"]["engine"]
    json.dumps(d)  # must be JSON-serialisable for later storage/reporting


@needs_tshark
def test_frame_ceiling_yields_partial_not_silent_discard():
    """Hitting the evidence-volume limit must surface as PARTIAL + warning (§15)."""
    cfg = Config(max_frames=10)
    run, frames = analyze_capture(f"{P}/C_normal_tls.pcap", config=cfg,
                                  adapter=TsharkAdapter(cfg))
    assert run.status is RunStatus.PARTIAL
    assert run.dissection_status == DissectStatus.LIMIT_EXCEEDED.value
    assert len(frames) == 10
    assert any("not discarded" in w for w in run.warnings)
