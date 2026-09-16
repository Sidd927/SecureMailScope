"""
Phase-1 integration + golden regression:  PCAP -> tshark -> adapter -> normalize -> evidence.

Proves the foundation preserves the observations established in OQ-28, without yet
implementing security findings.
"""
import json

import pytest

from securemailscope.dissect import TsharkAdapter, DissectStatus, normalize
from securemailscope.evidence import Capture

MANIFEST = "tests/golden/manifest.json"


def _tshark_available() -> bool:
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark_available(), reason="tshark not installed")


def _golden():
    return json.load(open(MANIFEST))["captures"]


def test_golden_hashes_still_match():
    """A golden pcap must never change silently (docs/architecture/07 §3)."""
    from securemailscope.evidence import sha256_file
    for c in _golden():
        assert sha256_file(c["pcap"]) == c["sha256"], f"{c['pcap']} changed — needs new hash+version+reason"


@needs_tshark
def test_full_chain_capture_metadata():
    adapter = TsharkAdapter()
    for c in _golden():
        cap = Capture.from_file(c["pcap"], tool_versions={"tshark": adapter.version()})
        assert cap.sha256 == c["sha256"]
        r = adapter.dissect(c["pcap"])
        truncated = r.status == DissectStatus.TRUNCATED
        cap = cap.with_dissection(packet_count=r.packet_count, truncated=truncated)
        assert cap.packet_count == c["expected"]["packet_count"], c["pcap"]


@needs_tshark
def test_golden_structural_observations():
    """Full pipeline must reproduce the recorded structural observations exactly."""
    from securemailscope.ingest import analyze_capture
    for c in _golden():
        run, _ = analyze_capture(c["pcap"])
        exp = c["expected"]
        assert run.status.value == exp["run_status"], c["scenario_id"]
        assert run.packet_count == exp["packet_count"], c["scenario_id"]
        assert run.evidence_summary["tcp_streams"] == exp["tcp_streams"], c["scenario_id"]
        assert run.evidence_summary["app_protocols"] == exp["app_protocols"], c["scenario_id"]
        assert run.evidence_summary["tls_frames"] == exp["tls_frames"], c["scenario_id"]


@needs_tshark
def test_golden_covers_all_mail_protocols():
    """Phase-2 §26 coverage requirement."""
    protos = {c["protocol"] for c in _golden()}
    assert {"smtp", "imap", "pop3"} <= protos


@needs_tshark
def test_normalize_recovers_frames_and_ports():
    adapter = TsharkAdapter()
    r = adapter.dissect("research/experiments/oq28/pcaps/C_normal_tls.pcap")
    frames = normalize(r.packets, capture_id="t")
    assert len(frames) == 84
    # SMTP submission port 587 must appear as a server port somewhere (proves normalization works).
    ports = {f.dst_port for f in frames} | {f.src_port for f in frames}
    assert 587 in ports
    # every frame carries a transport for this TCP-only capture
    assert all(f.transport == "tcp" for f in frames)


@needs_tshark
def test_truncated_capture_is_flagged_not_failed():
    """Regression on OQ-28 E_incomplete philosophy: truncation is a capture property,
    surfaced honestly, never a crash."""
    adapter = TsharkAdapter()
    r = adapter.dissect("research/experiments/oq28/pcaps/E_incomplete.pcap")
    # E_incomplete is a well-formed pcap of short sessions (not byte-truncated), so it reads OK;
    # the point is the chain does not error and packet count is deterministic.
    assert r.status in (DissectStatus.OK, DissectStatus.TRUNCATED)
    assert r.packet_count == 37
