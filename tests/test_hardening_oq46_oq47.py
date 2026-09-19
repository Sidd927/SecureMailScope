"""
Phase-7 hardening regressions: OQ-46 (session completeness) and OQ-47 (SMTP
segmentation), plus the architectural invariants that had no explicit assertion.

Two properties carry most of the weight here:

* **Completeness is evidence-driven.** `TRUNCATED` means the recording stopped while
  this session was open -- not "a boundary is missing", which is a different and much
  more common condition. Over-applying it would silently shrink cross-session history.

* **Segmentation is not semantics.** For a given application byte stream the
  reconstruction must not depend on how that stream was cut into packets. Each segmented
  case is asserted equal to its unsegmented twin, and the absent cases are asserted to
  stay absent -- a fix that recovered capabilities by relaxing the matcher would pass the
  first half of that and fail the second.
"""
import json
import pathlib

import pytest

from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.crosssession.comparability import Comparability, assess
from securemailscope.dissect import TsharkAdapter
from securemailscope.evidence.states import EvidenceState
from securemailscope.ingest import analyze_capture
from securemailscope.session import reconstruct_sessions
from securemailscope.session.base import _open_session_completeness
from securemailscope.session.grouping import StreamGroup
from securemailscope.session.model import Completeness

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "research" / "experiments" / "oq46_47"
MANIFEST = CORPUS / "manifest.json"


def _tshark() -> bool:
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark(), reason="tshark not installed")
needs_corpus = pytest.mark.skipif(
    not MANIFEST.exists(),
    reason="hardening corpus absent; run research/experiments/oq46_47/craft_hardening.py")


def manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def sessions_for(group: str, pcap: str):
    run, frames = analyze_capture(str(CORPUS / group / pcap))
    return reconstruct_sessions(frames, run.capture.capture_id)


# ============================================================ OQ-46
@needs_tshark
@needs_corpus
@pytest.mark.parametrize("case", [c["case"] for c in manifest()["oq46"]]
                         if MANIFEST.exists() else [])
def test_oq46_completeness_matches_the_declared_expectation(case):
    entry = next(c for c in manifest()["oq46"] if c["case"] == case)
    sessions = sessions_for("oq46", entry["pcap"])
    assert sessions
    assert sessions[0].completeness.value == entry["expected_completeness"], entry["note"]


@needs_tshark
@needs_corpus
def test_truncated_is_reachable_from_a_real_capture():
    """The defect itself: before the fix no capture could produce TRUNCATED."""
    sessions = sessions_for("oq46", "C_cut_mid_dialogue.pcap")
    assert sessions[0].completeness is Completeness.TRUNCATED


@needs_tshark
@needs_corpus
def test_a_quiet_stream_is_not_called_truncated():
    """The distinction the fix exists to preserve: other traffic followed, so the
    recording did not stop here."""
    sessions = sessions_for("oq46", "H_quiet_stream_then_more_traffic.pcap")
    assert len(sessions) == 2
    quiet, later = sorted(sessions, key=lambda s: s.first_frame or 0)
    assert quiet.completeness is Completeness.INCOMPLETE
    assert later.completeness is Completeness.COMPLETE


@needs_tshark
@needs_corpus
def test_a_late_capture_start_is_incomplete_not_truncated():
    """Missing SYN but a real teardown: the capture began late, it did not cut short."""
    sessions = sessions_for("oq46", "F_missing_setup.pcap")
    assert sessions[0].completeness is Completeness.INCOMPLETE


@needs_tshark
@needs_corpus
def test_normal_teardown_is_never_mistaken_for_truncation():
    for pcap in ("A_clean_teardown.pcap", "B_reset_teardown.pcap"):
        assert sessions_for("oq46", pcap)[0].completeness is Completeness.COMPLETE


@needs_tshark
@needs_corpus
def test_truncated_session_is_excluded_from_cross_session_baselines():
    """The consequence that made this a correctness defect rather than a cosmetic one:
    the Phase-5 guard was dead, so truncated sessions entered baselines."""
    session = sessions_for("oq46", "C_cut_mid_dialogue.pcap")[0]
    assert session.completeness is Completeness.TRUNCATED
    assessment = assess(session)
    assert assessment.result is Comparability.INSUFFICIENT_EVIDENCE
    assert "truncated" in assessment.reason


def test_capture_level_truncation_marks_every_open_session():
    """tshark reporting the FILE as cut is sufficient on its own: a session need not own
    the last frame to have been ended by the recording."""
    group = StreamGroup(capture_id="c", tcp_stream_id=0, capture_truncated=True)
    assert _open_session_completeness(group, closed=False) is Completeness.TRUNCATED
    assert _open_session_completeness(group, closed=True) is Completeness.INCOMPLETE


def test_completeness_without_capture_context_defaults_to_incomplete():
    """A group built without capture context must not guess truncation."""
    group = StreamGroup(capture_id="c", tcp_stream_id=0)
    assert _open_session_completeness(group, closed=False) is Completeness.INCOMPLETE


# ============================================================ OQ-47
@needs_tshark
@needs_corpus
@pytest.mark.parametrize("case", [c["case"] for c in manifest()["oq47"]]
                         if MANIFEST.exists() else [])
def test_oq47_advertisement_matches_the_declared_expectation(case):
    entry = next(c for c in manifest()["oq47"] if c["case"] == case)
    session = sessions_for("oq47", entry["pcap"])[0]
    field = session.starttls_advertised
    assert field.value == entry["expected_advertised"], entry["note"]
    assert field.state.value == entry["expected_state"], entry["note"]


@needs_tshark
@needs_corpus
@pytest.mark.parametrize("case", [c["case"] for c in manifest()["oq47"]
                                  if c.get("equivalent_to")]
                         if MANIFEST.exists() else [])
def test_segmentation_does_not_change_semantics(case):
    """The core property: same application bytes, any packetisation, same meaning."""
    entry = next(c for c in manifest()["oq47"] if c["case"] == case)
    twin = next(c for c in manifest()["oq47"] if c["case"] == entry["equivalent_to"])
    segmented = sessions_for("oq47", entry["pcap"])[0]
    whole = sessions_for("oq47", twin["pcap"])[0]
    assert segmented.starttls_advertised.value == whole.starttls_advertised.value
    assert segmented.starttls_advertised.state == whole.starttls_advertised.state
    assert segmented.tls_state == whole.tls_state
    assert segmented.app_state == whole.app_state


@needs_tshark
@needs_corpus
def test_absence_stays_ambiguous_when_segmented():
    """A permissive matcher would pass the recovery tests and fail this one."""
    session = sessions_for("oq47", "K_absent_split.pcap")[0]
    assert session.starttls_advertised.value is False
    assert session.starttls_advertised.state is EvidenceState.AMBIGUOUS


@needs_tshark
@needs_corpus
def test_capability_string_in_message_body_is_not_an_advertisement():
    """Attacker-controlled DATA content must never become protocol evidence."""
    session = sessions_for("oq47", "N_forged_capability_in_message_body.pcap")[0]
    assert session.starttls_advertised.value is False
    assert session.starttls_advertised.state is EvidenceState.AMBIGUOUS


@needs_tshark
@needs_corpus
def test_recovered_advertisement_names_the_frames_that_carried_it():
    """Provenance must point at real packets, not at a synthetic reassembly."""
    session = sessions_for("oq47", "C_split_inside_token.pcap")[0]
    field = session.starttls_advertised
    assert field.value is True
    assert field.frames
    assert "reassembled" in field.basis


@needs_tshark
@needs_corpus
def test_retransmitted_capability_is_not_counted_twice():
    session = sessions_for("oq47", "H_retransmitted_segment.pcap")[0]
    assert session.starttls_advertised.value is True
    # One logical advertisement, however many times the segment was sent.
    assert len(set(session.starttls_advertised.frames)) == len(
        session.starttls_advertised.frames)


@needs_tshark
@needs_corpus
def test_out_of_order_segments_reassemble_by_sequence_not_arrival():
    session = sessions_for("oq47", "I_reordered_segments.pcap")[0]
    assert session.starttls_advertised.value is True


@needs_tshark
@needs_corpus
def test_segmented_advertisement_does_not_invent_an_upgrade():
    """Recovering the advertisement must not also manufacture a successful upgrade."""
    session = sessions_for("oq47", "L_advertised_never_used.pcap")[0]
    assert session.starttls_advertised.value is True
    assert session.starttls_requested.value is not True
    assert session.tls_state.value == "NONE"


@needs_tshark
@needs_corpus
def test_generator_b_segmentation_artifacts_are_gone():
    """The two sessions that motivated OQ-47 now resolve cleanly."""
    run, frames = analyze_capture(
        str(ROOT / "research/experiments/oq36/corpus/genB/B01_all_upgrade.pcap"))
    sessions = reconstruct_sessions(frames, run.capture.capture_id)
    assert all(s.starttls_advertised.value is True for s in sessions)
    assert all(s.starttls_advertised.state is EvidenceState.OBSERVED for s in sessions)


# ================================================ architectural invariants
def test_invariant_compliant_gives_no_credit_for_unobserved_state():
    """INVARIANT 2. A COMPLIANT finding must never raise a score above its start."""
    from securemailscope.posture import compute_score
    from securemailscope.posture import risk as risk_module
    from securemailscope.posture.fusion import FusionEngine
    from test_posture_fusion import finding

    compliant = [finding("SEC-TLS-002", status=FindingStatus.COMPLIANT,
                         severity=Severity.INFO, stream=f"cap:{i}") for i in range(20)]
    groups = risk_module.group_findings(FusionEngine().fuse(compliant).findings)
    score = compute_score(groups)
    assert score.value == 100.0
    assert score.components == ()          # nothing credited, nothing penalised


def test_invariant_ml_cannot_turn_unknown_into_observed():
    """INVARIANT 8. An ML signal attached to an abstaining session changes nothing."""
    from securemailscope.posture import PostureConfig, PostureEngine
    from test_posture_fusion import finding, ml

    unknown = [finding(status=FindingStatus.INSUFFICIENT_EVIDENCE,
                       severity=Severity.INFO, stream="cap:1")]
    off = PostureEngine(PostureConfig(ai_enabled=False)).assess(
        [], unknown, [], [], capture_id="cap", generated_at="X")
    on = PostureEngine(PostureConfig(ai_enabled=True)).assess(
        [], unknown, [], [ml(stream="cap:1")], capture_id="cap", generated_at="X")
    assert off.abstentions[0].reason is on.abstentions[0].reason
    assert [g.to_dict() for g in off.issue_groups if g.penalising] == []
    assert [g.to_dict() for g in on.issue_groups if g.penalising] == []


def test_invariant_only_one_scoring_path_exists():
    """INVARIANT 15. A second scoring implementation would let a later layer disagree
    with the canonical posture object. Assert the score can only come from one module."""
    import ast

    src = ROOT / "src" / "securemailscope"
    offenders = []
    for path in src.rglob("*.py"):
        if path.parts[-2:] == ("posture", "scoring.py"):
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("formula_"):
                offenders.append(f"{path.name}:{node.name}")
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in (
                            "SEVERITY_WEIGHT", "BAND_THRESHOLDS", "STARTING_VALUE"):
                        offenders.append(f"{path.name}:{target.id}")
    assert offenders == [], offenders
