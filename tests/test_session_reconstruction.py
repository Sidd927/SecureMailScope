"""
Phase-3 tests: session reconstruction, protocol state machines, STARTTLS/STLS evidence.

These encode the semantics the research established, especially that identical evidence
must yield identical state (docs/research/02B §3.1).
"""
import pytest

from securemailscope.dissect import TsharkAdapter
from securemailscope.evidence.states import EvidenceState
from securemailscope.ingest import analyze_capture
from securemailscope.session import (
    AppState, Completeness, Direction, TlsState, reconstruct_sessions,
)

P = "research/experiments/oq28/pcaps"


def _tshark_available() -> bool:
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark_available(), reason="tshark not installed")


def sessions_for(name):
    run, frames = analyze_capture(f"{P}/{name}.pcap")
    return reconstruct_sessions(frames, run.capture.capture_id)


def first(name):
    return sessions_for(name)[0]


# ===================================================== protocol identification
@needs_tshark
@pytest.mark.parametrize("name,proto", [
    ("C_normal_tls", "smtp"), ("P_imap_tls", "imap"), ("P_pop3_tls", "pop3"),
])
def test_protocol_reconstructed(name, proto):
    s = first(name)
    assert s.protocol == proto
    assert s.packet_count > 0
    assert s.stream_key and s.stream_key.endswith(":0")


# ===================================================== successful upgrade (Case A/D)
@needs_tshark
@pytest.mark.parametrize("name", ["C_normal_tls", "P_imap_tls", "P_pop3_tls"])
def test_successful_upgrade_all_protocols(name):
    s = first(name)
    assert s.starttls_advertised.state is EvidenceState.OBSERVED
    assert s.starttls_advertised.value is True
    assert s.starttls_requested.value is True
    assert s.starttls_accepted.value is True
    assert s.tls_state is TlsState.ESTABLISHED
    assert s.app_state is AppState.TLS_ESTABLISHED
    assert s.tls_transition.value is True


# ===================================================== legitimate decline (Case B)
@needs_tshark
@pytest.mark.parametrize("name", ["A_legit_decline", "P_imap_decline", "P_pop3_decline"])
def test_legitimate_decline_is_observed_not_judged(name):
    s = first(name)
    # The advertisement WAS seen -> that part is observed fact.
    assert s.starttls_advertised.state is EvidenceState.OBSERVED
    assert s.starttls_advertised.value is True
    assert s.starttls_requested.value is False
    assert s.tls_state is TlsState.NONE
    # No security vocabulary anywhere in the reconstruction.
    blob = str(s.to_dict()).lower()
    for banned in ("attack", "malicious", "critical", "downgrade attack", "stripping"):
        assert banned not in blob


# ===================================================== THE critical ambiguity (§13/§14)
@needs_tshark
def test_absent_advertisement_is_ambiguous_never_false():
    for name in ("B_strip_advert", "I_no_support", "P_imap_strip", "P_pop3_strip"):
        s = first(name)
        assert s.starttls_advertised.state is EvidenceState.AMBIGUOUS, name
        assert "indistinguishable" in s.starttls_advertised.basis


@needs_tshark
def test_identical_evidence_yields_identical_state():
    """B_strip_advert (attack) and I_no_support (legitimate) are byte-identical at the
    application layer (02B §3.1). The reconstruction must NOT differentiate them."""
    attack = first("B_strip_advert")
    legit = first("I_no_support")
    assert attack.starttls_advertised.state == legit.starttls_advertised.state
    assert attack.starttls_advertised.value == legit.starttls_advertised.value
    assert attack.app_state == legit.app_state
    assert attack.tls_state == legit.tls_state


# ===================================================== rejection (Case C)
@needs_tshark
def test_rejected_upgrade_distinct_from_absent_advertisement():
    rejected = [s for s in sessions_for("J_strip_command")
                if s.starttls_accepted.value is False]
    assert rejected, "expected rejected-upgrade streams"
    for s in rejected:
        # Advertisement was seen, command was sent, server said no: all observed.
        assert s.starttls_advertised.value is True
        assert s.starttls_requested.value is True
        assert s.starttls_accepted.state is EvidenceState.OBSERVED
        assert s.tls_state is TlsState.NONE


@needs_tshark
def test_accepted_but_incomplete_handshake_is_not_established():
    """Server accepted, TLS began, handshake never completed. Must not claim success."""
    partial = [s for s in sessions_for("D_failed_upgrade")
               if s.tls_state is TlsState.CLIENT_HELLO_OBSERVED]
    assert partial, "expected interrupted-handshake streams"
    for s in partial:
        assert s.starttls_accepted.value is True
        assert s.app_state is not AppState.TLS_ESTABLISHED
        assert s.tls_transition.state is EvidenceState.AMBIGUOUS


# ===================================================== implicit TLS (§17)
@needs_tshark
@pytest.mark.parametrize("name,proto", [
    ("T_SMTPS_implicit", "smtp"), ("T_IMAPS_implicit", "imap"), ("T_POP3S_implicit", "pop3"),
])
def test_implicit_tls_is_not_a_starttls_upgrade(name, proto):
    s = first(name)
    assert s.protocol == proto
    assert s.implicit_tls is True
    assert s.app_state is AppState.IMPLICIT_TLS
    # Crucially: implicit TLS must never look like a STARTTLS success.
    assert s.starttls_advertised.state is EvidenceState.NOT_OBSERVABLE
    assert s.starttls_requested.state is EvidenceState.NOT_OBSERVABLE
    assert s.starttls_accepted.state is EvidenceState.NOT_OBSERVABLE
    assert not any(t.event.startswith("starttls") for t in s.transitions)


# ===================================================== truncation (§21)
@needs_tshark
def test_truncation_preserves_observations_without_inventing_final_state():
    sessions = sessions_for("E_incomplete")
    assert len(sessions) == 5
    for s in sessions:
        assert s.completeness is Completeness.INCOMPLETE
        # Never manufacture a successful teardown or an established session.
        assert not any(t.to_state is AppState.CLOSED for t in s.transitions)
        assert s.app_state is not AppState.TLS_ESTABLISHED
    # Progressive states are preserved up to each cut point.
    observed = {s.app_state for s in sessions}
    assert AppState.CAPABILITY_REQUESTED in observed
    assert AppState.TLS_NEGOTIATING in observed


# ===================================================== network conditions (§22/§23)
@needs_tshark
def test_retransmission_does_not_duplicate_events():
    sessions = sessions_for("K_network_cond")
    for s in sessions:
        kinds = [e.kind for e in s.events]
        for kind in ("starttls_command", "capability_response"):
            assert kinds.count(kind) <= 1, f"{kind} duplicated in stream {s.tcp_stream_id}"


# ===================================================== provenance (§26/§27)
@needs_tshark
def test_every_transition_has_evidence_and_provenance():
    for name in ("C_normal_tls", "P_imap_tls", "P_pop3_tls"):
        s = first(name)
        assert s.transitions
        for t in s.transitions:
            assert t.evidence_state in tuple(EvidenceState)
            assert t.basis, f"transition {t.event} lacks a basis"
            if t.event not in ("connection_closed",):
                assert t.evidence_frames, f"transition {t.event} lacks evidence frames"


@needs_tshark
def test_endpoint_roles_from_protocol_evidence_not_port_order():
    s = first("C_normal_tls")
    assert s.server_port == 587 and s.client_port != 587
    assert "greeting" in s.endpoint_basis or "response" in s.endpoint_basis


# ===================================================== invariants (§33)
@needs_tshark
def test_invariant_tls_established_requires_sufficient_evidence():
    for name in ("C_normal_tls", "A_legit_decline", "D_failed_upgrade",
                 "E_incomplete", "K_network_cond"):
        for s in sessions_for(name):
            if s.tls_state is TlsState.ESTABLISHED:
                assert s.tls_transition.value is True
            if s.app_state is AppState.TLS_ESTABLISHED:
                assert s.tls_state is TlsState.ESTABLISHED, name


@needs_tshark
def test_invariant_no_security_verdicts_in_phase3():
    banned = {"severity", "critical", "high", "medium", "low", "attack",
              "attacker", "compromised", "malicious", "vulnerable", "risk_score"}
    for name in ("C_normal_tls", "B_strip_advert", "P_pop3_strip", "T_SMTPS_implicit"):
        for s in sessions_for(name):
            blob = str(s.to_dict()).lower()
            for word in banned:
                assert word not in blob, f"{word!r} leaked into Phase-3 output for {name}"


@needs_tshark
def test_invariant_absent_packets_cannot_create_observed_events():
    """No event may reference a frame that is not in the session's frame range."""
    for name in ("C_normal_tls", "E_incomplete"):
        for s in sessions_for(name):
            for e in s.events:
                if e.frame_number is not None and s.first_frame and s.last_frame:
                    assert s.first_frame <= e.frame_number <= s.last_frame


@needs_tshark
def test_all_streams_are_represented_none_dropped():
    run, frames = analyze_capture(f"{P}/C_normal_tls.pcap")
    sessions = reconstruct_sessions(frames, run.capture.capture_id)
    assert len(sessions) == run.evidence_summary["tcp_streams"]


# ===================================================== reproducibility
@needs_tshark
def test_reconstruction_is_reproducible():
    a = [s.to_dict() for s in sessions_for("C_normal_tls")]
    b = [s.to_dict() for s in sessions_for("C_normal_tls")]
    assert a == b
