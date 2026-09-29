"""
Phase-5 tests: cross-session reasoning and baselines.

The safety-semantics tests (§18) are the important ones: they assert the engine refuses
to turn a *difference* into an *attack*, and abstains rather than inventing history.
"""
import json

import pytest

from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.crosssession import (
    BLIND_STRIPPING, Comparability, ContrastState, CrossSessionConfig, CrossSessionEngine,
    Deviation, assess, build_baseline, evaluate_contrast, prior_comparable,
)
from securemailscope.crosssession.baseline import BaselineStatus
from securemailscope.dissect import TsharkAdapter
from securemailscope.evidence.states import EvidenceField
from securemailscope.ingest import analyze_capture
from securemailscope.session import reconstruct_sessions
from securemailscope.session.model import (
    Completeness, SessionEvidence, TlsState,
)

P = "research/experiments/oq28/pcaps"
ENGINE = CrossSessionEngine()


def _tshark() -> bool:
    try:
        TsharkAdapter().version(); return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark(), reason="tshark not installed")


# --------------------------------------------------------------- synthetic builders
def mk(stream: int, *, client="10.0.0.5", server="10.0.0.80", port=587, proto="smtp",
       advertised=True, established=True, version="TLS1.3", ts=None, implicit=False,
       completeness=Completeness.COMPLETE, requested=None) -> SessionEvidence:
    """Build a session with precise control over the security-relevant features."""
    if requested is None:
        requested = established
    adv = (EvidenceField.observed(True, "capability present") if advertised is True
           else EvidenceField.ambiguous(False, "capability absent; indistinguishable")
           if advertised is False else EvidenceField.unknown("no capability response"))
    return SessionEvidence(
        capture_id="cap", tcp_stream_id=stream, protocol=proto,
        client_ip=client, client_port=40000 + stream, server_ip=server, server_port=port,
        first_frame=stream * 10, start_epoch=float(ts if ts is not None else stream),
        packet_count=10, completeness=completeness, implicit_tls=implicit,
        tls_state=TlsState.ESTABLISHED if established else TlsState.NONE,
        starttls_advertised=adv,
        starttls_requested=EvidenceField.observed(bool(requested), "observed"),
        tls_transition=EvidenceField.observed(bool(established), "observed"),
        tls_negotiated_version=(EvidenceField.observed(version, "ServerHello")
                                if established else EvidenceField.unknown("no ServerHello")),
        auth_activity=EvidenceField.observed(False, "none"),
    )


def run(sessions, **cfg):
    return CrossSessionEngine(CrossSessionConfig(**cfg)).analyse(sessions, "cap")


def of_kind(report, kind):
    return report.by_deviation(kind)


# =============================================================== comparability
def test_comparability_requires_resolved_identity():
    s = mk(1, client=None)
    a = assess(s)
    assert a.result is Comparability.INSUFFICIENT_EVIDENCE


def test_comparability_rejects_unidentified_protocol():
    s = mk(1, proto=None)
    assert assess(s).result is Comparability.NOT_COMPARABLE


def test_truncated_session_is_not_comparable():
    s = mk(1, completeness=Completeness.TRUNCATED)
    assert assess(s).result is Comparability.INSUFFICIENT_EVIDENCE


def test_implicit_and_explicit_tls_are_never_pooled():
    explicit = [mk(i) for i in range(6)]
    subject = mk(9, implicit=True)
    assert prior_comparable(subject, explicit + [subject]) == []


def test_different_endpoints_do_not_share_a_baseline():
    other = [mk(i, server="10.9.9.9") for i in range(6)]
    subject = mk(9)
    assert prior_comparable(subject, other + [subject]) == []


def test_different_protocols_do_not_share_a_baseline():
    other = [mk(i, proto="imap", port=143) for i in range(6)]
    subject = mk(9)
    assert prior_comparable(subject, other + [subject]) == []


# =============================================================== baseline / history
@pytest.mark.parametrize("n,expected", [
    (0, BaselineStatus.INSUFFICIENT_HISTORY),
    (1, BaselineStatus.INSUFFICIENT_HISTORY),
    (4, BaselineStatus.INSUFFICIENT_HISTORY),
    (5, BaselineStatus.ESTABLISHED),
    (9, BaselineStatus.ESTABLISHED),
])
def test_history_threshold(n, expected):
    prior = [mk(i, ts=i) for i in range(n)]
    subject = mk(100, ts=100)
    assert build_baseline(subject, prior + [subject]).status is expected


def test_threshold_is_configurable():
    prior = [mk(i, ts=i) for i in range(3)]
    subject = mk(100, ts=100)
    assert build_baseline(subject, prior + [subject], min_history=3).usable
    assert not build_baseline(subject, prior + [subject], min_history=4).usable


def test_baseline_only_uses_prior_sessions():
    """Later sessions must never leak into an earlier session's baseline (§7)."""
    early = mk(0, ts=0)
    later = [mk(i, ts=i) for i in range(1, 9)]
    assert prior_comparable(early, [early] + later) == []


def test_baseline_cites_concrete_members():
    prior = [mk(i, ts=i) for i in range(6)]
    b = build_baseline(mk(100, ts=100), prior + [mk(100, ts=100)])
    assert b.usable and len(b.members) == 6
    for m in b.members:
        assert m.stream_key is not None or m.tcp_stream_id is not None
        assert m.membership_reason


def test_mixed_history_is_not_a_consistent_expectation():
    mixed = [mk(i, advertised=(i % 2 == 0), established=(i % 2 == 0), ts=i) for i in range(6)]
    subject = mk(100, ts=100)
    b = build_baseline(subject, mixed + [subject])
    assert b.usable
    assert not b.feature("starttls_advertised").is_consistent


# =============================================================== contrast
def test_no_control_means_not_applicable():
    same_client = [mk(i, ts=i) for i in range(6)]
    subject = mk(100, ts=100)
    c = evaluate_contrast(subject, same_client + [subject])
    assert c.state is ContrastState.CONTRAST_NOT_APPLICABLE


def test_control_from_another_client_is_found():
    controls = [mk(i, client="10.0.0.9", ts=i) for i in range(3)]
    subject = mk(100, ts=100, advertised=False, established=False)
    c = evaluate_contrast(subject, controls + [subject])
    assert c.state is ContrastState.CONTRAST_SUPPORTED
    assert c.control_upgrade_rate == 1.0


def test_disagreeing_controls_are_ambiguous_not_evidence():
    """Heterogeneous-but-legitimate client populations must not drive a conclusion."""
    controls = [mk(i, client="10.0.0.9", established=(i % 2 == 0), ts=i) for i in range(4)]
    subject = mk(100, ts=100, advertised=False, established=False)
    c = evaluate_contrast(subject, controls + [subject])
    assert c.state is ContrastState.CONTRAST_AMBIGUOUS


def test_implicit_tls_contrast_not_applicable():
    subject = mk(100, implicit=True)
    assert evaluate_contrast(subject, [subject]).state is ContrastState.CONTRAST_NOT_APPLICABLE


# =============================================================== STARTTLS rules
def test_stable_behaviour_yields_no_deviation():
    sessions = [mk(i, ts=i) for i in range(8)]
    report = run(sessions)
    assert of_kind(report, Deviation.SUSPICIOUS_DEVIATION) == []
    assert of_kind(report, Deviation.DEVIATION) == []
    assert of_kind(report, Deviation.NONE)


def test_control_present_and_consistent_yields_no_deviation():
    """Negative cross-session case: a real control population exists (a different
    client at the same server, matching test_control_from_another_client_is_found's
    setup), and the subject's own behaviour matches both its own history and that
    control -- so the engine must report no deviation, not withhold a verdict for
    lack of evidence. This is distinct from test_stable_behaviour_yields_no_deviation
    (single client, no control at all) and from test_no_control_means_not_applicable
    (no second client, so contrast is NOT_APPLICABLE): here contrast evidence is
    genuinely available, and the correct behaviour is a clean absence of a finding.
    """
    prior = [mk(i, ts=i) for i in range(6)]
    controls = [mk(200 + i, client="10.0.0.9", ts=200 + i) for i in range(3)]
    subject = mk(100, ts=100)  # same defaults as prior/controls: advertised & established
    report = run(prior + controls + [subject])
    assert of_kind(report, Deviation.SUSPICIOUS_DEVIATION) == []
    assert of_kind(report, Deviation.DEVIATION) == []
    assert of_kind(report, Deviation.NONE)


def test_deviation_without_control_stays_ambiguous():
    """The core limitation: a deviation with no control cannot become a conclusion."""
    prior = [mk(i, ts=i) for i in range(6)]
    subject = mk(100, ts=100, advertised=False, established=False)
    report = run(prior + [subject])
    devs = of_kind(report, Deviation.DEVIATION)
    assert devs, "expected a reported deviation"
    for f in devs:
        assert f.status is FindingStatus.AMBIGUOUS
        assert f.severity is Severity.INFO
        assert f.limitations, f"{f.rule_id} must state its limitation"
    # The stripping limitation belongs to the advertisement question specifically;
    # the upgrade rule carries its own (legitimate-decline) limitation instead.
    advert = [f for f in devs if f.rule_id == "CS-STARTTLS-001"]
    assert advert and BLIND_STRIPPING in advert[0].limitations


def test_deviation_with_unaffected_control_is_supported():
    prior = [mk(i, ts=i) for i in range(6)]
    controls = [mk(200 + i, client="10.0.0.9", ts=200 + i) for i in range(3)]
    subject = mk(100, ts=100, advertised=False, established=False)
    report = run(prior + controls + [subject])
    susp = of_kind(report, Deviation.SUSPICIOUS_DEVIATION)
    assert susp
    f = susp[0]
    assert f.status is FindingStatus.OBSERVED_ISSUE
    assert f.severity is Severity.MEDIUM
    assert f.contrast["state"] == ContrastState.CONTRAST_SUPPORTED.value
    assert BLIND_STRIPPING in f.limitations   # limitation carried even when supported


def test_legitimate_decline_never_becomes_an_automatic_issue():
    """OQ-25 inversion guard (§11): historical success + current decline != attack."""
    prior = [mk(i, ts=i) for i in range(6)]
    declined = mk(100, ts=100, advertised=True, established=False, requested=False)
    report = run(prior + [declined])
    for f in report.findings:
        if f.subject_stream_key == declined.stream_key:
            assert f.severity is Severity.INFO, f.rule_id
            assert f.deviation is not Deviation.SUSPICIOUS_DEVIATION
            blob = json.dumps(f.to_dict()).lower()
            assert "attack" not in blob or "not treated as" in blob


# =============================================================== TLS version rules
def test_version_upgrade_is_not_an_anomaly():
    prior = [mk(i, version="TLS1.2", ts=i) for i in range(6)]
    subject = mk(100, version="TLS1.3", ts=100)
    report = run(prior + [subject])
    version_findings = [f for f in report.findings if f.rule_id == "CS-TLS-001"]
    assert version_findings
    f = version_findings[0]
    assert f.status is FindingStatus.INFORMATIONAL and f.deviation is Deviation.NONE
    assert "improved" in f.conclusion


def test_version_regression_is_reported():
    prior = [mk(i, version="TLS1.3", ts=i) for i in range(6)]
    subject = mk(100, version="TLS1.2", ts=100)
    report = run(prior + [subject])
    f = [x for x in report.findings if x.rule_id == "CS-TLS-001"][0]
    assert f.status is FindingStatus.OBSERVED_ISSUE and f.severity is Severity.MEDIUM
    assert "regressed" in f.conclusion
    assert f.limitations   # cause explicitly not established


# =============================================================== safety semantics
def test_no_history_produces_no_fabricated_anomaly():
    report = run([mk(1)])
    assert of_kind(report, Deviation.DEVIATION) == []
    assert of_kind(report, Deviation.SUSPICIOUS_DEVIATION) == []
    assert report.abstentions == 1


def test_unrelated_sessions_do_not_form_a_baseline():
    unrelated = [mk(i, server="10.7.7.7", proto="imap", port=143, ts=i) for i in range(8)]
    subject = mk(100, ts=100, advertised=False, established=False)
    report = run(unrelated + [subject])
    assert of_kind(report, Deviation.DEVIATION) == []
    assert of_kind(report, Deviation.SUSPICIOUS_DEVIATION) == []


def test_no_attacker_attribution_or_stripping_claim():
    prior = [mk(i, ts=i) for i in range(6)]
    controls = [mk(200 + i, client="10.0.0.9", ts=200 + i) for i in range(3)]
    subject = mk(100, ts=100, advertised=False, established=False)
    blob = json.dumps(run(prior + controls + [subject]).to_dict()).lower()
    for banned in ("attacker", "was stripped", "stripping attack", "malicious actor",
                   "compromised", "exploited"):
        assert banned not in blob, banned


def test_findings_never_exceed_info_unless_observed_issue():
    prior = [mk(i, ts=i) for i in range(6)]
    subject = mk(100, ts=100, advertised=False, established=False)
    for f in run(prior + [subject]).findings:
        if f.status is not FindingStatus.OBSERVED_ISSUE:
            assert f.severity is Severity.INFO


# =============================================================== determinism
def test_engine_is_deterministic_and_order_independent():
    prior = [mk(i, ts=i) for i in range(6)]
    controls = [mk(200 + i, client="10.0.0.9", ts=200 + i) for i in range(3)]
    subject = mk(100, ts=100, advertised=False, established=False)
    population = prior + controls + [subject]
    a = run(population).to_dict()
    b = run(list(reversed(population))).to_dict()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# =============================================================== research consistency
@needs_tshark
def test_oq25_control_present_vs_absent_on_real_captures():
    """OQ-25 11J vs 11J', reproduced on packet-derived evidence (§21)."""
    def analyse(name):
        run_, frames = analyze_capture(f"{P}/{name}.pcap")
        return ENGINE.analyse(reconstruct_sessions(frames, run_.capture.capture_id),
                              run_.capture.capture_id)

    with_control = analyse("G_control_endpoint")
    without = analyse("H_no_control")

    assert of_kind(with_control, Deviation.SUSPICIOUS_DEVIATION), \
        "control endpoint must enable a supported deviation"
    assert not of_kind(without, Deviation.SUSPICIOUS_DEVIATION), \
        "no control endpoint must NOT produce a supported deviation"
    assert not of_kind(without, Deviation.DEVIATION), \
        "consistently stripped traffic with no control is indistinguishable"


@needs_tshark
def test_phase5_does_not_alter_phase4_behaviour():
    """Phase 5 supplements Phase 4; it must not change it (§4)."""
    from securemailscope.analysis import SecurityAnalysisEngine
    run_, frames = analyze_capture(f"{P}/B_strip_advert.pcap")
    sessions = reconstruct_sessions(frames, run_.capture.capture_id)
    before = SecurityAnalysisEngine().analyse(sessions, run_.capture.capture_id).to_dict()
    ENGINE.analyse(sessions, run_.capture.capture_id)
    after = SecurityAnalysisEngine().analyse(sessions, run_.capture.capture_id).to_dict()
    assert json.dumps(before, sort_keys=True) == json.dumps(after, sort_keys=True)
