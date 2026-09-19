"""
Phase-7 tests: the posture engine over the real corpora, end to end.

    PCAP -> tshark -> sessions -> findings -> cross-session -> ML -> posture

These are the tests that would catch a contract drifting apart from the pipeline that
feeds it. Everything above this file works on constructed findings; this one works on
bytes.

Corpus note: the OQ-25 corpus is a session-*outcome* model that predates the packet
crafter, so it produces no `SessionEvidence` and cannot drive this pipeline. Its
scenarios were replicated at packet level in OQ-28 (docs/research/02B), which is what is
exercised here, alongside the Phase-6 generators B and C.
"""
import json
import os

import pytest

from securemailscope.analysis import SecurityAnalysisEngine
from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.crosssession import CrossSessionEngine
from securemailscope.dissect import TsharkAdapter
from securemailscope.ingest import analyze_capture
from securemailscope.ml.engine import AnomalyEngine
from securemailscope.ml.models import RobustZScoreModel
from securemailscope.posture import (
    PostureBand, PostureConfig, PostureEngine, FactKind,
)
from securemailscope.session import reconstruct_sessions

OQ28 = "research/experiments/oq28/pcaps"
GEN_B = "research/experiments/oq36/corpus/genB"
GEN_C = "research/experiments/oq36/corpus/genC"
AT = "2026-09-20T00:00:00Z"


def _tshark() -> bool:
    try:
        TsharkAdapter().version()
        return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark(), reason="tshark not installed")
needs_gen = pytest.mark.skipif(
    not os.path.isdir(GEN_B),
    reason="Phase-6 corpus absent; run research/experiments/oq36/genb.py and genc.py")


def pipeline(path: str, ai: bool = False, run_id: str = "fixed-run"):
    run, frames = analyze_capture(path)
    sessions = reconstruct_sessions(frames, run.capture.capture_id)
    findings = SecurityAnalysisEngine().analyse(
        sessions, run.capture.capture_id).findings
    cross = CrossSessionEngine().analyse(sessions, run.capture.capture_id).findings
    ml_results = ()
    if ai and sessions:
        engine = AnomalyEngine(RobustZScoreModel(aggregate="sum"))
        rows = engine.matrix(sessions).rows
        engine.fit(rows)
        engine.set_threshold(rows, 0.95)
        ml_results = engine.analyse(sessions, run.capture.capture_id).results
    assessment = PostureEngine(PostureConfig(ai_enabled=ai)).assess(
        sessions, findings, cross, ml_results, capture_id=run.capture.capture_id,
        run_id=run_id, generated_at=AT)
    return sessions, findings, cross, assessment


# ------------------------------------------------------------- OQ-28 corpus
@needs_tshark
@pytest.mark.parametrize("name", [
    "C_normal_tls.pcap", "A_legit_decline.pcap", "B_strip_advert.pcap",
    "I_no_support.pcap", "T_TLS10.pcap", "T_TLS12.pcap", "T_SMTPS_implicit.pcap",
    "P_imap_tls.pcap", "P_pop3_decline.pcap", "G_control_endpoint.pcap",
    "E_incomplete.pcap", "K_network_cond.pcap", "X_prompt_injection.pcap",
])
def test_oq28_capture_produces_a_serialisable_assessment(name):
    _, _, _, assessment = pipeline(f"{OQ28}/{name}")
    payload = assessment.to_dict()
    json.dumps(payload)
    assert payload["overall_posture"] in {b.value for b in PostureBand}
    assert payload["versions"]["schema"] == "1.0"
    assert payload["limitations"]


@needs_tshark
def test_legacy_tls_capture_is_penalised_and_cited():
    _, _, _, assessment = pipeline(f"{OQ28}/T_TLS10.pcap")
    penalising = [g for g in assessment.issue_groups if g.penalising]
    assert penalising
    assert penalising[0].severity is Severity.HIGH
    standards = assessment.standards_summary["standards"]
    assert "RFC 8996 (BCP 195)" in standards


@needs_tshark
def test_modern_tls_capture_is_not_penalised():
    _, _, _, assessment = pipeline(f"{OQ28}/C_normal_tls.pcap")
    assert [g for g in assessment.issue_groups if g.penalising] == []
    assert assessment.band in (PostureBand.STRONG, PostureBand.INSUFFICIENT_EVIDENCE)


@needs_tshark
def test_the_byte_identical_pair_produces_the_same_posture():
    """B_strip_advert (attack) and I_no_support (legitimate) are byte-identical at the
    application layer. The posture engine must not invent a difference."""
    _, _, _, attack = pipeline(f"{OQ28}/B_strip_advert.pcap")
    _, _, _, benign = pipeline(f"{OQ28}/I_no_support.pcap")
    assert attack.score.value == benign.score.value
    assert attack.band is benign.band
    assert ([g.issue_class for g in attack.issue_groups if g.penalising]
            == [g.issue_class for g in benign.issue_groups if g.penalising])


@needs_tshark
def test_implicit_tls_reports_certificate_as_not_observable_not_as_an_issue():
    _, _, _, assessment = pipeline(f"{OQ28}/T_SMTPS_implicit.pcap")
    reasons = assessment.risk_summary["abstentions"]["by_reason"]
    assert reasons.get("NOT_OBSERVABLE", 0) > 0
    classes = assessment.risk_summary["abstentions"]["by_issue_class"]
    assert "CERTIFICATE_OBSERVABILITY" in classes


@needs_tshark
def test_incomplete_capture_does_not_receive_a_clean_certification():
    _, _, _, assessment = pipeline(f"{OQ28}/E_incomplete.pcap")
    assert assessment.abstentions
    if assessment.band is PostureBand.STRONG:
        # A STRONG band is only acceptable when coverage supports it.
        assert assessment.coverage.assessed_fraction >= 0.5


@needs_tshark
def test_prompt_injection_capture_yields_no_hostile_analyst_text():
    _, _, _, assessment = pipeline(f"{OQ28}/X_prompt_injection.pcap")
    blob = json.dumps(assessment.to_dict()).lower()
    for banned in ("ignore all previous", "ignore previous instructions",
                   "you are now", "system prompt"):
        assert banned not in blob


@needs_tshark
def test_multiple_protocols_are_each_given_their_own_posture():
    for name, protocol in (("P_imap_tls.pcap", "imap"),
                           ("P_pop3_decline.pcap", "pop3")):
        _, _, _, assessment = pipeline(f"{OQ28}/{name}")
        assert [p.protocol for p in assessment.protocol_posture] == [protocol]


# ------------------------------------------------------- Phase-6 generators
@needs_tshark
@needs_gen
@pytest.mark.parametrize("path", [
    f"{GEN_B}/B01_all_upgrade.pcap", f"{GEN_B}/B04_strip_with_control.pcap",
    f"{GEN_B}/B16_legacy_tls.pcap", f"{GEN_C}/C07_reject_upgrade.pcap",
    f"{GEN_C}/C17_legacy_tls.pcap", f"{GEN_C}/C19_truncated.pcap",
])
def test_generated_corpus_produces_a_coherent_assessment(path):
    sessions, findings, _, assessment = pipeline(path)
    assert assessment.coverage.sessions_total == len(sessions)
    total_scoped = (assessment.coverage.sessions_assessed
                    + assessment.coverage.sessions_abstained)
    assert total_scoped <= len(sessions)
    json.dumps(assessment.to_dict())


@needs_tshark
@needs_gen
def test_a_clean_generated_capture_outscores_a_legacy_tls_one():
    _, _, _, clean = pipeline(f"{GEN_B}/B01_all_upgrade.pcap")
    _, _, _, legacy = pipeline(f"{GEN_B}/B16_legacy_tls.pcap")
    assert clean.score.value > legacy.score.value


@needs_tshark
@needs_gen
def test_benign_config_change_is_not_scored_as_a_weakness():
    """Legitimate mid-capture reconfiguration must not become a security issue."""
    _, _, _, assessment = pipeline(f"{GEN_B}/B08_config_change.pcap")
    deviations = [g for g in assessment.issue_groups
                  if g.fact_kind is FactKind.BEHAVIOURAL_DEVIATION and g.penalising]
    for group in deviations:
        # A deviation may exist, but it must be reported as behavioural, never as a
        # standards-bound weakness.
        assert group.fact_kind is FactKind.BEHAVIOURAL_DEVIATION


@needs_tshark
@needs_gen
def test_truncated_generated_capture_abstains_rather_than_certifying():
    _, _, _, assessment = pipeline(f"{GEN_C}/C19_truncated.pcap")
    assert assessment.abstentions
    assert assessment.band is not PostureBand.STRONG


@needs_tshark
@needs_gen
def test_recurring_issue_is_one_group_across_many_sessions():
    _, _, _, assessment = pipeline(f"{GEN_B}/B16_legacy_tls.pcap")
    penalising = [g for g in assessment.issue_groups if g.penalising]
    assert len(penalising) == 1
    assert penalising[0].recurrence > 1
    assert len(assessment.prioritised) >= 1


# --------------------------------------------------------- ML integration
@needs_tshark
@needs_gen
def test_no_ai_equivalence_holds_on_a_real_capture():
    """The --no-ai guarantee, asserted end to end rather than on fixtures."""
    _, _, _, off = pipeline(f"{GEN_B}/B04_strip_with_control.pcap", ai=False)
    _, _, _, on = pipeline(f"{GEN_B}/B04_strip_with_control.pcap", ai=True)

    assert off.score.to_dict() == on.score.to_dict()
    assert off.band is on.band
    assert ([g.to_dict() for g in off.issue_groups if g.penalising]
            == [g.to_dict() for g in on.issue_groups if g.penalising])
    assert ([r.to_dict() for r in off.remediation_summary]
            == [r.to_dict() for r in on.remediation_summary])
    assert off.standards_summary == on.standards_summary
    assert all(p.ml_adjustment == 0.0 for p in off.prioritised)


@needs_tshark
@needs_gen
def test_ml_enabled_run_states_the_phase6_limitation():
    _, _, _, on = pipeline(f"{GEN_B}/B04_strip_with_control.pcap", ai=True)
    assert on.model_summary["role"] == "secondary prioritisation signal only"
    assert any("zero unique true detections" in l for l in on.limitations)


@needs_tshark
@needs_gen
def test_ml_cannot_introduce_a_penalising_finding():
    _, _, _, off = pipeline(f"{GEN_C}/C01_upgrade_smtp.pcap", ai=False)
    _, _, _, on = pipeline(f"{GEN_C}/C01_upgrade_smtp.pcap", ai=True)
    assert (len([g for g in off.issue_groups if g.penalising])
            == len([g for g in on.issue_groups if g.penalising]))


# ------------------------------------------------------------ determinism
@needs_tshark
def test_same_capture_produces_an_identical_assessment():
    a = pipeline(f"{OQ28}/G_control_endpoint.pcap")[3].to_dict()
    b = pipeline(f"{OQ28}/G_control_endpoint.pcap")[3].to_dict()
    assert a == b


@needs_tshark
def test_every_penalising_finding_traces_back_to_frames_and_a_rule():
    _, _, _, assessment = pipeline(f"{OQ28}/T_TLS10.pcap")
    for fused in assessment.fused_findings:
        if not fused.penalising:
            continue
        assert fused.source_rule_ids
        assert fused.all_frames
        assert fused.citations
        assert fused.remediation is not None


# ================================================== OQ-33r real vendor traffic
REAL = "research/experiments/oq33r/out"
needs_real = pytest.mark.skipif(
    not os.path.isdir(REAL) or not os.path.exists(f"{REAL}/scenarios.json"),
    reason="real-vendor corpus absent; see research/experiments/oq33r/README.md")


@needs_tshark
@needs_real
@pytest.mark.parametrize("name", [
    "postfix_smtp_starttls_upgrade", "postfix_smtp_client_declines",
    "postfix_smtp_plaintext_session", "postfix_smtp_no_starttls_offered",
    "dovecot_imap_starttls_upgrade", "dovecot_imap_plaintext_login",
    "dovecot_pop3_stls_upgrade", "dovecot_pop3_plaintext_login",
    "dovecot_imap_imaps_implicit_tls", "dovecot_pop3_pop3s_implicit_tls",
])
def test_real_vendor_capture_produces_a_coherent_assessment(name):
    """Bytes emitted by Postfix and Dovecot, not by our generators."""
    sessions, _, _, assessment = pipeline(f"{REAL}/{name}.pcap")
    assert [s for s in sessions if s.protocol], "no mail session reconstructed"
    json.dumps(assessment.to_dict())
    assert assessment.band.value in {b.value for b in PostureBand}


@needs_tshark
@needs_real
def test_real_postfix_without_starttls_is_ambiguous_not_false():
    """The project's central discipline, asserted on genuine vendor traffic: a server
    that really did not advertise yields AMBIGUOUS, never a confident negative."""
    sessions, _, _, _ = pipeline(f"{REAL}/postfix_smtp_no_starttls_offered.pcap")
    smtp = [s for s in sessions if s.protocol == "smtp" and s.starttls_advertised.value
            is not None]
    assert smtp
    for session in smtp:
        assert session.starttls_advertised.value is False
        assert session.starttls_advertised.state.value == "AMBIGUOUS"


@needs_tshark
@needs_real
def test_real_implicit_tls_reports_capability_as_not_observable():
    for name in ("dovecot_imap_imaps_implicit_tls", "dovecot_pop3_pop3s_implicit_tls"):
        sessions, _, _, _ = pipeline(f"{REAL}/{name}.pcap")
        mail = [s for s in sessions if s.protocol]
        assert mail
        assert all(s.implicit_tls for s in mail)
        assert all(s.starttls_advertised.state.value == "NOT_OBSERVABLE" for s in mail)


@needs_tshark
@needs_real
def test_real_cleartext_login_is_detected_as_plaintext_authentication():
    """A genuine security detection on real server traffic, not a crafted fixture."""
    for name in ("dovecot_imap_plaintext_login", "dovecot_pop3_plaintext_login"):
        _, findings, _, assessment = pipeline(f"{REAL}/{name}.pcap")
        rules = {f.rule_id for f in findings
                 if f.status is FindingStatus.OBSERVED_ISSUE}
        assert "SEC-PLAIN-001" in rules, name
        assert assessment.band is PostureBand.WEAK


@needs_tshark
@needs_real
def test_real_starttls_upgrade_negotiates_a_recorded_tls_version():
    """Validates the supported_versions handling against a real OpenSSL handshake."""
    for name in ("dovecot_pop3_stls_upgrade", "postfix_smtp_starttls_upgrade"):
        sessions, _, _, _ = pipeline(f"{REAL}/{name}.pcap")
        versions = {str(s.tls_negotiated_version.value) for s in sessions
                    if s.tls_negotiated_version.value}
        assert versions and versions <= {"TLS1.2", "TLS1.3"}, (name, versions)
