"""
Phase-7 tests: posture engine, scoring, prioritisation, coverage and the --no-ai
equivalence guarantee.

The monotonicity tests are property tests in spirit: they assert relationships that must
hold for *any* input, not outcomes for one fixture. A scoring function that happens to
produce sensible numbers on the demo capture and improves when a HIGH issue is added is
worse than no score at all.
"""
import pytest

from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.ml.contract import AnomalyBand
from securemailscope.posture import (
    MAX_ML_ADJUSTMENT, MIN_ASSESSED_FRACTION, PostureBand, PostureConfig, PostureEngine,
    SEVERITY_WEIGHT, band_for, compute_score,
)
from securemailscope.posture import risk as risk_module
from securemailscope.posture.fusion import FusionEngine
from securemailscope.posture.model import (
    EvidenceCertainty, FactKind, IssueClass, RiskDimension,
)
from securemailscope.session.model import (
    Completeness, SessionEvidence, TlsState, TransportRole,
)
from securemailscope.evidence.states import EvidenceField

from test_posture_fusion import cross, finding, ml, ref

ENGINE = PostureEngine()
AT = "2026-09-20T00:00:00Z"


def session(stream=1, protocol="smtp", complete=True) -> SessionEvidence:
    return SessionEvidence(
        capture_id="cap", tcp_stream_id=stream, protocol=protocol,
        client_ip="10.0.0.5", client_port=40000 + stream,
        server_ip="10.0.0.80", server_port=587,
        first_frame=1, last_frame=10, start_epoch=1000.0 + stream,
        end_epoch=1001.0 + stream, packet_count=10,
        transport_flags=(TransportRole.SETUP_OBSERVED, TransportRole.TEARDOWN_OBSERVED),
        completeness=Completeness.COMPLETE if complete else Completeness.INCOMPLETE,
        tls_state=TlsState.ESTABLISHED)


def groups_for(findings, cross_findings=()):
    fused = FusionEngine().fuse(findings, cross_findings, ()).findings
    return risk_module.group_findings(fused)


def score_of(findings, cross_findings=()):
    return compute_score(groups_for(findings, cross_findings)).value


# --------------------------------------------------------- score properties
def test_score_is_decomposable_into_its_components():
    score = compute_score(groups_for([finding(), finding("SEC-PLAIN-001")]))
    assert score.components
    assert score.value == pytest.approx(
        score.starting_value - sum(c.penalty for c in score.components))


def test_adding_a_confirmed_high_issue_never_improves_the_score():
    base = [finding("SEC-STLS-001", severity=Severity.MEDIUM)]
    worse = base + [finding("SEC-PLAIN-001", severity=Severity.HIGH, stream="cap:2")]
    assert score_of(worse) <= score_of(base)


def test_more_affected_sessions_never_improves_the_score():
    one = [finding(stream="cap:1")]
    many = [finding(stream=f"cap:{i}") for i in range(1, 12)]
    assert score_of(many) <= score_of(one)


def test_capture_length_does_not_dominate_the_score():
    """Ten times the sessions must not cost ten times the score."""
    ten = score_of([finding(stream=f"cap:{i}") for i in range(10)])
    hundred = score_of([finding(stream=f"cap:{i}") for i in range(100)])
    assert (ten - hundred) < SEVERITY_WEIGHT[Severity.MEDIUM]


def test_duplicate_findings_are_not_double_penalised():
    single = score_of([finding(finding_id="a")])
    triple = score_of([finding(finding_id="a"), finding(finding_id="b"),
                       finding(finding_id="c")])
    assert single == triple


def test_a_single_critical_is_not_averaged_away_by_benign_sessions():
    findings = [finding("SEC-TLS-001", severity=Severity.CRITICAL, stream="cap:0")]
    findings += [finding("SEC-TLS-002", status=FindingStatus.COMPLIANT,
                         severity=Severity.INFO, stream=f"cap:{i}")
                 for i in range(1, 60)]
    assert score_of(findings) < 75.0


def test_higher_severity_costs_more():
    medium = score_of([finding("SEC-STLS-001", severity=Severity.MEDIUM)])
    high = score_of([finding("SEC-PLAIN-001", severity=Severity.HIGH)])
    critical = score_of([finding("SEC-TLS-001", severity=Severity.CRITICAL)])
    assert critical < high < medium


def test_compliant_evidence_never_credits_the_score():
    clean = compute_score(groups_for([
        finding("SEC-TLS-002", status=FindingStatus.COMPLIANT,
                severity=Severity.INFO)]))
    assert clean.value == 100.0
    assert clean.components == ()


def test_unknown_formula_is_rejected():
    with pytest.raises(ValueError, match="unknown scoring formula"):
        compute_score((), None, "F9-imaginary")


def test_bands_follow_the_documented_thresholds():
    assert band_for(95.0) is PostureBand.STRONG
    assert band_for(80.0) is PostureBand.ADEQUATE
    assert band_for(60.0) is PostureBand.WEAK
    assert band_for(10.0) is PostureBand.CRITICAL


# ------------------------------------------------- missing evidence handling
def test_no_assessable_session_is_not_graded_well():
    """Blindness must not be indistinguishable from security."""
    assessment = ENGINE.assess([session()], [], [], capture_id="cap", generated_at=AT)
    assert assessment.band is PostureBand.INSUFFICIENT_EVIDENCE


def test_sparse_coverage_withholds_certification_but_keeps_the_score():
    sessions = [session(i) for i in range(10)]
    # Only two sessions yield a conclusion; the rest are unassessed.
    findings = [finding(stream=f"cap:{i}") for i in range(2)]
    assessment = ENGINE.assess(sessions, findings, [], capture_id="cap",
                               generated_at=AT)
    assert assessment.coverage.assessed_fraction < MIN_ASSESSED_FRACTION
    assert assessment.band is PostureBand.INSUFFICIENT_EVIDENCE
    assert assessment.score.value > 0.0          # the arithmetic is untouched


def test_abstentions_are_reported_and_summarised_not_discarded():
    findings = [finding(status=FindingStatus.NOT_OBSERVABLE, severity=Severity.INFO,
                        stream=f"cap:{i}") for i in range(5)]
    assessment = ENGINE.assess([session(i) for i in range(5)], findings,
                               capture_id="cap", generated_at=AT)
    assert len(assessment.abstentions) == 5
    assert assessment.risk_summary["abstentions"]["total"] == 5
    assert assessment.risk_summary["abstentions"]["how_to_resolve"]


def test_evidence_coverage_reports_observation_state_fractions():
    assessment = ENGINE.assess([session(i) for i in range(4)],
                               [finding(stream=f"cap:{i}") for i in range(4)],
                               capture_id="cap", generated_at=AT)
    fractions = assessment.coverage.observation_fractions
    assert fractions
    assert abs(sum(fractions.values()) - 1.0) < 0.01


# -------------------------------------------------------------- priority
def test_priority_is_not_merely_severity():
    """A recurring, confirmed, actionable MEDIUM can outrank a one-off MEDIUM."""
    recurring = [finding("SEC-STLS-001", severity=Severity.MEDIUM,
                         stream=f"cap:{i}") for i in range(20)]
    single = [finding("SEC-PLAIN-002", severity=Severity.MEDIUM, stream="cap:99")]
    assessment = ENGINE.assess([session(i) for i in range(21)],
                               recurring + single, capture_id="cap", generated_at=AT)
    ranks = {p.finding.key.issue_class: p.rank for p in assessment.prioritised}
    assert ranks[IssueClass.STARTTLS_UPGRADE_FAILURE] < ranks[IssueClass.NO_TLS_PROTECTION]


def test_priority_does_not_decrease_when_more_sessions_are_affected():
    def priority(n):
        findings = [finding(stream=f"cap:{i}") for i in range(n)]
        a = ENGINE.assess([session(i) for i in range(n)], findings,
                          capture_id="cap", generated_at=AT)
        return a.prioritised[0].priority_score
    assert priority(20) >= priority(1)


def test_severity_tiers_are_never_crossed_by_other_factors():
    high = [finding("SEC-PLAIN-001", severity=Severity.HIGH, stream="cap:1")]
    mediums = [finding("SEC-STLS-001", severity=Severity.MEDIUM,
                       stream=f"cap:{i}") for i in range(2, 60)]
    assessment = ENGINE.assess([session(i) for i in range(60)], high + mediums,
                               capture_id="cap", generated_at=AT)
    assert assessment.prioritised[0].finding.severity is Severity.HIGH


def test_one_prioritised_entry_per_issue_group_not_per_session():
    findings = [finding(stream=f"cap:{i}") for i in range(30)]
    assessment = ENGINE.assess([session(i) for i in range(30)], findings,
                               capture_id="cap", generated_at=AT)
    assert len(assessment.prioritised) == 1
    assert assessment.prioritised[0].affected_sessions == 30
    assert len(assessment.fused_findings) == 30      # every session still retained


def test_every_prioritised_entry_explains_itself():
    assessment = ENGINE.assess([session()], [finding()], capture_id="cap",
                               generated_at=AT)
    for item in assessment.prioritised:
        assert item.explanation
        assert item.factors


# -------------------------------------------------------- --no-ai equivalence
def _pair(sessions, findings, cross_findings, ml_results):
    off = PostureEngine(PostureConfig(ai_enabled=False)).assess(
        sessions, findings, cross_findings, ml_results, capture_id="cap",
        generated_at=AT)
    on = PostureEngine(PostureConfig(ai_enabled=True)).assess(
        sessions, findings, cross_findings, ml_results, capture_id="cap",
        generated_at=AT)
    return off, on


def test_disabling_ai_leaves_security_facts_identical():
    sessions = [session(i) for i in range(3)]
    findings = [finding(stream=f"cap:{i}") for i in range(3)]
    ml_results = [ml(stream=f"cap:{i}") for i in range(3)]
    off, on = _pair(sessions, findings, [], ml_results)

    assert off.score.to_dict() == on.score.to_dict()
    assert off.band is on.band
    # Every group that can affect the score must be identical. The AI-enabled run may
    # carry an extra non-penalising ANOMALY group; it must not carry anything else.
    assert ([g.to_dict() for g in off.issue_groups if g.penalising]
            == [g.to_dict() for g in on.issue_groups if g.penalising])
    extra = ({(g.issue_class, g.fact_kind) for g in on.issue_groups}
             - {(g.issue_class, g.fact_kind) for g in off.issue_groups})
    assert all(kind is FactKind.ANOMALY_SIGNAL for _, kind in extra), extra

    # The risk summary may differ ONLY in ML bookkeeping. Asserting the exact set of
    # differing keys is stronger than asserting equality of a hand-picked subset: if a
    # future change let the ML lane touch a security count, this fails.
    differing = {k for k in off.risk_summary
                 if off.risk_summary[k] != on.risk_summary.get(k)}
    assert differing <= {"anomaly_signals", "by_fact_kind"}, differing
    for key in ("issue_groups", "highest_severity", "by_severity", "by_dimension",
                "affected_sessions", "behavioural_deviations", "positive_evidence"):
        assert off.risk_summary[key] == on.risk_summary[key], key
    # ANOMALY_SIGNAL is the only fact kind the ML lane may add.
    assert (set(on.risk_summary["by_fact_kind"]) - set(off.risk_summary["by_fact_kind"])
            <= {"ANOMALY_SIGNAL"})
    assert off.standards_summary == on.standards_summary
    assert ([r.to_dict() for r in off.remediation_summary]
            == [r.to_dict() for r in on.remediation_summary])


def test_disabling_ai_removes_only_prioritisation_metadata():
    sessions = [session(i) for i in range(3)]
    findings = [finding(stream=f"cap:{i}") for i in range(3)]
    off, on = _pair(sessions, findings, [], [ml(stream=f"cap:{i}") for i in range(3)])
    assert all(p.ml_adjustment == 0.0 for p in off.prioritised)
    assert off.model_summary["ai_enabled"] is False
    assert on.model_summary["ai_enabled"] is True
    assert on.model_summary["role"] == "secondary prioritisation signal only"


def test_ml_results_cannot_reach_the_engine_when_ai_is_disabled():
    sessions = [session()]
    off, _ = _pair(sessions, [finding()], [], [ml()])
    assert all(f.ml_signal is None for f in off.fused_findings)
    assert not any(f.key.fact_kind is FactKind.ANOMALY_SIGNAL
                   for f in off.fused_findings)


def test_ml_adjustment_cannot_cross_a_severity_tier():
    """The ML boundary made arithmetic: the nudge is smaller than the tier gap."""
    from securemailscope.posture.prioritise import _SEVERITY_BASE
    gaps = [_SEVERITY_BASE[Severity.HIGH] - _SEVERITY_BASE[Severity.MEDIUM],
            _SEVERITY_BASE[Severity.CRITICAL] - _SEVERITY_BASE[Severity.HIGH]]
    assert MAX_ML_ADJUSTMENT < min(gaps)


def test_ml_never_changes_severity_or_status():
    sessions = [session()]
    off, on = _pair(sessions, [finding(severity=Severity.HIGH)], [], [ml()])
    off_issue = [f for f in off.fused_findings if f.penalising][0]
    on_issue = [f for f in on.fused_findings if f.penalising][0]
    assert off_issue.severity is on_issue.severity
    assert off_issue.status is on_issue.status


def test_anomalous_session_with_no_rule_finding_does_not_penalise():
    sessions = [session()]
    on = PostureEngine(PostureConfig(ai_enabled=True)).assess(
        sessions, [], [], [ml()], capture_id="cap", generated_at=AT)
    assert on.risk_summary["issue_groups"] == 0
    assert on.risk_summary["anomaly_signals"] == 1


# ------------------------------------------------------------- determinism
def test_assessment_is_repeatable():
    sessions = [session(i) for i in range(4)]
    findings = [finding(stream=f"cap:{i}") for i in range(4)]
    a = ENGINE.assess(sessions, findings, capture_id="cap", generated_at=AT).to_dict()
    b = ENGINE.assess(sessions, findings, capture_id="cap", generated_at=AT).to_dict()
    assert a == b


def test_assessment_is_input_order_independent():
    sessions = [session(i) for i in range(5)]
    findings = [finding(stream=f"cap:{i}") for i in range(5)]
    a = ENGINE.assess(sessions, findings, capture_id="cap", generated_at=AT).to_dict()
    b = ENGINE.assess(list(reversed(sessions)), list(reversed(findings)),
                      capture_id="cap", generated_at=AT).to_dict()
    assert a == b


def test_assessment_id_is_content_addressed():
    """Independent of run id: two analyses of the same evidence must agree."""
    sessions = [session()]
    a = ENGINE.assess(sessions, [finding()], capture_id="cap", run_id="run-1",
                      generated_at=AT)
    b = ENGINE.assess(sessions, [finding()], capture_id="cap", run_id="run-2",
                      generated_at=AT)
    c = ENGINE.assess(sessions, [finding(severity=Severity.CRITICAL)],
                      capture_id="cap", generated_at=AT)
    assert a.assessment_id == b.assessment_id
    assert a.assessment_id != c.assessment_id


def test_empty_capture_produces_a_valid_assessment():
    assessment = ENGINE.assess([], [], [], capture_id="cap", generated_at=AT)
    assert assessment.band is PostureBand.INSUFFICIENT_EVIDENCE
    assert assessment.fused_findings == ()
    assert assessment.to_dict()["overall_posture"] == "INSUFFICIENT_EVIDENCE"


# ------------------------------------------------- protocol / provenance
def test_protocol_posture_is_scored_per_protocol():
    sessions = [session(1, "smtp"), session(2, "imap"), session(3, "pop3")]
    findings = [finding(stream="cap:1", protocol="smtp"),
                finding("SEC-TLS-002", status=FindingStatus.COMPLIANT,
                        severity=Severity.INFO, stream="cap:2", protocol="imap"),
                finding("SEC-TLS-002", status=FindingStatus.COMPLIANT,
                        severity=Severity.INFO, stream="cap:3", protocol="pop3")]
    assessment = ENGINE.assess(sessions, findings, capture_id="cap", generated_at=AT)
    by_protocol = {p.protocol: p for p in assessment.protocol_posture}
    assert set(by_protocol) == {"smtp", "imap", "pop3"}
    assert by_protocol["smtp"].score.value < by_protocol["imap"].score.value


def test_provenance_records_every_source_and_rule():
    assessment = ENGINE.assess([session()], [finding()], [cross()],
                               capture_id="cap", generated_at=AT)
    provenance = assessment.provenance
    assert provenance["source_counts"]["deterministic_findings"] == 1
    assert provenance["source_counts"]["cross_session_findings"] == 1
    assert set(provenance["rule_ids"]) == {"SEC-TLS-001", "CS-TLS-001"}
    assert provenance["versions"]["scoring_formula"]


def test_every_assessment_carries_the_method_limitations():
    assessment = ENGINE.assess([session()], [finding()], capture_id="cap",
                               generated_at=AT)
    joined = " ".join(assessment.limitations).lower()
    assert "attribution" in joined
    assert "passive" in joined
    assert "ambiguous" in joined


def test_ml_limitations_are_attached_only_when_ml_contributed():
    off, on = _pair([session()], [finding()], [], [ml()])
    assert not any("prioritisation signal" in l for l in off.limitations)
    assert any("zero unique true detections" in l for l in on.limitations)


def test_remediation_is_traceable_to_a_standard():
    assessment = ENGINE.assess([session()], [finding()], capture_id="cap",
                               generated_at=AT)
    assert assessment.remediation_summary
    guidance = assessment.remediation_summary[0]
    assert guidance.citations
    assert guidance.citations[0].standard == "RFC 8996 (BCP 195)"


def test_standards_summary_lists_only_rule_cited_standards():
    assessment = ENGINE.assess([session()], [finding()], [cross()],
                               capture_id="cap", generated_at=AT)
    standards = assessment.standards_summary["standards"]
    assert set(standards) <= {"RFC 8996 (BCP 195)", "RFC 3207", "RFC 2595",
                              "NIST SP 800-52r2", "RFC 8314"}
    assert assessment.standards_summary["unmapped_citations"] == []
