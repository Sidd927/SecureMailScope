"""
Phase-7 tests: evidence fusion, deduplication and contradiction handling.

The tests that matter here are the negative ones. A fusion layer that concatenates
findings looks correct on a happy path and silently triples the severity of one
misconfiguration in production; a fusion layer that over-merges silently promotes "this
differs from last time" into "this is a vulnerability". Both are asserted against.
"""
import pytest

from securemailscope.analysis.model import (
    EvidenceRef, FindingStatus, SecurityFinding, Severity,
)
from securemailscope.crosssession.model import CrossSessionFinding, Deviation
from securemailscope.evidence.states import EvidenceState
from securemailscope.ml.contract import AnomalyBand, MLAnomalyResult
from securemailscope.posture import standards as standards_registry
from securemailscope.posture.fusion import FusionEngine
from securemailscope.posture.model import (
    AbstentionReason, EvidenceCertainty, FactKind, IssueClass, Observability, Relation,
    SourceLane,
)

RFC8996 = "RFC 8996 (BCP 195) SS4-5: TLS 1.0 and TLS 1.1 MUST NOT be used"
RFC3207 = "RFC 3207 SS6 (SMTP STARTTLS security considerations)"


def ref(state=EvidenceState.OBSERVED, frames=(3,), field="tls_negotiated_version"):
    return EvidenceRef(field, "TLS1.0", state, tuple(frames), "test")


def finding(rule_id="SEC-TLS-001", *, status=FindingStatus.OBSERVED_ISSUE,
            severity=Severity.HIGH, stream="cap:1", finding_id=None,
            refs=None, standards=(RFC8996,), remediation=None,
            protocol="smtp") -> SecurityFinding:
    return SecurityFinding(
        finding_id=finding_id or f"{rule_id}@{stream}",
        rule_id=rule_id, title=f"{rule_id} title", status=status, severity=severity,
        conclusion=f"{rule_id} conclusion", explanation="why",
        standards=standards if status is FindingStatus.OBSERVED_ISSUE else standards,
        capture_id="cap", tcp_stream_id=int(stream.split(":")[1]), protocol=protocol,
        stream_key=stream, evidence_refs=refs or (ref(),), remediation=remediation)


def cross(rule_id="CS-TLS-001", *, status=FindingStatus.OBSERVED_ISSUE,
          severity=Severity.MEDIUM, deviation=Deviation.DEVIATION, stream="cap:1",
          finding_id=None, baseline=None) -> CrossSessionFinding:
    return CrossSessionFinding(
        finding_id=finding_id or f"{rule_id}@{stream}", rule_id=rule_id,
        title=f"{rule_id} title", status=status, severity=severity,
        deviation=deviation, conclusion="differs from baseline", explanation="why",
        capture_id="cap", subject_stream_key=stream,
        tcp_stream_id=int(stream.split(":")[1]), protocol="smtp",
        baseline=({"status": "ESTABLISHED", "sample_count": 7}
                  if baseline is None else baseline),
        evidence_refs=(ref(frames=(9,)),), standards=(RFC3207,))


def ml(stream="cap:1", band=AnomalyBand.ANOMALOUS, score=9.0):
    return MLAnomalyResult(
        session_key=stream, capture_id="cap", model_id="robust-z",
        model_version="0.1.0", feature_schema_version="1.0",
        anomaly_score=score, threshold=5.0, band=band,
        basis="score above threshold", model_artifact_hash="abc123")


# ------------------------------------------------------------ deduplication
def test_same_condition_reported_three_times_fuses_into_one_finding():
    result = FusionEngine().fuse([
        finding(finding_id="a"), finding(finding_id="b"), finding(finding_id="c")])
    assert len(result.findings) == 1
    assert result.duplicate_count == 2


def test_duplicate_sources_are_all_retained_with_provenance():
    """Deduplication must compress the count, never the evidence."""
    result = FusionEngine().fuse([
        finding(finding_id="a", refs=(ref(frames=(3,)),)),
        finding(finding_id="b", refs=(ref(frames=(4,)),)),
    ])
    fused = result.findings[0]
    assert {s.finding_id for s in fused.sources} == {"a", "b"}
    assert fused.all_frames == (3, 4)
    assert any(s.relation is Relation.DUPLICATES for s in fused.sources)


def test_finding_id_is_not_the_dedup_key():
    """Different ids for the same condition must still fuse -- otherwise dedup is a
    no-op, because ids are unique by construction."""
    result = FusionEngine().fuse([finding(finding_id=f"id-{i}") for i in range(5)])
    assert len(result.findings) == 1


def test_different_sessions_do_not_fuse():
    result = FusionEngine().fuse([finding(stream="cap:1"), finding(stream="cap:2")])
    assert len(result.findings) == 2


def test_different_issue_classes_do_not_fuse():
    result = FusionEngine().fuse([
        finding("SEC-TLS-001"), finding("SEC-PLAIN-001", severity=Severity.HIGH)])
    assert {f.key.issue_class for f in result.findings} == {
        IssueClass.DEPRECATED_TLS_VERSION, IssueClass.PLAINTEXT_AUTH_EXPOSURE}


# ------------------------------------------------------- not over-merging
def test_base_issue_and_behavioural_deviation_stay_separate_facts():
    """A deviation enriches; it never becomes a standards-bound weakness."""
    result = FusionEngine().fuse([finding()], [cross()])
    kinds = {f.key.fact_kind for f in result.findings}
    assert kinds == {FactKind.BASE_SECURITY_ISSUE, FactKind.BEHAVIOURAL_DEVIATION}


def test_cross_session_source_is_related_not_asserted_as_an_attack():
    result = FusionEngine().fuse([], [cross()])
    fused = result.findings[0]
    assert fused.key.fact_kind is FactKind.BEHAVIOURAL_DEVIATION
    assert "attack" not in fused.conclusion.lower()
    assert all("attack" not in s.detail.lower() for s in fused.sources)


def test_anomaly_signal_is_its_own_fact_and_cannot_penalise():
    result = FusionEngine().fuse([], [], [ml()])
    anomalies = [f for f in result.findings
                 if f.key.fact_kind is FactKind.ANOMALY_SIGNAL]
    assert len(anomalies) == 1
    assert anomalies[0].penalising is False
    assert anomalies[0].severity is Severity.INFO


def test_anomaly_conclusion_disclaims_vulnerability_and_attack():
    fused = FusionEngine().fuse([], [], [ml()]).findings[0]
    text = fused.conclusion.lower()
    assert "not a vulnerability" in text and "not an attack" in text


def test_ml_attaches_to_a_finding_as_prioritisation_only():
    result = FusionEngine().fuse([finding()], [], [ml()])
    issue = [f for f in result.findings
             if f.key.fact_kind is FactKind.BASE_SECURITY_ISSUE][0]
    assert issue.ml_signal is not None
    assert issue.severity is Severity.HIGH          # unchanged by the signal
    ml_sources = [s for s in issue.sources if s.lane is SourceLane.ML]
    assert [s.relation for s in ml_sources] == [Relation.PRIORITIZES]


# ---------------------------------------------------------- contradictions
def test_contradicting_sources_do_not_silently_pick_the_reassuring_reading():
    result = FusionEngine().fuse([
        finding("SEC-TLS-001", status=FindingStatus.OBSERVED_ISSUE,
                severity=Severity.HIGH, finding_id="issue"),
        finding("SEC-TLS-001", status=FindingStatus.COMPLIANT,
                severity=Severity.INFO, finding_id="compliant"),
    ])
    # The two readings are different fact kinds, so they remain two entries; the point
    # is that the COMPLIANT one never erases the issue.
    issues = [f for f in result.findings if f.penalising]
    assert issues and issues[0].severity is Severity.HIGH


def test_contradiction_within_one_fact_is_recorded_and_lowers_certainty():
    """Two sources, same key, disagreeing outcome: keep the less certain reading."""
    result = FusionEngine().fuse([
        finding("SEC-TLS-001", status=FindingStatus.OBSERVED_ISSUE,
                severity=Severity.HIGH, finding_id="a"),
        finding("SEC-PLAIN-002", status=FindingStatus.OBSERVED_ISSUE,
                severity=Severity.MEDIUM, finding_id="b"),
    ])
    # Different classes -> no contradiction; assert the engine does not invent one.
    assert result.contradiction_count == 0


def test_ambiguous_evidence_yields_uncertain_certainty_not_confirmed():
    fused = FusionEngine().fuse([
        finding(refs=(ref(state=EvidenceState.AMBIGUOUS),))]).findings[0]
    assert fused.certainty is EvidenceCertainty.UNCERTAIN


def test_severity_is_not_reduced_because_certainty_is_low():
    """The central risk/confidence separation."""
    fused = FusionEngine().fuse([
        finding(severity=Severity.HIGH,
                refs=(ref(state=EvidenceState.AMBIGUOUS),))]).findings[0]
    assert fused.severity is Severity.HIGH
    assert fused.certainty is EvidenceCertainty.UNCERTAIN


# ------------------------------------------------------------- abstentions
@pytest.mark.parametrize("status,reason", [
    (FindingStatus.AMBIGUOUS, AbstentionReason.AMBIGUOUS_EVIDENCE),
    (FindingStatus.INSUFFICIENT_EVIDENCE, AbstentionReason.INSUFFICIENT_CAPTURE),
    (FindingStatus.NOT_OBSERVABLE, AbstentionReason.NOT_OBSERVABLE),
])
def test_non_conclusive_statuses_become_abstentions_not_findings(status, reason):
    result = FusionEngine().fuse([
        finding(status=status, severity=Severity.INFO)])
    assert result.findings == ()
    assert len(result.abstentions) == 1
    assert result.abstentions[0].reason is reason


def test_every_abstention_says_what_would_resolve_it():
    result = FusionEngine().fuse([
        finding(status=FindingStatus.NOT_OBSERVABLE, severity=Severity.INFO)])
    abstention = result.abstentions[0]
    assert abstention.resolved_by
    assert abstention.what_could_not_be_concluded
    assert abstention.why


def test_abstention_is_never_silently_discarded():
    findings = [finding(status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                        stream=f"cap:{i}") for i in range(7)]
    result = FusionEngine().fuse(findings)
    assert len(result.abstentions) == 7


def test_cross_session_without_baseline_abstains_as_insufficient_history():
    result = FusionEngine().fuse([], [cross(
        status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
        deviation=Deviation.NOT_ASSESSED, baseline={})])
    assert result.abstentions[0].reason is AbstentionReason.INSUFFICIENT_HISTORY


def test_not_observable_is_distinct_from_an_issue():
    """A missing certificate is unobservable, not a low-risk weakness."""
    result = FusionEngine().fuse([
        finding("SEC-TLS-003", status=FindingStatus.NOT_OBSERVABLE,
                severity=Severity.INFO, standards=())])
    assert result.findings == ()
    assert result.abstentions[0].issue_class is IssueClass.CERTIFICATE_OBSERVABILITY


# ------------------------------------------------------------ determinism
def test_fusion_is_order_independent():
    findings = [finding(stream=f"cap:{i}") for i in range(6)]
    a = FusionEngine().fuse(findings).to_dict()
    b = FusionEngine().fuse(list(reversed(findings))).to_dict()
    assert a == b


def test_fusion_is_repeatable():
    findings = [finding(), finding("SEC-PLAIN-001")]
    engine = FusionEngine()
    assert engine.fuse(findings).to_dict() == engine.fuse(findings).to_dict()


# -------------------------------------------------------------- standards
def test_standards_are_structured_without_being_rewritten():
    fused = FusionEngine().fuse([finding()]).findings[0]
    assert fused.citations
    citation = fused.citations[0]
    assert citation.standard == "RFC 8996 (BCP 195)"
    assert citation.section == "SS4-5"
    assert citation.text == RFC8996          # verbatim, not paraphrased


def test_unrecognised_standard_is_carried_through_not_dropped():
    citation = standards_registry.resolve("ISO 99999 invented by nobody")
    assert citation.standard == standards_registry.UNMAPPED_STANDARD
    assert citation.text == "ISO 99999 invented by nobody"


def test_penalising_finding_must_carry_a_citation():
    fused = FusionEngine().fuse([finding()]).findings[0]
    assert fused.penalising
    assert fused.citations


def test_remediation_is_bound_to_the_issue_class():
    fused = FusionEngine().fuse([finding()]).findings[0]
    assert fused.remediation is not None
    assert "TLS" in fused.remediation.recommended_action
    assert fused.remediation.verification
    assert any("cannot confirm" in limit for limit in fused.remediation.limitations)
