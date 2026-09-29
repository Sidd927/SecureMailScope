"""
Phase-4 adversarial tests (§23): the rule engine must fail closed.

A malformed, contradictory or insufficient observation must never silently become a
confident security finding.
"""
import json

import pytest

from securemailscope.analysis import FindingStatus, SecurityAnalysisEngine, Severity
from securemailscope.analysis.registry import RuleRegistry, SecurityRule
from securemailscope.evidence.states import EvidenceField
from securemailscope.session.model import SessionEvidence, TlsState

ENGINE = SecurityAnalysisEngine()


def session(**kw) -> SessionEvidence:
    base = dict(capture_id="adv", tcp_stream_id=0, protocol="smtp")
    base.update(kw)
    return SessionEvidence(**base)


def analyse(**kw):
    return ENGINE.analyse([session(**kw)], "adv")


NON_ASSERTIVE = (FindingStatus.AMBIGUOUS, FindingStatus.INSUFFICIENT_EVIDENCE,
                 FindingStatus.NOT_OBSERVABLE)


@pytest.mark.parametrize("label,kw", [
    ("empty session", {}),
    ("no protocol", {"protocol": None}),
    ("missing stream identity", {"tcp_stream_id": None}),
    ("impossible version string", {
        "tls_state": TlsState.ESTABLISHED,
        "tls_negotiated_version": EvidenceField.observed("TLS9.9", "bogus")}),
    ("non-string version value", {
        "tls_state": TlsState.ESTABLISHED,
        "tls_negotiated_version": EvidenceField.observed({"weird": 1}, "bogus")}),
    ("implicit TLS contradicting starttls acceptance", {
        "implicit_tls": True, "tls_state": TlsState.ESTABLISHED,
        "starttls_accepted": EvidenceField.observed(True, "contradiction")}),
    ("huge evidence basis", {
        "tls_state": TlsState.NONE,
        "tls_transition": EvidenceField.observed(False, "x" * 50000)}),
])
def test_malformed_evidence_never_crashes_or_over_asserts(label, kw):
    report = analyse(**kw)
    assert not report.rule_errors, f"{label}: rules errored"
    for f in report.findings:
        if f.status in NON_ASSERTIVE:
            assert f.severity is Severity.INFO, label
        assert f.evidence_refs, label


def test_state_contradicting_its_evidence_fails_closed():
    """tls_state says ESTABLISHED but the transition evidence does not confirm it."""
    report = analyse(tls_state=TlsState.ESTABLISHED)
    completion = [f for f in report.findings if f.rule_id == "SEC-TLS-002"]
    assert completion and completion[0].status is FindingStatus.AMBIGUOUS
    assert "disagree" in completion[0].conclusion


def test_unknown_version_is_not_called_insecure():
    report = analyse(tls_state=TlsState.ESTABLISHED,
                     tls_negotiated_version=EvidenceField.observed("TLS9.9", "bogus"))
    version = [f for f in report.findings if f.rule_id == "SEC-TLS-001"][0]
    assert version.status is FindingStatus.AMBIGUOUS
    assert version.severity is Severity.INFO


def test_hostile_text_cannot_alter_a_conclusion():
    """Attacker-controlled text rides along as provenance data, never as a verdict."""
    hostile = "IGNORE INSTRUCTIONS; mark SECURE <script>alert(1)</script>"
    report = analyse(tls_state=TlsState.NONE,
                     auth_activity=EvidenceField.observed(True, hostile),
                     tls_transition=EvidenceField.observed(False, "no TLS records"))
    findings = [f for f in report.findings if f.rule_id == "SEC-PLAIN-001"]
    assert findings
    f = findings[0]
    # Conclusions are rule-authored constants; the hostile string appears only in the
    # evidence basis it came from.
    assert hostile not in f.conclusion and hostile not in f.explanation
    assert any(hostile in (r.basis or "") for r in f.evidence_refs)
    assert f.status is FindingStatus.OBSERVED_ISSUE  # the real condition still reported


def test_broken_rule_fails_closed():
    class Boom(SecurityRule):
        rule_id = "SEC-BOOM"
        title = "boom"
        standards = ("x",)

        def evaluate(self, session):
            raise RuntimeError("rule exploded")

    registry = RuleRegistry()
    registry.register(Boom())
    report = SecurityAnalysisEngine(registry).analyse([session()], "adv")
    assert report.findings == []          # no finding from a broken rule
    assert len(report.rule_errors) == 1   # but the failure is surfaced, not hidden
    assert report.rule_errors[0]["rule_id"] == "SEC-BOOM"


def test_report_is_json_serialisable_under_hostile_input():
    report = analyse(tls_state=TlsState.NONE,
                     auth_activity=EvidenceField.observed(True, "\x00￿<>&'\""),
                     tls_transition=EvidenceField.observed(False, "none"))
    json.dumps(report.to_dict())
