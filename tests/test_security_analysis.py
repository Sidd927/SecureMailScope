"""
Phase-4 tests: deterministic security analysis engine.

The most important tests here are the FORBIDDEN-SEMANTICS ones (Phase-4 §20): they
assert that the engine refuses to manufacture conclusions the evidence cannot support.
"""
import json

import pytest

from securemailscope.analysis import (
    FindingStatus, SecurityAnalysisEngine, Severity, build_default_registry,
)
from securemailscope.analysis.model import EvidenceRef, SecurityFinding
from securemailscope.dissect import TsharkAdapter
from securemailscope.evidence.states import EvidenceState
from securemailscope.ingest import analyze_capture
from securemailscope.session import reconstruct_sessions

P = "research/experiments/oq28/pcaps"


def _tshark() -> bool:
    try:
        TsharkAdapter().version(); return True
    except Exception:
        return False


needs_tshark = pytest.mark.skipif(not _tshark(), reason="tshark not installed")
ENGINE = SecurityAnalysisEngine()


def analyse(name):
    run, frames = analyze_capture(f"{P}/{name}.pcap")
    sessions = reconstruct_sessions(frames, run.capture.capture_id)
    return ENGINE.analyse(sessions, run.capture.capture_id), sessions


def rule_findings(report, rule_id):
    return [f for f in report.findings if f.rule_id == rule_id]


# ============================================================ registry / contract
def test_registry_has_unique_rule_ids():
    reg = build_default_registry()
    ids = [r.rule_id for r in reg.rules]
    assert len(ids) == len(set(ids)) == len(reg)


def test_registry_rejects_duplicate_registration():
    from securemailscope.analysis.rules import DeprecatedTlsVersionRule
    reg = build_default_registry()
    with pytest.raises(ValueError):
        reg.register(DeprecatedTlsVersionRule())


def test_finding_requires_evidence_refs():
    with pytest.raises(ValueError):
        SecurityFinding(
            finding_id="x", rule_id="R", title="t", status=FindingStatus.INFORMATIONAL,
            severity=Severity.INFO, conclusion="c", explanation="e", standards=(),
            capture_id="cap", tcp_stream_id=0, protocol="smtp", evidence_refs=())


def test_non_assertive_status_cannot_carry_severity():
    """AMBIGUOUS/INSUFFICIENT/NOT_OBSERVABLE may never assert impact (§14/§15)."""
    r = EvidenceRef("f", "v", EvidenceState.AMBIGUOUS)
    for status in (FindingStatus.AMBIGUOUS, FindingStatus.INSUFFICIENT_EVIDENCE,
                   FindingStatus.NOT_OBSERVABLE, FindingStatus.COMPLIANT):
        with pytest.raises(ValueError):
            SecurityFinding(
                finding_id="x", rule_id="R", title="t", status=status,
                severity=Severity.HIGH, conclusion="c", explanation="e",
                standards=("s",), capture_id="c", tcp_stream_id=0, protocol="smtp",
                evidence_refs=(r,))


def test_observed_issue_must_cite_standards():
    r = EvidenceRef("f", "v", EvidenceState.OBSERVED)
    with pytest.raises(ValueError):
        SecurityFinding(
            finding_id="x", rule_id="R", title="t", status=FindingStatus.OBSERVED_ISSUE,
            severity=Severity.HIGH, conclusion="c", explanation="e", standards=(),
            capture_id="c", tcp_stream_id=0, protocol="smtp", evidence_refs=(r,))


# ============================================================ TLS version rules
@needs_tshark
@pytest.mark.parametrize("name,version,status,severity", [
    ("T_TLS10", "TLS1.0", FindingStatus.OBSERVED_ISSUE, Severity.HIGH),
    ("T_TLS11", "TLS1.1", FindingStatus.OBSERVED_ISSUE, Severity.HIGH),
    ("T_TLS12", "TLS1.2", FindingStatus.COMPLIANT, Severity.INFO),
    ("C_normal_tls", "TLS1.3", FindingStatus.COMPLIANT, Severity.INFO),
])
def test_tls_version_posture(name, version, status, severity):
    report, sessions = analyse(name)
    assert sessions[0].tls_negotiated_version.value == version
    f = rule_findings(report, "SEC-TLS-001")[0]
    assert f.status is status and f.severity is severity
    assert version in f.conclusion
    if status is FindingStatus.OBSERVED_ISSUE:
        assert any("8996" in s or "800-52" in s for s in f.standards)
        assert f.remediation


@needs_tshark
def test_missing_servicehello_is_insufficient_not_insecure():
    """Absence of visible TLS version must NEVER become 'weak version' (§7)."""
    report, _ = analyse("D_failed_upgrade")
    v1 = rule_findings(report, "SEC-TLS-001")
    for f in v1:
        assert f.status in (FindingStatus.COMPLIANT, FindingStatus.INSUFFICIENT_EVIDENCE)
        if f.status is FindingStatus.INSUFFICIENT_EVIDENCE:
            assert f.severity is Severity.INFO
            assert "not" in f.conclusion.lower()


@needs_tshark
def test_handshake_completion_not_manufactured():
    """CLIENT_HELLO_OBSERVED must not become TLS_ESTABLISHED (§8)."""
    report, sessions = analyse("D_failed_upgrade")
    partial = [s for s in sessions if s.tls_state.value == "CLIENT_HELLO_OBSERVED"]
    assert partial
    for f in rule_findings(report, "SEC-TLS-002"):
        if f.status is FindingStatus.INSUFFICIENT_EVIDENCE:
            assert "not established" in f.conclusion or "could not" in f.conclusion


# ============================================================ certificate boundary
@needs_tshark
def test_certificate_validation_not_faked():
    """SEC-TLS-003 was NARROWED in Phase 11 to trust and revocation only.

    Extraction is now implemented (SEC-CERT-001..005), so the old conclusion wording
    "validation was not performed" no longer describes this rule. What it must still
    do -- and what this test now pins -- is refuse to claim trust or revocation, which
    no implementation can ever establish from a passive capture.
    """
    report, _ = analyse("C_normal_tls")
    f = rule_findings(report, "SEC-TLS-003")[0]
    assert f.status is FindingStatus.NOT_OBSERVABLE
    assert f.severity is Severity.INFO
    assert "not evaluated" in f.conclusion
    blob = json.dumps(f.to_dict()).lower()
    # the boundary is named, with the reason it is structural rather than unfinished
    assert "trust" in blob and "revocation" in blob
    assert "trust anchor" in blob
    # and no trust verdict is ever asserted
    for forbidden in ("certificate is trusted", "certificate is untrusted",
                      "chain is valid", "certificate is valid", "revoked"):
        assert forbidden not in blob, forbidden
    assert f.limitations  # boundary must be stated explicitly


# ============================================================ THE critical semantics
@needs_tshark
def test_absent_advertisement_never_becomes_stripping():
    """Forbidden: 'STARTTLS not advertised' -> 'STARTTLS stripped' (§9, §31)."""
    for name in ("B_strip_advert", "I_no_support", "P_imap_strip", "P_pop3_strip"):
        report, _ = analyse(name)
        f = rule_findings(report, "SEC-STLS-002")[0]
        assert f.status is FindingStatus.AMBIGUOUS
        assert f.severity is Severity.INFO
        blob = json.dumps(f.to_dict()).lower()
        assert "was stripped" not in blob
        assert "stripping attack" not in blob
        assert "indistinguish" in blob or "cannot separate" in blob


@needs_tshark
def test_attack_and_legitimate_produce_identical_findings():
    """B_strip_advert (attack) and I_no_support (legitimate) are byte-identical at the
    application layer; the engine must not differentiate them."""
    a, _ = analyse("B_strip_advert")
    b, _ = analyse("I_no_support")
    norm = lambda rep: sorted(
        (f.rule_id, f.status.value, f.severity.value, f.conclusion)
        for f in rep.findings)
    assert norm(a) == norm(b)


@needs_tshark
def test_implicit_tls_never_reported_as_starttls_failure():
    for name in ("T_SMTPS_implicit", "T_IMAPS_implicit", "T_POP3S_implicit"):
        report, _ = analyse(name)
        assert not rule_findings(report, "SEC-STLS-001")
        assert not rule_findings(report, "SEC-STLS-002")
        f = rule_findings(report, "SEC-STLS-003")[0]
        assert f.status is FindingStatus.INFORMATIONAL
        blob = json.dumps(f.to_dict()).lower()
        for banned in ("starttls failed", "not supported", "stripped"):
            assert banned not in blob


@needs_tshark
def test_plaintext_never_becomes_credential_theft():
    """Forbidden: cleartext AUTH -> 'credentials stolen/compromised' (§13)."""
    report, _ = analyse("B_strip_advert")
    blob = json.dumps(report.to_dict()).lower()
    for banned in ("stolen", "compromised", "credential theft", "attacker captured",
                   "exfiltrat", "harvested"):
        assert banned not in blob
    auth = rule_findings(report, "SEC-PLAIN-001")
    assert auth and auth[0].status is FindingStatus.OBSERVED_ISSUE
    assert "does not assert" in auth[0].explanation


@needs_tshark
def test_no_attacker_attribution_anywhere():
    for name in ("B_strip_advert", "J_strip_command", "A_legit_decline", "T_TLS10"):
        report, _ = analyse(name)
        blob = json.dumps(report.to_dict()).lower()
        for banned in ("attacker", "adversary performed", "malicious actor", "was attacked"):
            assert banned not in blob, f"{banned!r} in {name}"


# ============================================================ STARTTLS outcomes
@needs_tshark
def test_successful_upgrade_is_compliant_not_a_vulnerability():
    for name in ("C_normal_tls", "P_imap_tls", "P_pop3_tls"):
        report, _ = analyse(name)
        f = rule_findings(report, "SEC-STLS-001")[0]
        assert f.status is FindingStatus.COMPLIANT and f.severity is Severity.INFO


@needs_tshark
def test_rejected_upgrade_is_an_issue_but_not_an_attack():
    report, _ = analyse("J_strip_command")
    rejected = [f for f in rule_findings(report, "SEC-STLS-001")
                if f.status is FindingStatus.OBSERVED_ISSUE]
    assert rejected
    f = rejected[0]
    assert f.severity is Severity.MEDIUM
    assert "not by itself evidence of an attack" in f.explanation


@needs_tshark
def test_advertised_but_declined_is_informational():
    report, _ = analyse("A_legit_decline")
    f = rule_findings(report, "SEC-STLS-002")[0]
    assert f.status is FindingStatus.INFORMATIONAL
    assert f.severity is Severity.INFO


# ============================================================ provenance
@needs_tshark
def test_every_finding_has_traceable_evidence():
    for name in ("C_normal_tls", "B_strip_advert", "T_TLS10", "T_SMTPS_implicit"):
        report, _ = analyse(name)
        assert report.findings
        for f in report.findings:
            assert f.evidence_refs, f.rule_id
            assert f.capture_id and f.stream_key
            for r in f.evidence_refs:
                assert r.field_name and r.evidence_state in tuple(EvidenceState)


@needs_tshark
def test_findings_cite_specific_frames_where_available():
    report, _ = analyse("T_TLS10")
    version_finding = rule_findings(report, "SEC-TLS-001")[0]
    assert version_finding.all_frames, "version finding should cite the ServerHello frame"


# ============================================================ determinism
@needs_tshark
def test_engine_is_deterministic():
    a, _ = analyse("C_normal_tls")
    b, _ = analyse("C_normal_tls")
    assert json.dumps(a.to_dict(), sort_keys=True) == json.dumps(b.to_dict(), sort_keys=True)


@needs_tshark
def test_finding_ids_are_stable_across_runs():
    a, _ = analyse("T_TLS10")
    b, _ = analyse("T_TLS10")
    assert [f.finding_id for f in a.findings] == [f.finding_id for f in b.findings]


# ============================================================ no cross-session / no ML
def test_no_cross_session_or_ml_imports():
    """Inspect actual imports and identifiers, not prose: the module docstrings
    legitimately name what Phase 4 deliberately excludes."""
    import ast
    import pathlib

    import securemailscope.analysis as pkg

    banned_modules = {"sklearn", "numpy", "torch", "openai", "requests", "urllib",
                      "socket", "http"}
    banned_names = {"IsolationForest", "baseline", "control_endpoint", "anomaly_score"}
    for path in pathlib.Path(pkg.__file__).parent.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in banned_modules, (path, alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in banned_modules, (path, node.module)
            elif isinstance(node, ast.Name):
                assert node.id not in banned_names, (path, node.id)
            elif isinstance(node, ast.Attribute):
                assert node.attr not in banned_names, (path, node.attr)


@needs_tshark
def test_analysis_is_per_session_only():
    """Analysing a session alone must give the same findings as within its capture."""
    run, frames = analyze_capture(f"{P}/J_strip_command.pcap")
    sessions = reconstruct_sessions(frames, run.capture.capture_id)
    full = ENGINE.analyse(sessions, run.capture.capture_id)
    for s in sessions:
        alone = ENGINE.analyse([s], run.capture.capture_id)
        mine = [f.to_dict() for f in full.findings if f.stream_key == s.stream_key]
        assert [f.to_dict() for f in alone.findings] == mine
