"""
Phase-11 rules: honesty properties and the forbidden inferences.

Every "never turn X into Y" rule in docs/phase11/05 §8 is asserted here rather than only
documented, because a documented prohibition does not survive a refactor.
"""
import json

import pytest

from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.analysis.rules.certificate_rules import (
    CertificateChainRule, CertificateExpiryRule, CertificateKeyStrengthRule,
    CertificatePresenceRule, CertificateSignatureRule,
)
from securemailscope.analysis.rules.configuration_rules import (
    CHECKLIST, CHECKLIST_VERSION, InsecureConfigurationRule,
)
from securemailscope.analysis.rules.keyexchange_rules import (
    ForwardSecrecyRule, KeyExchangeRule,
)
from securemailscope.crypto import certificates as C
from securemailscope.evidence.states import EvidenceField
from securemailscope.session.model import SessionEvidence, TlsState

DAY = 86400
YEAR = 365 * DAY
#: A capture taken well in the past, so "expired now" and "expired then" differ.
CAPTURE_EPOCH = 1_600_000_000          # 2020-09-13


def session(**kw):
    """A TLS session with Phase-11 evidence, defaulting to a healthy TLS 1.2 state."""
    defaults = dict(
        capture_id="a" * 64, tcp_stream_id=1, protocol="smtp",
        tls_state=TlsState.ESTABLISHED, start_epoch=float(CAPTURE_EPOCH),
        tls_negotiated_version=EvidenceField.observed("TLS1.2", "ServerHello"),
        tls_forward_secrecy=EvidenceField.observed(True, "ECDHE"),
        tls_key_exchange=EvidenceField.observed("ECDHE", "suite"),
    )
    defaults.update(kw)
    return SessionEvidence(**defaults)


def cert(index=0, **kw):
    return C.CertificateEvidence(index=index, **kw)


def with_certs(certs, **kw):
    return session(
        certificates=tuple(certs),
        tls_certificate_chain=EvidenceField.observed(len(certs), "Certificate message"),
        **kw)


def blob(finding):
    return json.dumps(finding.to_dict()).lower()


#: Clause markers that make the surrounding text a DENIAL rather than a claim.
_NEGATIONS = ("not ", "never ", "cannot ", "no ", "without ", "nor ")


def affirmative(finding):
    """Finding text with every negated clause removed.

    A blunt substring search for "untrusted" matches the engine's own honest sentence
    "absence of certificate evidence is not evidence of an absent, invalid or
    untrusted certificate" -- i.e. it flags the denial as though it were the claim.
    That is a false positive in the TEST, and loosening the assertion to accommodate
    it would also stop catching the real thing.

    So the text is split into SENTENCES and any sentence carrying a negation is
    dropped before the forbidden terms are sought. An affirmative "the certificate is
    untrusted" still fails; the engine's denial of it does not.

    The scope is the sentence, not the clause: negation reaches across commas and
    colons, as in "...is not evidence of an absent, invalid or untrusted certificate",
    where clause-splitting would strand "invalid or untrusted certificate" and read a
    denial as a claim. Callers additionally assert on `conclusion` alone, which is
    short and unconditionally assertive, so the coarser scope here does not weaken the
    guarantee where it matters most.
    """
    text = " ".join(
        str(v) for v in (finding.conclusion, finding.explanation,
                         finding.remediation or "", " ".join(finding.limitations)))
    kept = [s.lower() for s in text.split(".")
            if not any(m in s.lower() for m in _NEGATIONS)]
    return " ".join(kept)


# ================================================= THE capture-timestamp rule
def test_expiry_uses_the_capture_timestamp_not_the_wall_clock():
    """THE defining test for D-12.

    This certificate expired long before today but was valid when the traffic was
    captured. A wall-clock comparison reports "expired"; the correct forensic answer
    is that it was valid during the captured session.
    """
    certificate = cert(
        not_before_epoch=CAPTURE_EPOCH - YEAR,
        not_after_epoch=CAPTURE_EPOCH + DAY,          # long past by "now"
        not_before_text="2019-09-13 00:00:00 (UTC)",
        not_after_text="2020-09-14 00:00:00 (UTC)")
    findings = CertificateExpiryRule().evaluate(with_certs([certificate]))
    assert findings[0].status is FindingStatus.COMPLIANT
    assert "expired" not in findings[0].conclusion.lower()


def test_expiry_is_reported_when_it_had_already_expired_at_capture_time():
    """The converse: a genuine expiry must still be found."""
    certificate = cert(
        not_before_epoch=CAPTURE_EPOCH - 2 * YEAR,
        not_after_epoch=CAPTURE_EPOCH - DAY,
        not_before_text="2018-09-13 00:00:00 (UTC)",
        not_after_text="2020-09-12 00:00:00 (UTC)")
    finding = CertificateExpiryRule().evaluate(with_certs([certificate]))[0]
    assert finding.status is FindingStatus.OBSERVED_ISSUE
    assert finding.severity is Severity.HIGH


def test_not_yet_valid_is_distinguished_from_expired():
    certificate = cert(
        not_before_epoch=CAPTURE_EPOCH + YEAR,
        not_after_epoch=CAPTURE_EPOCH + 2 * YEAR,
        not_before_text="2021-09-13 00:00:00 (UTC)",
        not_after_text="2022-09-13 00:00:00 (UTC)")
    finding = CertificateExpiryRule().evaluate(with_certs([certificate]))[0]
    assert finding.status is FindingStatus.OBSERVED_ISSUE
    assert "not valid until" in finding.explanation


def test_expiry_abstains_without_a_capture_timestamp():
    """No reference instant means no verdict -- the current date is NOT substituted."""
    certificate = cert(not_before_epoch=0, not_after_epoch=10,
                       not_before_text="a", not_after_text="b")
    s = with_certs([certificate], start_epoch=None)
    finding = CertificateExpiryRule().evaluate(s)[0]
    assert finding.status is FindingStatus.INSUFFICIENT_EVIDENCE
    assert "current date is" in finding.explanation


def test_expiry_findings_are_stable_across_time():
    """`assessment_id` is content-addressed: re-running an old capture must not drift.

    Any wall-clock dependence would make the same PCAP produce different findings on
    different days, which would break assessment identity outright.
    """
    certificate = cert(not_before_epoch=CAPTURE_EPOCH - DAY,
                       not_after_epoch=CAPTURE_EPOCH + DAY,
                       not_before_text="x", not_after_text="y")
    s = with_certs([certificate])
    first = CertificateExpiryRule().evaluate(s)[0].to_dict()
    second = CertificateExpiryRule().evaluate(s)[0].to_dict()
    assert first == second


# ==================================================== forbidden inferences
def test_absent_certificate_is_not_a_certificate_defect():
    """never: "certificate not visible" -> "certificate invalid"."""
    s = session(tls_negotiated_version=EvidenceField.observed("TLS1.3", "ServerHello"))
    finding = CertificatePresenceRule().evaluate(s)[0]
    assert finding.status is FindingStatus.NOT_OBSERVABLE
    assert finding.severity is Severity.INFO
    claims = affirmative(finding)
    conclusion = finding.conclusion.lower()
    for forbidden in ("certificate is invalid", "invalid certificate", "untrusted",
                      "certificate is missing", "expired", "revoked"):
        assert forbidden not in claims, forbidden
        assert forbidden not in conclusion, forbidden
    assert "rfc 8446" in blob(finding)           # the actual reason is given


def test_absence_reason_distinguishes_encrypted_from_truncated():
    """"Encrypted", "not sent" and "not captured" have different remediations."""
    encrypted = CertificatePresenceRule().evaluate(session(
        tls_negotiated_version=EvidenceField.observed("TLS1.3", "sh")))[0]
    truncated = CertificatePresenceRule().evaluate(session(
        tls_state=TlsState.HANDSHAKE_INTERRUPTED,
        tls_negotiated_version=EvidenceField.observed("TLS1.2", "sh")))[0]
    assert "encrypts" in encrypted.explanation
    assert "truncated" in truncated.explanation
    assert encrypted.explanation != truncated.explanation


def test_chain_never_claims_trust_or_revocation():
    """never: "no trust anchor" -> "untrusted"; "revocation unknown" -> "revoked"."""
    certs = [cert(0, subject_key_id="11", authority_key_id="22"),
             cert(1, subject_key_id="22", authority_key_id="22")]
    s = with_certs(certs, chain_links=(True,))
    finding = CertificateChainRule().evaluate(s)[0]
    claims = affirmative(finding)
    for forbidden in ("is trusted", "is untrusted", "chain is valid",
                      "certificate is valid", "is revoked"):
        assert forbidden not in claims, forbidden
        assert forbidden not in finding.conclusion.lower(), forbidden
    assert "trust anchor" in blob(finding)       # the boundary is named
    assert "structural" in blob(finding)


def test_broken_link_is_ambiguous_not_an_issue():
    """never: "chain incomplete in capture" -> "chain broken"."""
    certs = [cert(0, subject_key_id="11", authority_key_id="99"),
             cert(1, subject_key_id="22", authority_key_id="22")]
    finding = CertificateChainRule().evaluate(
        with_certs(certs, chain_links=(False,)))[0]
    assert finding.status is FindingStatus.AMBIGUOUS
    assert finding.severity is Severity.INFO
    assert "not a finding that the chain is invalid" in finding.explanation.lower()
    assert "invalid" not in affirmative(finding)
    assert "broken" not in affirmative(finding)
    assert "invalid" not in finding.conclusion.lower()


def test_self_signed_is_not_called_malicious():
    certs = [cert(0, subject_key_id="ab", authority_key_id="ab")]
    finding = CertificateChainRule().evaluate(with_certs(certs))[0]
    assert finding.status is FindingStatus.OBSERVED_ISSUE
    claims = affirmative(finding)
    for forbidden in ("attack", "malicious", "attacker", "interception",
                      "man-in-the-middle", "mitm"):
        assert forbidden not in claims, forbidden
    assert "not an indication of malicious activity" in finding.explanation


def test_no_handshake_never_reports_absent_forward_secrecy():
    """never: "no ServerHello observed" -> "no forward secrecy"."""
    s = session(tls_forward_secrecy=EvidenceField.unknown("no ServerHello observed"),
                tls_key_exchange=EvidenceField.unknown("no ServerHello observed"))
    finding = ForwardSecrecyRule().evaluate(s)[0]
    assert finding.status is FindingStatus.INSUFFICIENT_EVIDENCE
    assert finding.severity is Severity.INFO
    assert "NOT a finding that forward secrecy is absent" in finding.explanation


def test_unknown_suite_never_reports_a_weak_cipher():
    """never: "unknown cipher suite" -> "weak cipher suite"."""
    s = session(tls_key_exchange=EvidenceField.ambiguous(None, "suite 0xffff unknown"),
                tls_forward_secrecy=EvidenceField.ambiguous(None, "suite unknown"))
    for rule in (KeyExchangeRule(), ForwardSecrecyRule()):
        finding = rule.evaluate(s)[0]
        assert finding.status is FindingStatus.AMBIGUOUS
        assert finding.severity is Severity.INFO
        assert "weak" not in affirmative(finding)


def test_unread_key_is_not_reported_as_a_small_key():
    s = with_certs([cert(0)])                 # no key_bits at all
    finding = CertificateKeyStrengthRule().evaluate(s)[0]
    assert finding.status is FindingStatus.INSUFFICIENT_EVIDENCE
    assert "an unread key is not a small key" in finding.explanation


def test_unrecognised_signature_oid_is_not_reported_as_weak():
    s = with_certs([cert(0)], chain_signature_oids=("1.2.3.4.5",))
    finding = CertificateSignatureRule().evaluate(s)[0]
    assert finding.status is FindingStatus.INSUFFICIENT_EVIDENCE
    assert "never as weak" in finding.explanation


# ============================================== positive detections still work
def test_weak_rsa_key_is_reported():
    s = with_certs([cert(0, public_key_algorithm="RSA", key_bits=1024)])
    finding = CertificateKeyStrengthRule().evaluate(s)[0]
    assert finding.status is FindingStatus.OBSERVED_ISSUE
    assert finding.severity is Severity.HIGH
    assert "2048" in blob(finding)
    assert finding.remediation


def test_exactly_2048_bits_passes():
    """Boundary: the NIST minimum is inclusive."""
    s = with_certs([cert(0, public_key_algorithm="RSA", key_bits=2048)])
    assert CertificateKeyStrengthRule().evaluate(s)[0].status is FindingStatus.COMPLIANT


def test_sha1_signature_is_reported():
    s = with_certs([cert(0)], chain_signature_oids=("1.2.840.113549.1.1.5",))
    finding = CertificateSignatureRule().evaluate(s)[0]
    assert finding.status is FindingStatus.OBSERVED_ISSUE
    assert finding.severity is Severity.HIGH
    assert "sha-1" in blob(finding)


def test_absent_forward_secrecy_is_reported_when_observed():
    s = session(tls_forward_secrecy=EvidenceField.observed(
        False, "TLS_RSA_WITH_AES_128_CBC_SHA uses RSA key exchange"))
    finding = ForwardSecrecyRule().evaluate(s)[0]
    assert finding.status is FindingStatus.OBSERVED_ISSUE
    assert finding.severity is Severity.MEDIUM
    assert finding.remediation


# ================================================== the D-16 checklist
def test_checklist_is_closed_and_versioned():
    assert CHECKLIST_VERSION
    assert len(CHECKLIST) == 7
    names = [name for name, _check in CHECKLIST]
    assert len(set(names)) == len(names)


def test_checklist_never_scores_missing_evidence_as_a_pass():
    """A checklist that treated absent evidence as compliant would manufacture
    reassurance, which is worse than having no checklist."""
    s = session(                                   # TLS seen, but nothing else known
        tls_negotiated_version=EvidenceField.unknown("no ServerHello"),
        tls_forward_secrecy=EvidenceField.unknown("no ServerHello"),
        tls_key_exchange=EvidenceField.unknown("no ServerHello"))
    finding = InsecureConfigurationRule().evaluate(s)[0]
    text = blob(finding)
    assert "not observable" in text or "not evaluated" in text
    assert finding.status is not FindingStatus.COMPLIANT or "not evaluated" in text
    # every unevaluated item is named, so coverage is legible
    assert finding.limitations


def test_checklist_states_that_it_is_closed():
    s = with_certs([cert(0, public_key_algorithm="RSA", key_bits=2048)])
    finding = InsecureConfigurationRule().evaluate(s)[0]
    assert f"closed at version {CHECKLIST_VERSION}" in " ".join(finding.limitations)
    assert "not claimed to be absent" in " ".join(finding.limitations)


def test_checklist_does_not_duplicate_the_dedicated_findings():
    """Fusion groups on IssueClass: a duplicate would inflate recurrence damping and
    move the score for a condition already counted once."""
    s = with_certs([cert(0, public_key_algorithm="RSA", key_bits=1024)])
    finding = InsecureConfigurationRule().evaluate(s)[0]
    # it reports coverage, not a second copy of the weak-key condition
    assert finding.status is FindingStatus.INFORMATIONAL
    assert finding.severity is Severity.INFO
    assert "deliberately not a second copy" in finding.explanation


# ===================================================== structural invariants
def test_non_assertive_statuses_never_carry_severity_above_info():
    """Phase-4 invariant: we do not assert impact for conditions not established."""
    cases = [
        (CertificatePresenceRule(), session()),
        (CertificateChainRule(), with_certs([cert(0)])),
        (KeyExchangeRule(), session(
            tls_key_exchange=EvidenceField.unknown("none"))),
        (ForwardSecrecyRule(), session(
            tls_forward_secrecy=EvidenceField.unknown("none"))),
        (InsecureConfigurationRule(), session()),
    ]
    non_assertive = {FindingStatus.AMBIGUOUS, FindingStatus.INSUFFICIENT_EVIDENCE,
                     FindingStatus.NOT_OBSERVABLE, FindingStatus.COMPLIANT,
                     FindingStatus.INFORMATIONAL}
    for rule, s in cases:
        for finding in rule.evaluate(s):
            if finding.status in non_assertive:
                assert finding.severity is Severity.INFO, (rule.rule_id, finding.status)


def test_every_certificate_rule_cites_a_standard():
    for rule in (CertificatePresenceRule(), CertificateExpiryRule(),
                 CertificateKeyStrengthRule(), CertificateSignatureRule(),
                 CertificateChainRule(), KeyExchangeRule(), ForwardSecrecyRule(),
                 InsecureConfigurationRule()):
        assert rule.standards, rule.rule_id
        joined = " ".join(rule.standards)
        assert "RFC" in joined or "NIST" in joined, rule.rule_id


def test_certificate_rules_do_not_run_without_certificates():
    """Rules that need a certificate must not fabricate one from nothing."""
    s = session()
    for rule in (CertificateExpiryRule(), CertificateKeyStrengthRule(),
                 CertificateSignatureRule(), CertificateChainRule()):
        assert rule.applies_to(s) is False, rule.rule_id


@pytest.mark.parametrize("hostile", [
    "<script>alert(1)</script>", "'; DROP TABLE findings;--",
    "‮evil.test", "../../etc/passwd", "{{7*7}}", "\x00\x01",
])
def test_hostile_certificate_text_is_carried_as_inert_data(hostile):
    """Certificate content is attacker-controlled. It must be reported, never
    interpreted, and never used to build an identifier."""
    s = with_certs([cert(0, san_dns_names=(hostile,))])
    finding = CertificatePresenceRule().evaluate(s)[0]
    # it round-trips as data
    assert json.loads(json.dumps(finding.to_dict()))
    # and the finding id stays content-addressed on rule/capture/stream/status only
    assert len(finding.finding_id) == 16
    assert all(c in "0123456789abcdef" for c in finding.finding_id)
