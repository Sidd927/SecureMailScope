"""
TLS posture rules.

Standards basis (verified against primary sources, see docs/research/20):
  * RFC 8996 (BCP 195, Mar 2021) -- "TLS 1.0 MUST NOT be used", likewise TLS 1.1.
  * NIST SP 800-52r2 (Aug 2019, current) 3.1 -- servers "shall be configured to use
    TLS 1.2", "should be configured to use TLS 1.3", "should not be configured to use
    TLS 1.1", and "shall not use TLS 1.0, SSL 3.0, or SSL 2.0".

Deliberately NOT implemented, because the evidence does not support them:
  * Extended Master Secret (RFC 7627) and renegotiation_info (RFC 5746). tshark can
    dissect these, but our normalized contract does not carry them and our corpus does
    not contain them. Inventing a rule would produce findings we cannot evidence.
  * Cipher-suite strength grading. The cipher value is observed, but mapping every IANA
    suite to a NIST-approved/not-approved verdict needs a maintained table we have not
    built or validated; a half-populated table would silently mislabel unknown suites.
"""
from __future__ import annotations

from typing import List

from securemailscope.analysis.model import FindingStatus, SecurityFinding, Severity
from securemailscope.analysis.registry import SecurityRule, ref
from securemailscope.evidence.states import EvidenceState
from securemailscope.session.model import SessionEvidence, TlsState

RFC8996 = "RFC 8996 (BCP 195) SS4-5: TLS 1.0 and TLS 1.1 MUST NOT be used"
NIST_52R2 = ("NIST SP 800-52r2 SS3.1: servers shall use TLS 1.2, should use TLS 1.3, "
             "should not use TLS 1.1, shall not use TLS 1.0/SSL 3.0/SSL 2.0")

#: Versions prohibited outright, with the severity rationale recorded alongside.
_DEPRECATED = {
    "SSL2.0": (Severity.CRITICAL, "SSL 2.0 is prohibited outright and is fundamentally broken"),
    "SSL3.0": (Severity.CRITICAL, "SSL 3.0 is prohibited outright (POODLE-era protocol)"),
    "TLS1.0": (Severity.HIGH,
               "RFC 8996 states TLS 1.0 MUST NOT be used and NIST SP 800-52r2 states "
               "servers shall not use it; handshake integrity depends on SHA-1"),
    "TLS1.1": (Severity.HIGH,
               "RFC 8996 states TLS 1.1 MUST NOT be used; NIST SP 800-52r2 states "
               "servers should not be configured to use it"),
}
_ACCEPTABLE = {
    "TLS1.2": "NIST SP 800-52r2 requires servers to support TLS 1.2",
    "TLS1.3": "NIST SP 800-52r2 recommends TLS 1.3; it is the current best practice",
}


class DeprecatedTlsVersionRule(SecurityRule):
    """SEC-TLS-001 -- negotiated TLS version against RFC 8996 / NIST SP 800-52r2."""

    rule_id = "SEC-TLS-001"
    title = "Negotiated TLS version posture"
    description = ("Evaluates the TLS version negotiated in the ServerHello against "
                   "RFC 8996 and NIST SP 800-52r2.")
    standards = (RFC8996, NIST_52R2)

    def applies_to(self, session: SessionEvidence) -> bool:
        # Only meaningful where TLS evidence exists at all.
        return session.tls_state is not TlsState.NONE

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        version = session.tls_negotiated_version
        refs = [ref("tls_negotiated_version", version)]

        # No ServerHello -> the negotiated version simply cannot be established.
        # Absence of a visible version is NOT evidence of a weak version (Phase-4 SS7).
        if version.state is EvidenceState.UNKNOWN:
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="The negotiated TLS version could not be established from this capture.",
                explanation=("TLS records were present but no ServerHello was captured, so the "
                             "negotiated version is unknown. This is a capture limitation, not an "
                             "indication that a weak version was used."),
                evidence_refs=refs,
                limitations=("A missing ServerHello may result from truncation, packet loss, "
                             "or capture position.",))]

        if version.state is EvidenceState.AMBIGUOUS:
            return [self.finding(
                session,
                status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                conclusion="A ServerHello was observed but its version value was not recognised.",
                explanation=("The version field held a value outside the known TLS/SSL set. It is "
                             "not treated as insecure, because an unrecognised value is not "
                             "evidence of a deprecated protocol."),
                evidence_refs=refs,
                limitations=("Unknown version values may indicate a non-standard implementation "
                             "or a dissector limitation.",))]

        name = str(version.value)
        if name in _DEPRECATED:
            severity, rationale = _DEPRECATED[name]
            return [self.finding(
                session,
                status=FindingStatus.OBSERVED_ISSUE, severity=severity,
                conclusion=f"The session negotiated {name}, a deprecated protocol version.",
                explanation=rationale,
                evidence_refs=refs,
                remediation=("Disable this protocol version on the mail service and require "
                             "TLS 1.2 as a minimum, preferring TLS 1.3."))]

        if name in _ACCEPTABLE:
            return [self.finding(
                session,
                status=FindingStatus.COMPLIANT, severity=Severity.INFO,
                conclusion=f"The session negotiated {name}, which meets current guidance.",
                explanation=_ACCEPTABLE[name],
                evidence_refs=refs)]

        return [self.finding(
            session,
            status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
            conclusion=f"Negotiated version {name!r} is outside the evaluated set.",
            explanation="No standards judgement is made for a version this rule does not cover.",
            evidence_refs=refs)]


class TlsHandshakeCompletionRule(SecurityRule):
    """SEC-TLS-002 -- what the handshake evidence actually establishes.

    Preserves the Phase-3 distinction between a ClientHello, a progressed negotiation,
    and an established session. Never manufactures TLS_ESTABLISHED (Phase-4 SS8).
    """

    rule_id = "SEC-TLS-002"
    title = "TLS handshake completion evidence"
    description = "Reports what the captured handshake evidence supports, without over-claiming."
    standards = ("RFC 8446 SS2 (handshake message flow)",)

    def applies_to(self, session: SessionEvidence) -> bool:
        return session.tls_state is not TlsState.NONE

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        refs = [ref("tls_transition", session.tls_transition)]
        state = session.tls_state

        if state is TlsState.ESTABLISHED:
            # Defensive: only claim completion when the transition evidence agrees.
            # A state enum that contradicts its own supporting evidence must fail
            # closed rather than produce a confident COMPLIANT finding.
            if not (session.tls_transition.state is EvidenceState.OBSERVED
                    and session.tls_transition.value is True):
                return [self.finding(
                    session,
                    status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                    conclusion="TLS state and its supporting evidence disagree.",
                    explanation=("The session is marked as established but the transition "
                                 "evidence does not confirm it. No completion claim is made."),
                    evidence_refs=refs)]
            return [self.finding(
                session,
                status=FindingStatus.COMPLIANT, severity=Severity.INFO,
                conclusion="TLS negotiation completed and encrypted application data was observed.",
                explanation=("Both hellos and subsequent encrypted application records were "
                             "captured. Because the Finished messages are themselves encrypted, "
                             "flowing application data is the strongest passive completion evidence."),
                evidence_refs=refs)]

        if state in (TlsState.CLIENT_HELLO_OBSERVED, TlsState.SERVER_HELLO_OBSERVED):
            seen = ("a ClientHello only" if state is TlsState.CLIENT_HELLO_OBSERVED
                    else "both hellos")
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="TLS negotiation was observed but completion is not established.",
                explanation=(f"The capture contains {seen} and no encrypted application data, so "
                             "the handshake cannot be said to have completed. This is reported as "
                             "incomplete evidence, not as a failed or insecure session."),
                evidence_refs=refs,
                limitations=("Truncation or capture position can cut a handshake short without "
                             "any fault in the session itself.",))]

        return [self.finding(
            session,
            status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
            conclusion="TLS records were present but the handshake could not be reconstructed.",
            explanation="Neither hello was captured in this stream; no completion claim is made.",
            evidence_refs=refs)]


class CertificateObservabilityRule(SecurityRule):
    """SEC-TLS-003 -- certificate TRUST and REVOCATION boundary.

    NARROWED IN PHASE 11 (ADR-0023). This rule previously covered two things: whether a
    certificate was visible at all, and whether trust could be evaluated. Phase 11
    implements extraction (D-10..D-14), which makes the first half of that answer --
    and the limitation "certificate extraction is not implemented in this phase" --
    false. Leaving it would have put a lie in the output.

    Presence and absence now belong to SEC-CERT-001, which can name the specific reason
    (encrypted under TLS 1.3, not sent on resumption, or truncated capture). What
    remains here is the part that no amount of implementation will change: trust and
    revocation are not passively observable, at any TLS version, with or without a
    visible certificate.

    The rule id and IssueClass are unchanged, so assessments recorded before Phase 11
    stay interpretable.
    """

    rule_id = "SEC-TLS-003"
    title = "Certificate trust and revocation boundary"
    description = ("States what certificate validation is structurally impossible from a "
                   "passive capture, independently of whether a certificate was visible.")
    standards = ("RFC 5280 SS6 (path validation requires trust anchors, which a packet "
                 "capture does not contain)",
                 "RFC 6960 (OCSP status is a separate network transaction)",
                 "RFC 8446 SS2 (Certificate is encrypted in TLS 1.3)")

    def applies_to(self, session: SessionEvidence) -> bool:
        return session.tls_state is not TlsState.NONE

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        version = session.tls_negotiated_version
        refs = [ref("tls_negotiated_version", version),
                ref("tls_certificate_chain", session.tls_certificate_chain)]
        extracted = bool(session.certificates)
        state = ("A certificate was extracted and its structure analysed (SEC-CERT-001 "
                 "and SEC-CERT-005), but trust was still not evaluated"
                 if extracted else
                 "No certificate was observable in this session (SEC-CERT-001 records why)")
        return [self.finding(
            session,
            status=FindingStatus.NOT_OBSERVABLE, severity=Severity.INFO,
            conclusion="Certificate trust and revocation were not evaluated.",
            explanation=(f"{state}. Trust cannot be established from a packet capture: "
                         "RFC 5280 SS6 defines path validation over a set of trust anchors, "
                         "and a capture contains none. Revocation cannot be established "
                         "either: OCSP and CRL retrieval are separate network transactions. "
                         "Neither limitation is a finding against the certificate."),
            evidence_refs=refs,
            limitations=(
                "Trust validation would require a trust store chosen by the analyst; "
                "which store, and how enterprise-internal CAs are handled, is an open "
                "question (OQ-04).",
                "Revocation status would require live OCSP or CRL access, which would "
                "breach the passive, offline operating model.",
                "Under TLS 1.3 the Certificate message is encrypted and is not passively "
                "recoverable without key material.",
                "Resumed sessions omit the Certificate message at any TLS version.",
            ))]
