"""
Key-exchange and forward-secrecy rules (PS deliverables D-09 and D-17).

Standards basis (primary sources, verified in docs/phase11/02):
  * RFC 8446 SS1.2 and App. D.5 -- TLS 1.3 removed static RSA and static Diffie-Hellman
    key exchange, so every TLS 1.3 suite provides forward secrecy by construction.
  * RFC 8446 SS4.2.8 -- in TLS 1.3 the key exchange is negotiated in the key_share
    extension, NOT encoded in the cipher suite (every 1.3 suite is Kx=any).
  * NIST SP 800-52r2 SS3.3.1 -- servers "shall" be configured with ephemeral key
    establishment for TLS 1.2 cipher suites.

The forbidden conversion this file exists to prevent: a handshake we could not see is
UNKNOWN, never "no forward secrecy". Absence of evidence about a security property is
not evidence that the property is absent, and for forward secrecy the difference is the
whole requirement.
"""
from __future__ import annotations

from typing import List

from securemailscope.analysis.model import FindingStatus, SecurityFinding, Severity
from securemailscope.analysis.registry import SecurityRule, ref
from securemailscope.evidence.states import EvidenceState
from securemailscope.session.model import SessionEvidence, TlsState

RFC8446_KEX = ("RFC 8446 SS4.2.8: TLS 1.3 negotiates key exchange in the key_share "
               "extension; the cipher suite does not encode it")
RFC8446_FS = ("RFC 8446 SS1.2 and App. D.5: TLS 1.3 removed static RSA and static "
              "Diffie-Hellman key exchange")
NIST_FS = ("NIST SP 800-52r2 SS3.3.1: servers shall be configured to use ephemeral "
           "key establishment")


class KeyExchangeRule(SecurityRule):
    """SEC-KEX-001 -- identify the negotiated key-exchange mechanism (D-09)."""

    rule_id = "SEC-KEX-001"
    title = "Key exchange mechanism"
    description = ("Identifies the key-exchange mechanism from the negotiated cipher "
                   "suite (TLS <=1.2) or the ServerHello key_share group (TLS 1.3).")
    standards = (RFC8446_KEX,)

    def applies_to(self, session: SessionEvidence) -> bool:
        return session.tls_state is not TlsState.NONE

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        kex = session.tls_key_exchange
        refs = [ref("tls_key_exchange", kex), ref("tls_named_group", session.tls_named_group),
                ref("tls_cipher_suite_name", session.tls_cipher_suite_name)]

        if kex.state is EvidenceState.UNKNOWN:
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="The key exchange mechanism could not be established.",
                explanation=("No ServerHello was captured, so the negotiated key exchange "
                             "is unknown. This is a capture limitation and is not an "
                             "indication that a weak key exchange was used."),
                evidence_refs=refs,
                limitations=("A missing ServerHello may result from truncation, packet "
                             "loss, capture position, or session resumption.",))]

        if kex.state is EvidenceState.AMBIGUOUS:
            return [self.finding(
                session,
                status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                conclusion="The key exchange mechanism could not be identified.",
                explanation=(f"{kex.basis}. An unrecognised cipher suite is not treated as "
                             "a weak one: the reference table is deliberately closed-world, "
                             "so an unlisted suite yields no verdict rather than a guess."),
                evidence_refs=refs,
                limitations=("The cipher suite reference table covers the IANA registry "
                             "entries listed in crypto/suites.py; others are reported as "
                             "unidentified.",))]

        return [self.finding(
            session,
            status=FindingStatus.INFORMATIONAL, severity=Severity.INFO,
            conclusion=f"Key exchange: {kex.value}.",
            explanation=kex.basis + ".",
            evidence_refs=refs)]


class ForwardSecrecyRule(SecurityRule):
    """SEC-FS-001 -- forward secrecy assessment (D-17)."""

    rule_id = "SEC-FS-001"
    title = "Forward secrecy"
    description = ("Assesses whether the negotiated key exchange provides forward "
                   "secrecy, from the TLS version and cipher suite.")
    standards = (RFC8446_FS, NIST_FS)

    def applies_to(self, session: SessionEvidence) -> bool:
        return session.tls_state is not TlsState.NONE

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        fs = session.tls_forward_secrecy
        refs = [ref("tls_forward_secrecy", fs),
                ref("tls_key_exchange", session.tls_key_exchange),
                ref("tls_negotiated_version", session.tls_negotiated_version)]

        if fs.state is EvidenceState.UNKNOWN:
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="Forward secrecy could not be assessed for this session.",
                explanation=("No ServerHello was captured, so the key exchange is not "
                             "established. This is NOT a finding that forward secrecy is "
                             "absent -- that would convert missing evidence into a "
                             "security conclusion."),
                evidence_refs=refs,
                limitations=("A resumed session, a truncated capture, or a capture "
                             "started mid-stream all produce this result.",))]

        if fs.state is EvidenceState.AMBIGUOUS:
            return [self.finding(
                session,
                status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                conclusion="Forward secrecy could not be determined.",
                explanation=(f"{fs.basis}. An unrecognised suite is not treated as lacking "
                             "forward secrecy."),
                evidence_refs=refs)]

        if fs.value is True:
            return [self.finding(
                session,
                status=FindingStatus.COMPLIANT, severity=Severity.INFO,
                conclusion="The session provides forward secrecy.",
                explanation=fs.basis + ".",
                evidence_refs=refs)]

        # Observed absence of forward secrecy: a real, evidenced security condition.
        return [self.finding(
            session,
            status=FindingStatus.OBSERVED_ISSUE, severity=Severity.MEDIUM,
            conclusion="The negotiated key exchange does not provide forward secrecy.",
            explanation=(f"{fs.basis}. Recorded traffic from this session could be "
                         "decrypted retrospectively by anyone who later obtains the "
                         "server's long-term private key."),
            evidence_refs=refs,
            remediation=("Configure the server to prefer ephemeral key establishment "
                         "(ECDHE or DHE) and to disable static RSA and static "
                         "Diffie-Hellman cipher suites. Enabling TLS 1.3 removes these "
                         "key exchanges entirely."),
            limitations=("This describes the key exchange for this session only; other "
                         "sessions with the same server may negotiate differently.",))]
