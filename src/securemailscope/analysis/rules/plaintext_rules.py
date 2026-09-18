"""
Cleartext exposure rules.

Phase 3 records authentication as *protocol activity only*. Phase 4 preserves that
boundary strictly (Phase-4 SS13): we may say an authentication command was observed
without TLS protection. We may NOT say credentials were stolen, compromised, or
captured by an attacker -- passive evidence of a cleartext command does not establish
that any adversary was present or obtained anything.
"""
from __future__ import annotations

from typing import List

from securemailscope.analysis.model import FindingStatus, SecurityFinding, Severity
from securemailscope.analysis.registry import SecurityRule, ref
from securemailscope.evidence.states import EvidenceState
from securemailscope.session.model import SessionEvidence, TlsState

RFC8314 = ("RFC 8314 SS3: cleartext email submission/access is obsolete; "
           "TLS is required for credential protection")
NIST_52R2 = "NIST SP 800-52r2 SS3.1 (TLS required to protect transmitted data)"


class CleartextAuthenticationRule(SecurityRule):
    """SEC-PLAIN-001 -- authentication activity observed without TLS protection."""

    rule_id = "SEC-PLAIN-001"
    title = "Authentication activity without TLS protection"
    description = ("Reports authentication-related protocol activity observed while the "
                   "session was not protected by TLS.")
    standards = (RFC8314, NIST_52R2)

    def applies_to(self, session: SessionEvidence) -> bool:
        # Inside implicit TLS the auth exchange is encrypted and not observable.
        return not session.implicit_tls

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        auth = session.auth_activity
        refs = [ref("auth_activity", auth), ref("tls_transition", session.tls_transition)]

        if auth.state is EvidenceState.NOT_OBSERVABLE:
            return []
        if auth.value is not True:
            return []

        # Authentication observed in cleartext: the session never reached TLS.
        if session.tls_state is TlsState.NONE:
            return [self.finding(
                session,
                status=FindingStatus.OBSERVED_ISSUE, severity=Severity.HIGH,
                conclusion=("Authentication commands were exchanged in cleartext; no TLS "
                            "protection was observed for this session."),
                explanation=("An authentication-related command was observed while the session "
                             "carried no TLS. Anything transmitted was therefore unprotected in "
                             "transit. This describes what the capture shows; it does not assert "
                             "that any third party observed or obtained the credentials, which "
                             "passive capture cannot establish."),
                evidence_refs=refs,
                remediation=("Require TLS before authentication: enable implicit TLS on the "
                             "submission/access ports, or require a successful STARTTLS/STLS "
                             "upgrade before accepting credentials."),
                limitations=(
                    "Observation of cleartext transmission is not evidence of interception.",
                    "Credential values are not extracted or assessed by this rule.",
                ))]

        # TLS exists in the stream: auth was seen in the cleartext phase before upgrade.
        return [self.finding(
            session,
            status=FindingStatus.INFORMATIONAL, severity=Severity.INFO,
            conclusion="Authentication activity was observed in the pre-TLS phase of the session.",
            explanation=("Authentication-related protocol activity appeared before the session "
                         "was protected. The capture does not establish whether credential "
                         "material itself was exposed."),
            evidence_refs=refs)]


class PlaintextSessionRule(SecurityRule):
    """SEC-PLAIN-002 -- the session carried no TLS at all."""

    rule_id = "SEC-PLAIN-002"
    title = "Mail session carried no TLS"
    description = "Reports a mail session that completed without any TLS protection."
    standards = (RFC8314, NIST_52R2)

    def applies_to(self, session: SessionEvidence) -> bool:
        return not session.implicit_tls and session.protocol is not None

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        if session.tls_state is not TlsState.NONE:
            return []
        transition = session.tls_transition
        if transition.state is not EvidenceState.OBSERVED or transition.value is not False:
            return []

        refs = [ref("tls_transition", transition),
                ref("starttls_advertised", session.starttls_advertised)]
        return [self.finding(
            session,
            status=FindingStatus.OBSERVED_ISSUE, severity=Severity.MEDIUM,
            conclusion="The mail session carried no TLS protection.",
            explanation=("No TLS records were observed in this stream, so message and command "
                         "content travelled in cleartext. This states what was observed. It does "
                         "not attribute a cause: a session may be unprotected through client "
                         "choice, server configuration, or interference, and this capture alone "
                         "cannot distinguish those."),
            evidence_refs=refs,
            remediation=("Require TLS for this service, preferring implicit TLS on the dedicated "
                         "ports (RFC 8314) or enforced STARTTLS/STLS."),
            limitations=("The cause of the missing protection is not determined by this rule.",))]
