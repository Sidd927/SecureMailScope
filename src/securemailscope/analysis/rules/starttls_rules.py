"""
STARTTLS / STLS rules.

Standards basis:
  * RFC 3207 SS6 -- "A man-in-the-middle attack can be launched by deleting the
    '250 STARTTLS' response from the server"; clients and servers MUST be able to be
    configured to require successful TLS negotiation.
  * RFC 2595 -- STARTTLS/STLS for IMAP and POP3.

The governing constraint (Phase-4 SS9, SS31; docs/research/02B SS3.1): an absent
advertisement is byte-identical whether the capability was stripped in transit or the
server genuinely does not support it. `B_strip_advert` and `I_no_support` produce the
same evidence. This engine therefore reports AMBIGUOUS and says why -- it must never
conclude "STARTTLS was stripped" from single-session passive evidence.
"""
from __future__ import annotations

from typing import List

from securemailscope.analysis.model import FindingStatus, SecurityFinding, Severity
from securemailscope.analysis.registry import SecurityRule, ref
from securemailscope.evidence.states import EvidenceState
from securemailscope.session.model import AppState, SessionEvidence, TlsState

RFC3207 = "RFC 3207 SS6 (SMTP STARTTLS security considerations)"
RFC2595 = "RFC 2595 (STARTTLS for IMAP and POP3)"


def _upgrade_standards(protocol) -> tuple:
    return (RFC3207,) if protocol == "smtp" else (RFC2595,)


class StartTlsUpgradeRule(SecurityRule):
    """SEC-STLS-001 -- outcome of an explicit STARTTLS/STLS upgrade attempt."""

    rule_id = "SEC-STLS-001"
    title = "STARTTLS/STLS upgrade outcome"
    description = "Reports the reconstructed outcome of an explicit upgrade attempt."
    standards = (RFC3207, RFC2595)

    def applies_to(self, session: SessionEvidence) -> bool:
        # Implicit TLS never performs an upgrade; evaluating it here would be a
        # category error (Phase-4 SS10).
        return not session.implicit_tls

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        requested = session.starttls_requested
        accepted = session.starttls_accepted
        refs = [ref("starttls_requested", requested), ref("starttls_accepted", accepted)]
        standards = _upgrade_standards(session.protocol)

        if requested.value is not True:
            return []  # no upgrade attempted; other rules cover that situation

        if accepted.state is EvidenceState.AMBIGUOUS:
            return [self.finding(
                session,
                status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                conclusion="The server's response to the upgrade request was contradictory.",
                explanation=("Both a rejection and an acceptance were observed for the same "
                             "upgrade request. The capture does not settle which applied."),
                evidence_refs=refs, standards=standards)]

        if accepted.value is False:
            return [self.finding(
                session,
                status=FindingStatus.OBSERVED_ISSUE, severity=Severity.MEDIUM,
                conclusion="The client requested an upgrade and the server refused it.",
                explanation=("The client asked to upgrade and the server responded with an error, "
                             "so the session could not be protected by TLS. RFC 3207 requires that "
                             "endpoints be configurable to require successful TLS negotiation. "
                             "A refusal is a configuration and availability condition; it is not "
                             "by itself evidence of an attack."),
                evidence_refs=refs, standards=standards,
                remediation=("Ensure the service offers and accepts STARTTLS/STLS, and configure "
                             "clients to require successful negotiation for sensitive peers."),
                limitations=("A refusal observed passively cannot be distinguished from an "
                             "injected error without corroborating evidence.",))]

        if accepted.value is True:
            if session.tls_state is TlsState.ESTABLISHED:
                return [self.finding(
                    session,
                    status=FindingStatus.COMPLIANT, severity=Severity.INFO,
                    conclusion="The session successfully upgraded to TLS.",
                    explanation=("Advertisement, command, acceptance and a completed TLS "
                                 "negotiation were all observed. A successful upgrade is not a "
                                 "vulnerability."),
                    evidence_refs=refs + [ref("tls_transition", session.tls_transition)],
                    standards=standards)]
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="The upgrade was accepted but completion was not established.",
                explanation=("The server accepted the upgrade, yet the capture does not show a "
                             "completed handshake. This is reported as incomplete evidence rather "
                             "than as a failed upgrade."),
                evidence_refs=refs + [ref("tls_transition", session.tls_transition)],
                standards=standards)]

        return [self.finding(
            session,
            status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
            conclusion="An upgrade was requested but no server response was captured.",
            explanation="The outcome of the upgrade request cannot be established.",
            evidence_refs=refs, standards=standards)]


class StartTlsAdvertisementRule(SecurityRule):
    """SEC-STLS-002 -- advertisement posture, with the ambiguity preserved."""

    rule_id = "SEC-STLS-002"
    title = "STARTTLS/STLS advertisement posture"
    description = ("Reports whether the upgrade capability was advertised, preserving the "
                   "ambiguity when it is absent.")
    standards = (RFC3207, RFC2595)

    def applies_to(self, session: SessionEvidence) -> bool:
        return not session.implicit_tls

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        advertised = session.starttls_advertised
        refs = [ref("starttls_advertised", advertised)]
        standards = _upgrade_standards(session.protocol)

        if advertised.state is EvidenceState.OBSERVED and advertised.value is True:
            if session.starttls_requested.value is True:
                return []  # upgrade path covered by SEC-STLS-001
            return [self.finding(
                session,
                status=FindingStatus.INFORMATIONAL, severity=Severity.INFO,
                conclusion="The server advertised an upgrade capability that the client did not use.",
                explanation=("The capability was present and the client did not request it. This is "
                             "a client behaviour observation. It is not an attack, and passive "
                             "single-session evidence cannot establish why the client declined."),
                evidence_refs=refs + [ref("starttls_requested", session.starttls_requested)],
                standards=standards,
                remediation=("Configure clients to require STARTTLS/STLS for this service where "
                             "the peer is expected to support it."))]

        if advertised.state is EvidenceState.AMBIGUOUS:
            # THE load-bearing case. Do not resolve what the evidence cannot resolve.
            return [self.finding(
                session,
                status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                conclusion=("No upgrade capability was advertised; stripping and genuine "
                            "non-support cannot be distinguished."),
                explanation=("The capability response was observed and did not offer "
                             "STARTTLS/STLS. A server that does not support the extension and a "
                             "server whose advertisement was removed in transit produce identical "
                             "application-layer bytes, so this capture cannot separate them. "
                             "RFC 3207 SS6 documents that this capability can be removed in "
                             "transit; observing that it is absent is not evidence that removal "
                             "occurred."),
                evidence_refs=refs, standards=standards,
                limitations=(
                    "Single-session passive evidence cannot distinguish capability stripping "
                    "from genuine non-support.",
                    "Resolving this requires comparison against other sessions, which is "
                    "outside per-session analysis.",
                ))]

        if advertised.state is EvidenceState.UNKNOWN:
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="No capability response was captured for this session.",
                explanation="Whether an upgrade was offered cannot be established.",
                evidence_refs=refs, standards=standards)]

        return []


class ImplicitTlsRule(SecurityRule):
    """SEC-STLS-003 -- implicit TLS is a distinct behaviour, not a failed upgrade."""

    rule_id = "SEC-STLS-003"
    title = "Implicit TLS session"
    description = "Records that the session used implicit TLS rather than an explicit upgrade."
    standards = ("RFC 8314 (implicit TLS for email submission and access)",)

    def applies_to(self, session: SessionEvidence) -> bool:
        return session.implicit_tls

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        refs = [ref("starttls_advertised", session.starttls_advertised),
                ref("tls_transition", session.tls_transition)]
        return [self.finding(
            session,
            status=FindingStatus.INFORMATIONAL, severity=Severity.INFO,
            conclusion="The session used implicit TLS; no STARTTLS upgrade applies.",
            explanation=("The connection was encrypted from its first record, so there is no "
                         "cleartext upgrade dialogue to evaluate. The absence of a STARTTLS "
                         "advertisement here is expected and is not a failure, a lack of support, "
                         "or evidence of stripping."),
            evidence_refs=refs)]
