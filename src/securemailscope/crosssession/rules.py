"""
Cross-session rules (Phase-5 §14).

Each rule compares one subject session against a prior-history baseline and, where
available, unaffected control endpoints. The governing rule for all of them:

    difference != attack

A deviation is reported as a deviation. It becomes SUSPICIOUS_DEVIATION only when a
supported contrast adds independent evidence, and even then the engine does not claim
stripping, attribution, or exploitation -- passive evidence cannot establish those.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import List, Optional, Sequence

from securemailscope.analysis.model import EvidenceRef, FindingStatus, Severity
from securemailscope.analysis.registry import ref
from securemailscope.crosssession.baseline import Baseline, BaselineStatus
from securemailscope.crosssession.comparability import ComparabilityAssessment
from securemailscope.crosssession.contrast import ContrastResult, ContrastState
from securemailscope.crosssession.model import CrossSessionFinding, Deviation
from securemailscope.evidence.states import EvidenceState
from securemailscope.session.model import SessionEvidence, TlsState

RFC3207 = "RFC 3207 §6 (SMTP STARTTLS security considerations)"

#: Limitation carried on every finding that touches the stripping question. This is the
#: scientific boundary the project refuses to hide (Phase-5 §24).
BLIND_STRIPPING = (
    "Passive PCAP evidence alone cannot distinguish a consistently legitimate plaintext "
    "configuration from a consistently stripped STARTTLS configuration when no unaffected "
    "comparable control endpoint or other differentiating evidence exists."
)


class CrossSessionRule(ABC):
    rule_id: str = ""
    title: str = ""
    description: str = ""
    standards: tuple = ()

    def applies_to(self, session: SessionEvidence) -> bool:
        return True

    @abstractmethod
    def evaluate(self, session: SessionEvidence, baseline: Baseline,
                 contrast: ContrastResult,
                 comparability: ComparabilityAssessment) -> List[CrossSessionFinding]:
        ...

    def finding(self, session, *, status, severity, deviation, conclusion, explanation,
                baseline=None, contrast=None, comparability=None,
                evidence_refs=(), standards=None, limitations=()) -> CrossSessionFinding:
        seed = (f"{self.rule_id}|{session.capture_id}|{session.tcp_stream_id}"
                f"|{status.value}|{deviation.value}")
        return CrossSessionFinding(
            finding_id=hashlib.sha256(seed.encode()).hexdigest()[:16],
            rule_id=self.rule_id, title=self.title, status=status, severity=severity,
            deviation=deviation, conclusion=conclusion, explanation=explanation,
            capture_id=session.capture_id, subject_stream_key=session.stream_key,
            tcp_stream_id=session.tcp_stream_id, protocol=session.protocol,
            comparability=comparability.to_dict() if comparability else None,
            baseline=baseline.to_dict() if baseline else None,
            contrast=contrast.to_dict() if contrast else None,
            evidence_refs=tuple(evidence_refs),
            standards=tuple(standards if standards is not None else self.standards),
            limitations=tuple(limitations))

    # ---- shared guard ------------------------------------------------------
    def _abstain_if_no_baseline(self, session, baseline, comparability
                                ) -> Optional[CrossSessionFinding]:
        """No usable history => no comparison. Never fabricate one (§8)."""
        if baseline.usable:
            return None
        if baseline.status is BaselineStatus.NOT_APPLICABLE:
            return self.finding(
                session, status=FindingStatus.NOT_OBSERVABLE, severity=Severity.INFO,
                deviation=Deviation.NOT_ASSESSED,
                conclusion="Cross-session comparison does not apply to this session.",
                explanation=baseline.reason,
                baseline=baseline, comparability=comparability,
                evidence_refs=[ref("starttls_advertised", session.starttls_advertised)])
        return self.finding(
            session, status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
            deviation=Deviation.NOT_ASSESSED,
            conclusion="Insufficient comparable history to assess this session.",
            explanation=(baseline.reason + ". No anomaly is inferred from the absence of "
                         "history; the engine abstains."),
            baseline=baseline, comparability=comparability,
            evidence_refs=[ref("starttls_advertised", session.starttls_advertised)])


class StartTlsAdvertisementDeviationRule(CrossSessionRule):
    """CS-STARTTLS-001 -- advertisement behaviour vs prior comparable sessions.

    This is the rule the whole phase exists for. Historical sessions may show the
    capability consistently present while the subject shows it absent. That is a real,
    reportable deviation -- and it is still NOT proof of stripping (Finding 1, §10).
    """

    rule_id = "CS-STARTTLS-001"
    title = "STARTTLS/STLS advertisement deviation from baseline"
    description = "Compares advertisement behaviour against prior comparable sessions."
    standards = (RFC3207,)

    def applies_to(self, session: SessionEvidence) -> bool:
        return not session.implicit_tls and session.protocol is not None

    def evaluate(self, session, baseline, contrast, comparability):
        abstention = self._abstain_if_no_baseline(session, baseline, comparability)
        if abstention:
            return [abstention]

        feature = baseline.feature("starttls_advertised")
        advertised = session.starttls_advertised
        refs = [ref("starttls_advertised", advertised)]

        # Only a *consistent* historical baseline can establish an expectation.
        if feature is None or not feature.is_consistent:
            return [self.finding(
                session, status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                deviation=Deviation.NOT_ASSESSED,
                conclusion="Historical advertisement behaviour is not consistent.",
                explanation=("Prior comparable sessions disagree about whether the capability "
                             "was advertised, so no expectation can be established and no "
                             "deviation can be claimed."),
                baseline=baseline, contrast=contrast, comparability=comparability,
                evidence_refs=refs)]

        expected = feature.dominant
        current = ("true" if advertised.value is True else
                   "false" if advertised.value is False else advertised.state.value)

        if current == expected:
            # The subject is self-consistent. That alone proves nothing: a consistently
            # stripped endpoint is also self-consistent (02A §9 #1). The only thing that
            # can distinguish them is an unaffected comparable endpoint.
            controls_all_upgrade = (
                contrast.state is ContrastState.CONTRAST_SUPPORTED
                and contrast.control_upgrade_rate == 1.0
                and contrast.subject_upgraded is False)
            if controls_all_upgrade and current != "true":
                return [self.finding(
                    session, status=FindingStatus.OBSERVED_ISSUE, severity=Severity.MEDIUM,
                    deviation=Deviation.SUSPICIOUS_DEVIATION,
                    conclusion=("This endpoint consistently lacks the upgrade capability while "
                                "comparable endpoints at the same server consistently have it."),
                    explanation=(
                        f"This client's own history is self-consistent ({feature.total} prior "
                        f"sessions all {expected!r}), so its behaviour alone looks unremarkable. "
                        f"However {len(contrast.control_sessions)} comparable session(s) from "
                        "other clients at the same server did upgrade successfully. A capability "
                        "the server demonstrably offers to others is absent for this client. "
                        "That is a supported deviation worth investigating. It is not proof that "
                        "the capability was removed in transit -- client-specific server policy "
                        "produces the same observation -- and no actor is identified."),
                    baseline=baseline, contrast=contrast, comparability=comparability,
                    evidence_refs=refs,
                    limitations=(BLIND_STRIPPING,
                        "Per-client server policy and interference are indistinguishable here.",))]

            return [self.finding(
                session, status=FindingStatus.COMPLIANT, severity=Severity.INFO,
                deviation=Deviation.NONE,
                conclusion="Advertisement behaviour matches the established baseline.",
                explanation=(f"All {feature.total} prior comparable sessions showed "
                             f"{expected!r} and this session agrees."
                             + ("" if contrast.state is ContrastState.CONTRAST_SUPPORTED else
                                " No comparable control endpoint was available to corroborate "
                                "this from a second angle.")),
                baseline=baseline, contrast=contrast, comparability=comparability,
                evidence_refs=refs,
                limitations=() if contrast.state is ContrastState.CONTRAST_SUPPORTED
                            else (BLIND_STRIPPING,))]

        # Deviation established. Severity stays INFO: a difference is not an attack.
        supported = contrast.state is ContrastState.CONTRAST_SUPPORTED
        control_unaffected = supported and contrast.control_upgrade_rate == 1.0

        if control_unaffected:
            return [self.finding(
                session, status=FindingStatus.OBSERVED_ISSUE, severity=Severity.MEDIUM,
                deviation=Deviation.SUSPICIOUS_DEVIATION,
                conclusion=("This endpoint deviates from both its own history and from "
                            "comparable endpoints that remain unaffected."),
                explanation=(
                    f"Prior comparable sessions consistently showed {expected!r}; this session "
                    f"shows {current!r}. Separately, "
                    f"{len(contrast.control_sessions)} comparable session(s) from other clients "
                    "at the same endpoint did upgrade successfully. Two independent comparisons "
                    "therefore disagree with this session. That is a well-supported deviation "
                    "warranting investigation -- it is not proof that the capability was removed "
                    "in transit, and no actor is identified."),
                baseline=baseline, contrast=contrast, comparability=comparability,
                evidence_refs=refs, limitations=(BLIND_STRIPPING,
                    "A deviation supported by contrast indicates that this endpoint behaves "
                    "differently, not why.",))]

        reason = {
            ContrastState.CONTRAST_NOT_APPLICABLE:
                "no unaffected comparable control endpoint exists, so the deviation cannot be "
                "corroborated",
            ContrastState.CONTRAST_INSUFFICIENT:
                "too few control sessions to corroborate the deviation",
            ContrastState.CONTRAST_AMBIGUOUS:
                "comparable endpoints disagree among themselves, so they cannot corroborate "
                "the deviation",
            ContrastState.CONTRAST_SUPPORTED:
                "comparable endpoints show the same behaviour as this session, which does not "
                "corroborate a concern",
        }[contrast.state]

        return [self.finding(
            session, status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
            deviation=Deviation.DEVIATION,
            conclusion="This session deviates from its own history; the cause is undetermined.",
            explanation=(
                f"Prior comparable sessions consistently showed {expected!r} and this session "
                f"shows {current!r}. However, {reason}. A configuration change and interference "
                "produce the same observation here, so no security conclusion is drawn."),
            baseline=baseline, contrast=contrast, comparability=comparability,
            evidence_refs=refs, limitations=(BLIND_STRIPPING,))]


class StartTlsUpgradeDeviationRule(CrossSessionRule):
    """CS-STARTTLS-002 -- upgrade behaviour vs baseline.

    Guards the legitimate-decline false positive that OQ-25 exposed (Finding 2, §11):
    historical success plus a current decline must never become an automatic issue.
    """

    rule_id = "CS-STARTTLS-002"
    title = "STARTTLS/STLS upgrade deviation from baseline"
    description = "Compares upgrade outcome against prior comparable sessions."
    standards = (RFC3207,)

    def applies_to(self, session: SessionEvidence) -> bool:
        return not session.implicit_tls and session.protocol is not None

    def evaluate(self, session, baseline, contrast, comparability):
        abstention = self._abstain_if_no_baseline(session, baseline, comparability)
        if abstention:
            return [abstention]

        feature = baseline.feature("tls_established")
        refs = [ref("tls_transition", session.tls_transition),
                ref("starttls_requested", session.starttls_requested)]
        if feature is None or not feature.is_consistent:
            return []

        expected = feature.dominant
        current = "true" if session.tls_state is TlsState.ESTABLISHED else session.tls_state.value
        if current == expected:
            return []

        # Historical success + current non-upgrade. The client may simply have declined.
        declined = session.starttls_requested.value is False
        return [self.finding(
            session, status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
            deviation=Deviation.DEVIATION,
            conclusion="Upgrade outcome differs from the established baseline.",
            explanation=(
                f"Prior comparable sessions consistently showed {expected!r} and this session "
                f"shows {current!r}. "
                + ("The client did not request the upgrade, which is a legitimate client-side "
                   "choice as often as it is anything else. " if declined else "")
                + "A behavioural difference is reported as a difference; it is not treated as "
                  "an attack."),
            baseline=baseline, contrast=contrast, comparability=comparability,
            evidence_refs=refs,
            limitations=("A client declining an available upgrade is legitimate behaviour and "
                         "is not distinguishable here from an induced decline.",))]


class TlsVersionDeviationRule(CrossSessionRule):
    """CS-TLS-001 -- negotiated TLS version vs baseline.

    A version *change* is only interesting when it moves to a weaker version. An upgrade
    (e.g. TLS 1.2 -> 1.3) is reported as an improvement, never as an anomaly.
    """

    rule_id = "CS-TLS-001"
    title = "Negotiated TLS version deviation from baseline"
    description = "Compares the negotiated TLS version against prior comparable sessions."
    standards = ("RFC 8996 (BCP 195)", "NIST SP 800-52r2 §3.1")

    _RANK = {"SSL2.0": 0, "SSL3.0": 1, "TLS1.0": 2, "TLS1.1": 3, "TLS1.2": 4, "TLS1.3": 5}

    def evaluate(self, session, baseline, contrast, comparability):
        abstention = self._abstain_if_no_baseline(session, baseline, comparability)
        if abstention:
            return []          # version abstention is already covered by CS-STARTTLS-001

        feature = baseline.feature("tls_version")
        version = session.tls_negotiated_version
        refs = [ref("tls_negotiated_version", version)]
        if feature is None or not feature.is_consistent or version.value is None:
            return []

        expected, current = feature.dominant, str(version.value)
        if current == expected:
            return []

        old_rank, new_rank = self._RANK.get(expected), self._RANK.get(current)
        if old_rank is None or new_rank is None:
            return []   # unknown versions are not ranked; SEC-TLS-001 already handles them

        if new_rank > old_rank:
            return [self.finding(
                session, status=FindingStatus.INFORMATIONAL, severity=Severity.INFO,
                deviation=Deviation.NONE,
                conclusion=f"Negotiated version improved from {expected} to {current}.",
                explanation="A move to a newer TLS version is an improvement, not an anomaly.",
                baseline=baseline, comparability=comparability, evidence_refs=refs)]

        return [self.finding(
            session, status=FindingStatus.OBSERVED_ISSUE, severity=Severity.MEDIUM,
            deviation=Deviation.DEVIATION,
            conclusion=f"Negotiated version regressed from {expected} to {current}.",
            explanation=(
                f"All {feature.total} prior comparable sessions negotiated {expected}; this "
                f"session negotiated the weaker {current}. A regression to a weaker protocol "
                "version is a security-relevant change. The cause is not determined: server "
                "reconfiguration, client capability and interference are indistinguishable here."),
            baseline=baseline, contrast=contrast, comparability=comparability,
            evidence_refs=refs,
            limitations=("The cause of the version regression is not established by this rule.",))]


ALL_CROSS_RULES = (
    StartTlsAdvertisementDeviationRule,
    StartTlsUpgradeDeviationRule,
    TlsVersionDeviationRule,
)
