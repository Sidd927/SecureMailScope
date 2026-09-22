"""
Canonical posture contracts (Phase 7).

This module is the single source of truth for what SecureMailScope concludes about an
email infrastructure. The backend, dashboard and report generators of later phases must
consume `PostureAssessment` and must never recompute posture themselves; if a number is
not here, it does not exist.

Three separations are structural, not stylistic, and every one of them exists because
collapsing it is how a forensic tool starts lying:

1. **Severity / evidence certainty / observability are three dimensions.** A confirmed
   TLS 1.0 observation is HIGH severity *and* CONFIRMED. A cross-session deviation may
   be analytically important on merely PROBABLE evidence. An unobservable certificate is
   `NOT_OBSERVABLE` — it is **not** low risk. Severity is never reduced because
   certainty is low.

2. **Base issues, behavioural deviations and anomaly signals are three fact kinds.** A
   deviation may *enrich* an issue; it never becomes one. An anomaly may *prioritise*;
   it never concludes. Nothing here can turn a difference into an attack.

3. **Only `OBSERVED_ISSUE` penalises the score.** `COMPLIANT` is positive evidence and
   contributes to coverage, never to credit. `AMBIGUOUS`, `INSUFFICIENT_EVIDENCE` and
   `NOT_OBSERVABLE` become abstentions. Missing evidence never becomes a secure state
   and never improves a score.

Nothing in this module reads packet bytes. Every string that reaches an analyst comes
from a rule, a standard registry entry or a remediation template authored in this
repository — never from a capture.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from securemailscope.analysis.model import (
    EvidenceRef, FindingStatus, SecurityFinding, Severity,
)
from securemailscope.crosssession.model import CrossSessionFinding, Deviation
from securemailscope.evidence.states import EvidenceState
from securemailscope.ml.contract import AnomalyBand, MLAnomalyResult

#: Bumped when the posture contract shape changes.
POSTURE_SCHEMA_VERSION = "1.0"
POSTURE_ENGINE_VERSION = "0.8.0"


# --------------------------------------------------------------------- kinds
class FactKind(str, Enum):
    """What sort of fact a fused entry represents. Never interchangeable."""
    BASE_SECURITY_ISSUE = "BASE_SECURITY_ISSUE"        # standards-bound weakness
    BEHAVIOURAL_DEVIATION = "BEHAVIOURAL_DEVIATION"    # differs from a baseline
    ANOMALY_SIGNAL = "ANOMALY_SIGNAL"                  # statistically unlike normal
    POSITIVE_EVIDENCE = "POSITIVE_EVIDENCE"            # observed good state
    ABSTENTION = "ABSTENTION"                          # could not conclude


class Relation(str, Enum):
    """How one source relates to a fused finding.

    Deliberately excludes anything causal. There is no `CAUSES`, no `PROVES` and no
    `ATTRIBUTES`: passive capture cannot establish any of them.
    """
    SUPPORTS = "supports"                # independent evidence for the same fact
    ENRICHES = "enriches"                # adds context to an established fact
    DUPLICATES = "duplicates"            # the same fact reported again
    CONTEXTUALIZES = "contextualizes"    # explains the surrounding population
    PRIORITIZES = "prioritizes"          # affects analyst ordering only
    CONTRADICTS = "contradicts"          # conflicts with another source
    ABSTAINS = "abstains"                # declines to conclude


class IssueClass(str, Enum):
    """Stable content identity for a security condition.

    Fusion groups on this rather than on `rule_id` so that two rules describing one
    underlying condition converge, and so that a `finding_id` — which is unique per
    instance and therefore useless for deduplication — never leaks into the key.
    """
    DEPRECATED_TLS_VERSION = "DEPRECATED_TLS_VERSION"
    PLAINTEXT_AUTH_EXPOSURE = "PLAINTEXT_AUTH_EXPOSURE"
    NO_TLS_PROTECTION = "NO_TLS_PROTECTION"
    STARTTLS_UPGRADE_FAILURE = "STARTTLS_UPGRADE_FAILURE"
    STARTTLS_BEHAVIOUR_DEVIATION = "STARTTLS_BEHAVIOUR_DEVIATION"
    TLS_VERSION_DEVIATION = "TLS_VERSION_DEVIATION"
    TLS_HANDSHAKE_EVIDENCE = "TLS_HANDSHAKE_EVIDENCE"
    STARTTLS_ADVERTISEMENT = "STARTTLS_ADVERTISEMENT"
    IMPLICIT_TLS_SESSION = "IMPLICIT_TLS_SESSION"
    CERTIFICATE_OBSERVABILITY = "CERTIFICATE_OBSERVABILITY"
    # ---- Phase 11 (ADR-0023). New members only; no existing member changes meaning,
    # so POSTURE_SCHEMA_VERSION stays at 1.0 -- the document shape is unchanged.
    #
    # Named for the DIMENSION, not for a verdict. One class carries both the compliant
    # and the failing finding for its condition, so a verdict-shaped name lies half the
    # time: `FORWARD_SECRECY_ABSENT` renders in the dashboard as "Forward secrecy
    # absent" on a session that HAS forward secrecy, because the label is humanised
    # from the enum member. (The older DEPRECATED_TLS_VERSION has this wart; it is left
    # alone because renaming it would change the fusion identity of stored assessments.)
    KEY_EXCHANGE_MECHANISM = "KEY_EXCHANGE_MECHANISM"
    FORWARD_SECRECY = "FORWARD_SECRECY"
    CERTIFICATE_EXTRACTION = "CERTIFICATE_EXTRACTION"
    CERTIFICATE_VALIDITY = "CERTIFICATE_VALIDITY"
    CERTIFICATE_KEY_STRENGTH = "CERTIFICATE_KEY_STRENGTH"
    CERTIFICATE_SIGNATURE_ALGORITHM = "CERTIFICATE_SIGNATURE_ALGORITHM"
    CERTIFICATE_CHAIN_STRUCTURE = "CERTIFICATE_CHAIN_STRUCTURE"
    INSECURE_CONFIGURATION = "INSECURE_CONFIGURATION"
    ANOMALY = "ANOMALY"
    UNCLASSIFIED = "UNCLASSIFIED"


#: rule_id -> IssueClass. Explicit rather than derived from the id string, so renaming a
#: rule cannot silently change fusion identity.
RULE_ISSUE_CLASS: Dict[str, IssueClass] = {
    "SEC-TLS-001": IssueClass.DEPRECATED_TLS_VERSION,
    "SEC-TLS-002": IssueClass.TLS_HANDSHAKE_EVIDENCE,
    "SEC-TLS-003": IssueClass.CERTIFICATE_OBSERVABILITY,
    "SEC-STLS-001": IssueClass.STARTTLS_UPGRADE_FAILURE,
    "SEC-STLS-002": IssueClass.STARTTLS_ADVERTISEMENT,
    "SEC-STLS-003": IssueClass.IMPLICIT_TLS_SESSION,
    "SEC-PLAIN-001": IssueClass.PLAINTEXT_AUTH_EXPOSURE,
    "SEC-PLAIN-002": IssueClass.NO_TLS_PROTECTION,
    "CS-STARTTLS-001": IssueClass.STARTTLS_BEHAVIOUR_DEVIATION,
    "CS-STARTTLS-002": IssueClass.STARTTLS_BEHAVIOUR_DEVIATION,
    "CS-TLS-001": IssueClass.TLS_VERSION_DEVIATION,
    # ---- Phase 11 ----
    "SEC-KEX-001": IssueClass.KEY_EXCHANGE_MECHANISM,
    "SEC-FS-001": IssueClass.FORWARD_SECRECY,
    "SEC-CERT-001": IssueClass.CERTIFICATE_EXTRACTION,
    "SEC-CERT-002": IssueClass.CERTIFICATE_VALIDITY,
    "SEC-CERT-003": IssueClass.CERTIFICATE_KEY_STRENGTH,
    "SEC-CERT-004": IssueClass.CERTIFICATE_SIGNATURE_ALGORITHM,
    "SEC-CERT-005": IssueClass.CERTIFICATE_CHAIN_STRUCTURE,
    "SEC-CFG-001": IssueClass.INSECURE_CONFIGURATION,
}


class RiskDimension(str, Enum):
    """Analytical axis a security condition sits on (A-01).

    Only dimensions the evidence layer can actually support are listed. There is no
    domain-authentication dimension because SPF/DKIM/DMARC are absent from the
    authoritative problem statement and unobservable in a transport capture.
    """
    PROTOCOL_VERSION = "PROTOCOL_VERSION"
    PLAINTEXT_EXPOSURE = "PLAINTEXT_EXPOSURE"
    UPGRADE_INTEGRITY = "UPGRADE_INTEGRITY"
    CRYPTO_CONFIGURATION = "CRYPTO_CONFIGURATION"
    CERTIFICATE_TRUST = "CERTIFICATE_TRUST"
    BEHAVIOURAL_CONSISTENCY = "BEHAVIOURAL_CONSISTENCY"


ISSUE_DIMENSION: Dict[IssueClass, RiskDimension] = {
    IssueClass.DEPRECATED_TLS_VERSION: RiskDimension.PROTOCOL_VERSION,
    IssueClass.TLS_VERSION_DEVIATION: RiskDimension.PROTOCOL_VERSION,
    IssueClass.PLAINTEXT_AUTH_EXPOSURE: RiskDimension.PLAINTEXT_EXPOSURE,
    IssueClass.NO_TLS_PROTECTION: RiskDimension.PLAINTEXT_EXPOSURE,
    IssueClass.STARTTLS_UPGRADE_FAILURE: RiskDimension.UPGRADE_INTEGRITY,
    IssueClass.STARTTLS_BEHAVIOUR_DEVIATION: RiskDimension.BEHAVIOURAL_CONSISTENCY,
    IssueClass.STARTTLS_ADVERTISEMENT: RiskDimension.UPGRADE_INTEGRITY,
    IssueClass.TLS_HANDSHAKE_EVIDENCE: RiskDimension.CRYPTO_CONFIGURATION,
    IssueClass.IMPLICIT_TLS_SESSION: RiskDimension.CRYPTO_CONFIGURATION,
    IssueClass.CERTIFICATE_OBSERVABILITY: RiskDimension.CERTIFICATE_TRUST,
    # Phase 11. No new RiskDimension is invented: certificate conditions sit on the
    # existing CERTIFICATE_TRUST axis and key-exchange conditions on CRYPTO_CONFIGURATION.
    IssueClass.KEY_EXCHANGE_MECHANISM: RiskDimension.CRYPTO_CONFIGURATION,
    IssueClass.FORWARD_SECRECY: RiskDimension.CRYPTO_CONFIGURATION,
    IssueClass.CERTIFICATE_EXTRACTION: RiskDimension.CERTIFICATE_TRUST,
    IssueClass.CERTIFICATE_VALIDITY: RiskDimension.CERTIFICATE_TRUST,
    IssueClass.CERTIFICATE_KEY_STRENGTH: RiskDimension.CERTIFICATE_TRUST,
    IssueClass.CERTIFICATE_SIGNATURE_ALGORITHM: RiskDimension.CERTIFICATE_TRUST,
    IssueClass.CERTIFICATE_CHAIN_STRUCTURE: RiskDimension.CERTIFICATE_TRUST,
    IssueClass.INSECURE_CONFIGURATION: RiskDimension.CRYPTO_CONFIGURATION,
    IssueClass.ANOMALY: RiskDimension.BEHAVIOURAL_CONSISTENCY,
    IssueClass.UNCLASSIFIED: RiskDimension.CRYPTO_CONFIGURATION,
}


# ---------------------------------------------------- certainty / observability
class EvidenceCertainty(str, Enum):
    """How well the capture supports the condition. **Independent of severity.**"""
    CONFIRMED = "CONFIRMED"            # every supporting field directly observed
    PROBABLE = "PROBABLE"              # at least one field inferred, none contradictory
    UNCERTAIN = "UNCERTAIN"            # ambiguous or incomplete supporting evidence
    UNDETERMINED = "UNDETERMINED"      # no usable supporting evidence


class Observability(str, Enum):
    """Whether the condition is *capable* of being observed passively at all."""
    OBSERVABLE = "OBSERVABLE"
    PARTIALLY_OBSERVABLE = "PARTIALLY_OBSERVABLE"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"


def certainty_from_refs(refs: Sequence[EvidenceRef]) -> EvidenceCertainty:
    """Derive certainty from the evidence states actually consulted.

    Fails toward less certainty: a single AMBIGUOUS or INCOMPLETE ref pulls the whole
    finding down to UNCERTAIN, because a conclusion is only as supported as its weakest
    load-bearing observation.
    """
    if not refs:
        return EvidenceCertainty.UNDETERMINED
    states = {r.evidence_state for r in refs}
    if states & {EvidenceState.AMBIGUOUS, EvidenceState.INCOMPLETE}:
        return EvidenceCertainty.UNCERTAIN
    if states <= {EvidenceState.UNKNOWN, EvidenceState.NOT_OBSERVABLE}:
        return EvidenceCertainty.UNDETERMINED
    if EvidenceState.INFERRED in states:
        return EvidenceCertainty.PROBABLE
    if EvidenceState.OBSERVED in states:
        return EvidenceCertainty.CONFIRMED
    return EvidenceCertainty.UNDETERMINED


def observability_from_status(status: FindingStatus,
                              refs: Sequence[EvidenceRef]) -> Observability:
    if status is FindingStatus.NOT_OBSERVABLE:
        return Observability.NOT_OBSERVABLE
    if any(r.evidence_state is EvidenceState.NOT_OBSERVABLE for r in refs):
        return Observability.PARTIALLY_OBSERVABLE
    return Observability.OBSERVABLE


# ------------------------------------------------------------------- sources
class SourceLane(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    CROSS_SESSION = "CROSS_SESSION"
    ML = "ML"


@dataclass(frozen=True)
class SourceRef:
    """A fused finding's pointer back to one contributing source.

    Provenance is never flattened: even a source classified `DUPLICATES` keeps its own
    finding id, frames and evidence refs, so an analyst can see every observation that
    supported a conclusion rather than only the first one encountered.
    """
    lane: SourceLane
    finding_id: str
    rule_id: str
    relation: Relation
    status: Optional[FindingStatus] = None
    severity: Optional[Severity] = None
    deviation: Optional[Deviation] = None
    stream_key: Optional[str] = None
    frames: Tuple[int, ...] = ()
    evidence_refs: Tuple[EvidenceRef, ...] = ()
    standards: Tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lane": self.lane.value, "finding_id": self.finding_id,
            "rule_id": self.rule_id, "relation": self.relation.value,
            "status": self.status.value if self.status else None,
            "severity": self.severity.value if self.severity else None,
            "deviation": self.deviation.value if self.deviation else None,
            "stream_key": self.stream_key, "frames": list(self.frames),
            "evidence_refs": [r.to_dict() for r in self.evidence_refs],
            "standards": list(self.standards), "detail": self.detail,
        }


@dataclass(frozen=True)
class MLSignal:
    """The ML lane's contribution. Ordering metadata and nothing else.

    Deliberately carries no severity and no status. Phase 6 (ADR-0015) measured zero
    unique true detections on every held-out split, so this is a *secondary
    prioritisation signal*: it may reorder findings within one severity tier and may
    not do anything else.
    """
    model_id: str
    model_version: str
    anomaly_score: Optional[float]
    threshold: Optional[float]
    band: AnomalyBand
    model_artifact_hash: str = ""
    feature_schema_version: str = ""
    top_features: Tuple[str, ...] = ()
    basis: str = ""
    limitations: Tuple[str, ...] = (
        "secondary prioritisation signal only; ADR-0015 records zero unique true "
        "detections on every held-out split",
        "an anomaly is a statistical deviation from learned normal, not a "
        "vulnerability and not an attack",
    )

    @classmethod
    def from_result(cls, result: MLAnomalyResult) -> "MLSignal":
        return cls(
            model_id=result.model_id, model_version=result.model_version,
            anomaly_score=result.anomaly_score, threshold=result.threshold,
            band=result.band, model_artifact_hash=result.model_artifact_hash,
            feature_schema_version=result.feature_schema_version,
            top_features=tuple(c.feature_id for c in result.top_features),
            basis=result.basis)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id, "model_version": self.model_version,
            "anomaly_score": self.anomaly_score, "threshold": self.threshold,
            "band": self.band.value,
            "model_artifact_hash": self.model_artifact_hash,
            "feature_schema_version": self.feature_schema_version,
            "top_features": list(self.top_features), "basis": self.basis,
            "limitations": list(self.limitations),
        }


# ------------------------------------------------------------ fused finding
@dataclass(frozen=True)
class IssueKey:
    """Content identity used for deduplication.

    Keyed on the issue class and the scope, never on a finding id. Two findings
    describing the same condition in the same session therefore fuse into one entry
    regardless of how many rules or lanes produced them.
    """
    issue_class: IssueClass
    fact_kind: FactKind
    scope_key: Optional[str]              # stream_key at session scope

    def as_tuple(self) -> Tuple:
        return (self.issue_class.value, self.fact_kind.value, self.scope_key)

    def to_dict(self) -> Dict[str, Any]:
        return {"issue_class": self.issue_class.value,
                "fact_kind": self.fact_kind.value, "scope_key": self.scope_key}


@dataclass(frozen=True)
class StandardCitation:
    """Structured view of a standards string already emitted by a Phase-4 rule.

    The `text` field is the verbatim string the rule produced. Phase 7 adds structure
    around it; it never rewrites it and never introduces a standard a rule did not cite.
    """
    standard: str
    section: str
    reason: str
    text: str

    def to_dict(self) -> Dict[str, Any]:
        return {"standard": self.standard, "section": self.section,
                "reason": self.reason, "text": self.text}


@dataclass(frozen=True)
class RemediationGuidance:
    """Rule-bound remediation (A-05). Never generic security advice."""
    observed: str
    why_it_matters: str
    recommended_action: str
    affected_scope: str
    verification: str
    citations: Tuple[StandardCitation, ...] = ()
    limitations: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"observed": self.observed, "why_it_matters": self.why_it_matters,
                "recommended_action": self.recommended_action,
                "affected_scope": self.affected_scope,
                "verification": self.verification,
                "citations": [c.to_dict() for c in self.citations],
                "limitations": list(self.limitations)}


@dataclass(frozen=True)
class FusedFinding:
    """One coherent fact about one session, with every contributing source retained."""

    key: IssueKey
    title: str
    conclusion: str
    explanation: str
    severity: Severity
    status: FindingStatus
    certainty: EvidenceCertainty
    observability: Observability
    dimension: RiskDimension

    capture_id: str
    stream_key: Optional[str] = None
    protocol: Optional[str] = None
    tcp_stream_id: Optional[int] = None

    sources: Tuple[SourceRef, ...] = ()
    citations: Tuple[StandardCitation, ...] = ()
    ml_signal: Optional[MLSignal] = None
    remediation: Optional[RemediationGuidance] = None
    limitations: Tuple[str, ...] = ()
    contradictions: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # The Phase-4 invariant, re-asserted at the fusion boundary rather than assumed:
        # fusion must not be a way to smuggle severity onto an unestablished condition.
        if self.status is not FindingStatus.OBSERVED_ISSUE and self.severity is not Severity.INFO:
            raise ValueError(
                f"{self.key.issue_class.value}: status {self.status.value} may not "
                f"carry severity {self.severity.value}")
        if self.penalising and not self.citations:
            raise ValueError(
                f"{self.key.issue_class.value}: a penalising finding must cite a standard")
        if not self.sources:
            raise ValueError(
                f"{self.key.issue_class.value}: a fused finding must retain its sources")
        # An anomaly signal may never be a base issue, whatever else happens upstream.
        if self.key.fact_kind is FactKind.ANOMALY_SIGNAL and self.penalising:
            raise ValueError("an anomaly signal may never penalise the posture score")

    @property
    def penalising(self) -> bool:
        """Only an established issue contributes to the score. Nothing else, ever."""
        return (self.status is FindingStatus.OBSERVED_ISSUE
                and self.key.fact_kind in (FactKind.BASE_SECURITY_ISSUE,
                                           FactKind.BEHAVIOURAL_DEVIATION))

    @property
    def all_frames(self) -> Tuple[int, ...]:
        seen: List[int] = []
        for source in self.sources:
            for frame in source.frames:
                if frame not in seen:
                    seen.append(frame)
        return tuple(sorted(seen))

    @property
    def source_rule_ids(self) -> Tuple[str, ...]:
        return tuple(sorted({s.rule_id for s in self.sources}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key.to_dict(),
            "title": self.title, "conclusion": self.conclusion,
            "explanation": self.explanation,
            "severity": self.severity.value, "status": self.status.value,
            "certainty": self.certainty.value,
            "observability": self.observability.value,
            "dimension": self.dimension.value,
            "penalising": self.penalising,
            "session": {"capture_id": self.capture_id, "stream_key": self.stream_key,
                        "protocol": self.protocol,
                        "tcp_stream_id": self.tcp_stream_id},
            "frames": list(self.all_frames),
            "source_rule_ids": list(self.source_rule_ids),
            "sources": [s.to_dict() for s in self.sources],
            "citations": [c.to_dict() for c in self.citations],
            "ml_signal": self.ml_signal.to_dict() if self.ml_signal else None,
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "limitations": list(self.limitations),
            "contradictions": list(self.contradictions),
        }


# ------------------------------------------------------------- issue groups
@dataclass(frozen=True)
class IssueGroup:
    """All fused findings of one issue class across a population.

    Scoring operates on groups, not instances. One misconfigured server observed in 200
    sessions is one configuration problem, and penalising it 200 times would make the
    score a function of capture length rather than of security posture.
    """
    issue_class: IssueClass
    fact_kind: FactKind
    dimension: RiskDimension
    severity: Severity                      # highest severity in the group
    title: str
    findings: Tuple[FusedFinding, ...]
    affected_stream_keys: Tuple[str, ...]
    protocols: Tuple[str, ...]
    certainty: EvidenceCertainty
    remediation: Optional[RemediationGuidance] = None
    citations: Tuple[StandardCitation, ...] = ()

    @property
    def recurrence(self) -> int:
        return len(self.affected_stream_keys)

    @property
    def penalising(self) -> bool:
        return any(f.penalising for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issue_class": self.issue_class.value,
            "fact_kind": self.fact_kind.value,
            "dimension": self.dimension.value,
            "severity": self.severity.value, "title": self.title,
            "certainty": self.certainty.value,
            "recurrence": self.recurrence,
            "affected_stream_keys": list(self.affected_stream_keys),
            "protocols": list(self.protocols),
            "penalising": self.penalising,
            "citations": [c.to_dict() for c in self.citations],
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "finding_count": len(self.findings),
        }


# -------------------------------------------------------------- abstentions
class AbstentionReason(str, Enum):
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    AMBIGUOUS_EVIDENCE = "AMBIGUOUS_EVIDENCE"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"
    INSUFFICIENT_CAPTURE = "INSUFFICIENT_CAPTURE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    UNSUPPORTED_PROTOCOL_VARIANT = "UNSUPPORTED_PROTOCOL_VARIANT"
    NOT_COMPARABLE = "NOT_COMPARABLE"


@dataclass(frozen=True)
class Abstention:
    """An explicit refusal to conclude. Never silently discarded.

    Carries `resolved_by` because an abstention an analyst cannot act on is just a gap:
    the point is to say what additional evidence would settle the question.
    """
    reason: AbstentionReason
    issue_class: IssueClass
    what_could_not_be_concluded: str
    why: str
    resolved_by: str
    rule_id: str = ""
    stream_key: Optional[str] = None
    protocol: Optional[str] = None
    frames: Tuple[int, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"reason": self.reason.value, "issue_class": self.issue_class.value,
                "what_could_not_be_concluded": self.what_could_not_be_concluded,
                "why": self.why, "resolved_by": self.resolved_by,
                "rule_id": self.rule_id, "stream_key": self.stream_key,
                "protocol": self.protocol, "frames": list(self.frames)}


# ---------------------------------------------------------- evidence coverage
@dataclass(frozen=True)
class EvidenceCoverage:
    """How much of the traffic the analysis could actually see.

    Reported beside the score, never folded into it. A score of 90 over 20 % observable
    traffic and a score of 90 over 95 % observable traffic are different claims, and the
    contract makes the difference visible rather than arithmetically hidden.
    """
    sessions_total: int
    sessions_assessed: int
    sessions_abstained: int
    observation_counts: Dict[str, int] = field(default_factory=dict)
    completeness_counts: Dict[str, int] = field(default_factory=dict)
    protocol_counts: Dict[str, int] = field(default_factory=dict)

    @property
    def assessed_fraction(self) -> float:
        return self.sessions_assessed / self.sessions_total if self.sessions_total else 0.0

    @property
    def observation_fractions(self) -> Dict[str, float]:
        total = sum(self.observation_counts.values())
        if not total:
            return {}
        return {k: round(v / total, 4) for k, v in sorted(self.observation_counts.items())}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sessions_total": self.sessions_total,
            "sessions_assessed": self.sessions_assessed,
            "sessions_abstained": self.sessions_abstained,
            "assessed_fraction": round(self.assessed_fraction, 4),
            "observation_counts": dict(sorted(self.observation_counts.items())),
            "observation_fractions": self.observation_fractions,
            "completeness_counts": dict(sorted(self.completeness_counts.items())),
            "protocol_counts": dict(sorted(self.protocol_counts.items())),
        }


# ------------------------------------------------------------------ posture
class PostureBand(str, Enum):
    """Coarse posture verdict.

    `INSUFFICIENT_EVIDENCE` is a band, not a score of zero: refusing to grade a capture
    that shows too little is different from grading it badly.
    """
    STRONG = "STRONG"
    ADEQUATE = "ADEQUATE"
    WEAK = "WEAK"
    CRITICAL = "CRITICAL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class ScoreComponent:
    """One decomposable contribution to the score. The score is the sum of these."""
    issue_class: IssueClass
    severity: Severity
    recurrence: int
    base_weight: float
    recurrence_multiplier: float
    penalty: float
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {"issue_class": self.issue_class.value, "severity": self.severity.value,
                "recurrence": self.recurrence,
                "base_weight": round(self.base_weight, 4),
                "recurrence_multiplier": round(self.recurrence_multiplier, 4),
                "penalty": round(self.penalty, 4), "explanation": self.explanation}


@dataclass(frozen=True)
class PostureScore:
    """A number an analyst can take apart. Never a mysterious 0-100."""
    value: float
    band: PostureBand
    formula_id: str
    starting_value: float
    total_penalty: float
    components: Tuple[ScoreComponent, ...] = ()
    basis: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"value": round(self.value, 2), "band": self.band.value,
                "formula_id": self.formula_id,
                "starting_value": self.starting_value,
                "total_penalty": round(self.total_penalty, 4),
                "components": [c.to_dict() for c in self.components],
                "basis": self.basis}


@dataclass(frozen=True)
class ProtocolPosture:
    """Per-protocol posture. Only dimensions the evidence layer supports."""
    protocol: str
    sessions: int
    score: Optional[PostureScore]
    issue_classes: Tuple[str, ...] = ()
    dimensions_assessed: Tuple[str, ...] = ()
    dimensions_not_observable: Tuple[str, ...] = ()
    abstentions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"protocol": self.protocol, "sessions": self.sessions,
                "score": self.score.to_dict() if self.score else None,
                "issue_classes": list(self.issue_classes),
                "dimensions_assessed": list(self.dimensions_assessed),
                "dimensions_not_observable": list(self.dimensions_not_observable),
                "abstentions": self.abstentions}


@dataclass(frozen=True)
class PrioritisedFinding:
    """One ranked unit of analyst work (A-04).

    Ranking is per ISSUE GROUP, not per session. One deprecated TLS version observed in
    200 sessions is one thing to fix, and emitting 200 identical ranked rows would bury
    the other findings while telling an analyst nothing extra. `finding` is the
    group's highest-severity representative; `affected_sessions` gives the true scope,
    and every individual session remains in `IssueGroup.findings` and `fused_findings`.
    """
    rank: int
    priority_score: float
    finding: FusedFinding
    affected_sessions: int = 1
    affected_stream_keys: Tuple[str, ...] = ()
    factors: Dict[str, float] = field(default_factory=dict)
    ml_adjustment: float = 0.0
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"rank": self.rank, "priority_score": round(self.priority_score, 4),
                "affected_sessions": self.affected_sessions,
                "affected_stream_keys": list(self.affected_stream_keys),
                "factors": {k: round(v, 4) for k, v in sorted(self.factors.items())},
                "ml_adjustment": round(self.ml_adjustment, 4),
                "explanation": self.explanation,
                "representative_finding": self.finding.to_dict()}


@dataclass(frozen=True)
class PostureAssessment:
    """The canonical posture object. Later phases consume this and recompute nothing."""

    assessment_id: str
    capture_id: str
    run_id: Optional[str]
    generated_at: str
    schema_version: str = POSTURE_SCHEMA_VERSION
    engine_version: str = POSTURE_ENGINE_VERSION

    score: Optional[PostureScore] = None
    fused_findings: Tuple[FusedFinding, ...] = ()
    issue_groups: Tuple[IssueGroup, ...] = ()
    prioritised: Tuple[PrioritisedFinding, ...] = ()
    abstentions: Tuple[Abstention, ...] = ()
    coverage: Optional[EvidenceCoverage] = None
    protocol_posture: Tuple[ProtocolPosture, ...] = ()

    risk_summary: Dict[str, Any] = field(default_factory=dict)
    standards_summary: Dict[str, Any] = field(default_factory=dict)
    remediation_summary: Tuple[RemediationGuidance, ...] = ()
    model_summary: Optional[Dict[str, Any]] = None
    provenance: Dict[str, Any] = field(default_factory=dict)
    limitations: Tuple[str, ...] = ()
    ai_enabled: bool = False

    @property
    def band(self) -> PostureBand:
        return self.score.band if self.score else PostureBand.INSUFFICIENT_EVIDENCE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "capture_id": self.capture_id,
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "versions": {"schema": self.schema_version, "engine": self.engine_version},
            "ai_enabled": self.ai_enabled,
            "overall_posture": self.band.value,
            "score": self.score.to_dict() if self.score else None,
            "coverage": self.coverage.to_dict() if self.coverage else None,
            "risk_summary": self.risk_summary,
            "issue_groups": [g.to_dict() for g in self.issue_groups],
            "prioritised": [p.to_dict() for p in self.prioritised],
            "abstentions": [a.to_dict() for a in self.abstentions],
            "protocol_posture": [p.to_dict() for p in self.protocol_posture],
            "standards_summary": self.standards_summary,
            "remediation_summary": [r.to_dict() for r in self.remediation_summary],
            "model_summary": self.model_summary,
            "provenance": self.provenance,
            "limitations": list(self.limitations),
        }
