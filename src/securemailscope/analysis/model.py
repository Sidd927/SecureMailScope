"""
Security finding contract (Phase 4).

Two dimensions are kept deliberately orthogonal, because collapsing them is how
forensic tools start lying:

  * **Severity** -- how bad the condition would be IF it holds.
  * **Evidence state** -- how well the capture supports that it holds.

A finding may be HIGH severity on AMBIGUOUS evidence, or INFO severity on OBSERVED
evidence. Neither implies the other (Phase-4 §14).

`FindingStatus` adds a third axis: the analytic outcome. A forensic engine must be
able to return "we do not know" rather than forcing PASS/FAIL (Phase-4 §15).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from securemailscope.evidence.states import EvidenceState

#: Bumped when rule semantics change, so stored findings stay interpretable.
RULES_VERSION = "1.1"      # Phase 11: +8 rules, SEC-TLS-003 narrowed
ENGINE_VERSION = "0.5.0"


class Severity(str, Enum):
    """Impact if the condition holds. NOT a statement about confidence."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    """Analytic outcome for a rule against one session."""
    OBSERVED_ISSUE = "OBSERVED_ISSUE"              # positive evidence of a problem
    COMPLIANT = "COMPLIANT"                        # positive evidence of a good state
    INFORMATIONAL = "INFORMATIONAL"                # neutral, notable observation
    AMBIGUOUS = "AMBIGUOUS"                        # evidence supports >1 reading
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # capture cannot decide
    NOT_OBSERVABLE = "NOT_OBSERVABLE"              # structurally unobservable here


#: Statuses that must never carry a severity above INFO: we do not assert impact
#: for conditions we have not established.
_NON_ASSERTIVE = {
    FindingStatus.AMBIGUOUS,
    FindingStatus.INSUFFICIENT_EVIDENCE,
    FindingStatus.NOT_OBSERVABLE,
    FindingStatus.COMPLIANT,
    FindingStatus.INFORMATIONAL,
}


@dataclass(frozen=True)
class EvidenceRef:
    """Pointer from a finding back to the exact evidence that produced it."""
    field_name: str                  # SessionEvidence attribute consulted
    observed_value: Optional[str]    # what that field actually held
    evidence_state: EvidenceState    # the state of that field
    frames: Tuple[int, ...] = ()     # causing frame numbers
    basis: str = ""                  # why the field held that state
    #: WHERE the value came from. Added in Phase 11 because
    #: docs/research/01A SS4.1 makes this non-negotiable for certificate facts:
    #: "A tool that presents an actively retrieved certificate as if it were passively
    #: observed is making a false forensic claim." The Provenance enum has existed
    #: since Phase 2, but it stopped at the session layer and never reached a finding,
    #: so the distinction survived only in prose. Now it is structured and queryable.
    provenance: str = "none"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field_name,
            "observed_value": self.observed_value,
            "evidence_state": self.evidence_state.value,
            "frames": list(self.frames),
            "basis": self.basis,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class SecurityFinding:
    """One deterministic security conclusion about one session."""

    finding_id: str
    rule_id: str
    title: str
    status: FindingStatus
    severity: Severity
    conclusion: str                  # what the engine concludes, precisely worded
    explanation: str                 # concise analyst-facing reasoning
    standards: Tuple[str, ...]       # citable basis; empty only for INFORMATIONAL

    # session identity / provenance
    capture_id: str
    tcp_stream_id: Optional[int]
    protocol: Optional[str]
    stream_key: Optional[str] = None
    first_frame: Optional[int] = None
    last_frame: Optional[int] = None
    timestamp_epoch: Optional[float] = None

    evidence_refs: Tuple[EvidenceRef, ...] = ()
    remediation: Optional[str] = None
    limitations: Tuple[str, ...] = ()

    rules_version: str = RULES_VERSION
    engine_version: str = ENGINE_VERSION

    def __post_init__(self) -> None:
        # Invariant: unestablished conditions may not assert impact (§14/§15).
        if self.status in _NON_ASSERTIVE and self.severity is not Severity.INFO:
            raise ValueError(
                f"{self.rule_id}: status {self.status.value} may not carry severity "
                f"{self.severity.value}; only OBSERVED_ISSUE may assert impact")
        if self.status is FindingStatus.OBSERVED_ISSUE and not self.standards:
            raise ValueError(f"{self.rule_id}: an observed issue must cite a standards basis")
        if not self.evidence_refs:
            raise ValueError(f"{self.rule_id}: every finding must reference its evidence")

    @property
    def all_frames(self) -> Tuple[int, ...]:
        seen: List[int] = []
        for ref in self.evidence_refs:
            for frame in ref.frames:
                if frame not in seen:
                    seen.append(frame)
        return tuple(sorted(seen))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "conclusion": self.conclusion,
            "explanation": self.explanation,
            "standards": list(self.standards),
            "session": {
                "capture_id": self.capture_id,
                "tcp_stream_id": self.tcp_stream_id,
                "stream_key": self.stream_key,
                "protocol": self.protocol,
                "first_frame": self.first_frame,
                "last_frame": self.last_frame,
                "timestamp_epoch": self.timestamp_epoch,
            },
            "evidence_refs": [r.to_dict() for r in self.evidence_refs],
            "frames": list(self.all_frames),
            "remediation": self.remediation,
            "limitations": list(self.limitations),
            "versions": {
                "rules": self.rules_version,
                "engine": self.engine_version,
            },
        }
