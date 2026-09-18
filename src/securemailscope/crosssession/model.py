"""
Cross-session finding contract (Phase-5 §12).

Reuses the Phase-4 vocabulary (Severity, FindingStatus, EvidenceRef) rather than
duplicating it. What Phase 4 genuinely cannot represent is the *comparison provenance*:
which sessions formed the baseline, which controls were consulted, and why the
comparison was considered valid at all. That is the addition here.

A cross-session finding must always be able to answer: which historical sessions
established the baseline, which session deviated, and why were they comparable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from securemailscope.analysis.model import EvidenceRef, FindingStatus, Severity
from securemailscope.crosssession.baseline import Baseline
from securemailscope.crosssession.comparability import ComparabilityAssessment
from securemailscope.crosssession.contrast import ContrastResult

CROSS_RULES_VERSION = "1.0"
CROSS_ENGINE_VERSION = "0.5.0"


class Deviation(str, Enum):
    """What the comparison found. Deliberately separate from any security verdict:
    a difference is not an attack (Phase-5 final principle)."""
    NONE = "NONE"                       # behaviour matches the baseline
    DEVIATION = "DEVIATION"             # differs from a consistent baseline
    SUSPICIOUS_DEVIATION = "SUSPICIOUS_DEVIATION"  # differs AND contrast supports concern
    NOT_ASSESSED = "NOT_ASSESSED"       # no usable baseline / not comparable


@dataclass(frozen=True)
class CrossSessionFinding:
    """One comparison conclusion about one subject session."""

    finding_id: str
    rule_id: str
    title: str
    status: FindingStatus
    severity: Severity
    deviation: Deviation
    conclusion: str
    explanation: str

    # subject identity
    capture_id: str
    subject_stream_key: Optional[str]
    tcp_stream_id: Optional[int]
    protocol: Optional[str]

    # comparison provenance -- the reason this finding is permitted to exist
    comparability: Optional[Dict[str, Any]] = None
    baseline: Optional[Dict[str, Any]] = None
    contrast: Optional[Dict[str, Any]] = None

    evidence_refs: Tuple[EvidenceRef, ...] = ()
    standards: Tuple[str, ...] = ()
    limitations: Tuple[str, ...] = ()
    rules_version: str = CROSS_RULES_VERSION
    engine_version: str = CROSS_ENGINE_VERSION

    def __post_init__(self) -> None:
        # Same discipline as Phase 4: only an established issue may assert impact.
        if self.status is not FindingStatus.OBSERVED_ISSUE and self.severity is not Severity.INFO:
            raise ValueError(
                f"{self.rule_id}: status {self.status.value} may not carry severity "
                f"{self.severity.value}")
        # A comparison conclusion must name its comparison basis.
        if self.deviation in (Deviation.DEVIATION, Deviation.SUSPICIOUS_DEVIATION):
            if not self.baseline:
                raise ValueError(f"{self.rule_id}: a deviation must cite its baseline")
        if self.deviation is Deviation.SUSPICIOUS_DEVIATION and not self.contrast:
            raise ValueError(
                f"{self.rule_id}: a suspicious deviation must cite contrast evidence")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "deviation": self.deviation.value,
            "conclusion": self.conclusion,
            "explanation": self.explanation,
            "subject": {
                "capture_id": self.capture_id,
                "stream_key": self.subject_stream_key,
                "tcp_stream_id": self.tcp_stream_id,
                "protocol": self.protocol,
            },
            "comparability": self.comparability,
            "baseline": self.baseline,
            "contrast": self.contrast,
            "evidence_refs": [r.to_dict() for r in self.evidence_refs],
            "standards": list(self.standards),
            "limitations": list(self.limitations),
            "versions": {"rules": self.rules_version, "engine": self.engine_version},
        }
