"""
Deterministic rule registry.

A rule is a small, independently testable unit that consumes one SessionEvidence and
returns zero or more SecurityFindings. Rules must be pure: no I/O, no network, no
randomness, no global mutable state, no ML. Same evidence + same rules version =>
same findings (Phase-4 §6).
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from securemailscope.analysis.model import (
    EvidenceRef, FindingStatus, SecurityFinding, Severity,
)
from securemailscope.evidence.states import EvidenceField
from securemailscope.session.model import SessionEvidence


class SecurityRule(ABC):
    """One deterministic security rule."""

    rule_id: str = ""
    title: str = ""
    description: str = ""
    standards: Tuple[str, ...] = ()

    def applies_to(self, session: SessionEvidence) -> bool:
        """Applicability gate. Default: every session."""
        return True

    @abstractmethod
    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        """Evaluate against one session. Must be pure and deterministic."""

    # ---- construction helper ------------------------------------------------
    def finding(
        self,
        session: SessionEvidence,
        *,
        status: FindingStatus,
        severity: Severity,
        conclusion: str,
        explanation: str,
        evidence_refs: Sequence[EvidenceRef],
        standards: Optional[Sequence[str]] = None,
        remediation: Optional[str] = None,
        limitations: Sequence[str] = (),
    ) -> SecurityFinding:
        """Build a finding with a deterministic, content-derived id.

        The id is a hash of (rule, capture, stream, status) so the same input always
        yields the same id -- required for reproducible reports and stable diffing.
        """
        seed = f"{self.rule_id}|{session.capture_id}|{session.tcp_stream_id}|{status.value}"
        finding_id = hashlib.sha256(seed.encode()).hexdigest()[:16]
        return SecurityFinding(
            finding_id=finding_id,
            rule_id=self.rule_id,
            title=self.title,
            status=status,
            severity=severity,
            conclusion=conclusion,
            explanation=explanation,
            standards=tuple(standards if standards is not None else self.standards),
            capture_id=session.capture_id,
            tcp_stream_id=session.tcp_stream_id,
            protocol=session.protocol,
            stream_key=session.stream_key,
            first_frame=session.first_frame,
            last_frame=session.last_frame,
            timestamp_epoch=session.start_epoch,
            evidence_refs=tuple(evidence_refs),
            remediation=remediation,
            limitations=tuple(limitations),
        )


def ref(field_name: str, evidence: EvidenceField) -> EvidenceRef:
    """Build an EvidenceRef directly from a Phase-3 EvidenceField, preserving its
    state, basis and frames verbatim. Rules must never restate evidence by hand."""
    return EvidenceRef(
        field_name=field_name,
        observed_value=None if evidence.value is None else str(evidence.value),
        evidence_state=evidence.state,
        frames=tuple(evidence.frames),
        basis=evidence.basis,
        provenance=evidence.provenance.value,
    )


class RuleRegistry:
    """Ordered, duplicate-checked collection of rules."""

    def __init__(self) -> None:
        self._rules: List[SecurityRule] = []
        self._ids: Dict[str, SecurityRule] = {}

    def register(self, rule: SecurityRule) -> SecurityRule:
        if not rule.rule_id:
            raise ValueError("rule must declare a rule_id")
        if rule.rule_id in self._ids:
            raise ValueError(f"duplicate rule id: {rule.rule_id}")
        self._ids[rule.rule_id] = rule
        self._rules.append(rule)
        return rule

    def get(self, rule_id: str) -> Optional[SecurityRule]:
        return self._ids.get(rule_id)

    @property
    def rules(self) -> Tuple[SecurityRule, ...]:
        # Stable order: registration order, so output ordering is deterministic.
        return tuple(self._rules)

    def __len__(self) -> int:
        return len(self._rules)
