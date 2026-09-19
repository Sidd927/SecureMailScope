"""
Finding prioritisation (A-04, Phase 7).

Priority is **not** severity. Two HIGH findings are not equally urgent if one affects a
single session on uncertain evidence and the other recurs across an entire client
population on confirmed evidence. This module makes that difference explicit and
deterministic.

The ML boundary is enforced arithmetically, not by convention. `robust-z-sum` is a
secondary prioritisation signal (ADR-0015: zero unique true detections on every held-out
split), so its contribution is:

* **bounded** by `MAX_ML_ADJUSTMENT`, which is smaller than the gap between adjacent
  severity tiers, so an anomaly score can never reorder a HIGH below a MEDIUM;
* **additive only to the ordering number**, never to severity, status or score;
* **absent by default** -- with `--no-ai`, `ml_adjustment` is 0.0 for every finding and
  the ordering is fully determined by the deterministic factors.

No factor here is derived from the posture score, and the posture score is not derived
from priority. The dependency runs evidence -> findings -> priority, once, in one
direction.
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple

from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.ml.contract import AnomalyBand
from securemailscope.posture.model import (
    EvidenceCertainty, FactKind, FusedFinding, IssueGroup, PrioritisedFinding,
)

#: Base weight per severity. Gaps are wide so no other factor can cross a tier.
_SEVERITY_BASE: Dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 10.0,
    Severity.MEDIUM: 40.0,
    Severity.HIGH: 70.0,
    Severity.CRITICAL: 100.0,
}

#: Certainty modulates urgency without touching severity: a confirmed issue deserves an
#: analyst's time before an uncertain one of equal impact.
_CERTAINTY_FACTOR: Dict[EvidenceCertainty, float] = {
    EvidenceCertainty.CONFIRMED: 6.0,
    EvidenceCertainty.PROBABLE: 3.0,
    EvidenceCertainty.UNCERTAIN: 1.0,
    EvidenceCertainty.UNDETERMINED: 0.0,
}

#: A standards-bound weakness outranks a behavioural difference of equal severity.
_KIND_FACTOR: Dict[FactKind, float] = {
    FactKind.BASE_SECURITY_ISSUE: 5.0,
    FactKind.BEHAVIOURAL_DEVIATION: 2.0,
    FactKind.ANOMALY_SIGNAL: 0.0,
    FactKind.POSITIVE_EVIDENCE: 0.0,
    FactKind.ABSTENTION: 0.0,
}

#: Recurrence contribution, damped and capped for the same reason as in scoring:
#: capture length must not masquerade as urgency.
MAX_RECURRENCE_BONUS = 8.0

#: Hard ceiling on the ML contribution. Smaller than the narrowest severity gap
#: (MEDIUM 40 -> HIGH 70), so an anomaly score can shift order within a tier and never
#: across one. This number is the ML boundary made arithmetic.
MAX_ML_ADJUSTMENT = 4.0

#: Findings that are actionable at all. Positive evidence and abstentions are reported
#: elsewhere; ranking them alongside issues would bury the issues.
_RANKABLE = (FactKind.BASE_SECURITY_ISSUE, FactKind.BEHAVIOURAL_DEVIATION,
             FactKind.ANOMALY_SIGNAL)


def _recurrence_bonus(recurrence: int) -> float:
    if recurrence <= 1:
        return 0.0
    return min(MAX_RECURRENCE_BONUS, math.log2(recurrence) * 2.0)


def _ml_adjustment(finding: FusedFinding, ai_enabled: bool) -> float:
    """Bounded ordering nudge. Returns 0.0 whenever AI is disabled."""
    if not ai_enabled or finding.ml_signal is None:
        return 0.0
    signal = finding.ml_signal
    if signal.band is AnomalyBand.ANOMALOUS:
        return MAX_ML_ADJUSTMENT
    if signal.band is AnomalyBand.BORDERLINE:
        return MAX_ML_ADJUSTMENT / 2.0
    return 0.0


class PriorityRanker:
    """Deterministic ranking over issue groups. Order-independent by construction."""

    def rank(self, groups: Sequence[IssueGroup],
             ai_enabled: bool = False) -> Tuple[PrioritisedFinding, ...]:
        scored: List[Tuple[float, str, IssueGroup, FusedFinding,
                           Dict[str, float], float]] = []

        for group in groups:
            if group.fact_kind not in _RANKABLE:
                continue
            members = [f for f in group.findings if f.key.fact_kind in _RANKABLE]
            if not members:
                continue
            # Representative = worst severity, then most certain, then a stable key.
            representative = sorted(
                members,
                key=lambda f: (-_SEVERITY_BASE[f.severity],
                               -_CERTAINTY_FACTOR[f.certainty],
                               str(f.stream_key)))[0]
            factors = {
                "severity": _SEVERITY_BASE[group.severity],
                "certainty": _CERTAINTY_FACTOR[group.certainty],
                "fact_kind": _KIND_FACTOR[group.fact_kind],
                "recurrence": _recurrence_bonus(group.recurrence),
                "standards_backed": 3.0 if group.citations else 0.0,
                "actionable": 2.0 if group.remediation else 0.0,
            }
            adjustment = self._group_ml_adjustment(members, ai_enabled)
            total = sum(factors.values()) + adjustment
            # Tie-break on content, never on list position.
            tiebreak = f"{group.issue_class.value}|{group.fact_kind.value}"
            scored.append((total, tiebreak, group, representative, factors, adjustment))

        scored.sort(key=lambda t: (-t[0], t[1]))
        return tuple(
            PrioritisedFinding(
                rank=index + 1, priority_score=total, finding=representative,
                affected_sessions=group.recurrence,
                affected_stream_keys=group.affected_stream_keys,
                factors=factors, ml_adjustment=adjustment,
                explanation=self._explain(group, factors, adjustment, ai_enabled))
            for index, (total, _, group, representative, factors, adjustment)
            in enumerate(scored))

    def _group_ml_adjustment(self, members: Sequence[FusedFinding],
                             ai_enabled: bool) -> float:
        """Strongest bounded nudge across the group's sessions, or 0.0 without AI."""
        if not ai_enabled:
            return 0.0
        return max((_ml_adjustment(f, ai_enabled) for f in members), default=0.0)

    def _explain(self, group: IssueGroup, factors: Dict[str, float],
                 adjustment: float, ai_enabled: bool) -> str:
        parts = [f"{name} {value:g}" for name, value in sorted(factors.items())
                 if value]
        text = (f"{group.severity.value} {group.fact_kind.value} on "
                f"{group.certainty.value} evidence across {group.recurrence} "
                f"session(s); ranked on " + ", ".join(parts))
        if adjustment:
            text += (f"; ML prioritisation signal added {adjustment:g} "
                     f"(bounded at {MAX_ML_ADJUSTMENT:g}, cannot cross a severity tier)")
        elif ai_enabled:
            text += "; ML signal present but contributed nothing at this band"
        return text
