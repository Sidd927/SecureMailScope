"""
Posture scoring (A-03, Phase 7).

Three candidate formulations live here, all computed from the same `IssueGroup` inputs
so they can be compared on identical evidence. The selected one is `SELECTED_FORMULA`;
the others are retained because a score whose alternatives were never measured is an
assertion, not a decision. The comparison is in
`research/experiments/oq48/score_review.py` and the verdict in ADR-0016.

Four properties the score must have, and how they are obtained:

* **Decomposable** — the score is `starting_value - Σ ScoreComponent.penalty`, and every
  component names its issue class, severity, recurrence and arithmetic.
* **Deterministic** — pure arithmetic over sorted groups. No randomness, no clock, no
  model output.
* **Duplicate-resistant** — penalties are computed per *issue group*, never per finding
  instance, so re-reporting the same condition cannot move the score.
* **Never rewards missing evidence** — a capture in which nothing could be established
  does not score 100/STRONG; it returns `INSUFFICIENT_EVIDENCE`, which is a refusal to
  grade rather than a good grade.

Deliberately NOT inputs to the score: evidence certainty, observability, abstention
count and any ML signal. Lowering a score because evidence is incomplete would punish
the capture rather than the configuration, and raising one would reward blindness.
Coverage is reported beside the score instead (`EvidenceCoverage`).
"""
from __future__ import annotations

import math
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from securemailscope.analysis.model import Severity
from securemailscope.posture.model import (
    EvidenceCoverage, IssueGroup, PostureBand, PostureScore, ScoreComponent,
)

STARTING_VALUE = 100.0

#: Penalty weight per severity. Ratios, not absolutes: CRITICAL is worth two HIGHs, a
#: HIGH is worth about two and a half MEDIUMs. Chosen so that a single CRITICAL alone
#: drops a capture out of ADEQUATE, and a single MEDIUM alone does not.
SEVERITY_WEIGHT: Dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 12.0,
    Severity.HIGH: 28.0,
    Severity.CRITICAL: 55.0,
}

#: Ceiling on the recurrence multiplier. Recurrence is real evidence -- a weakness on
#: every session is worse than on one -- but it must not let capture length dominate:
#: an eight-hour capture of one misconfigured server is still one misconfigured server.
MAX_RECURRENCE_MULTIPLIER = 2.0

#: Band cut points, applied to the final score.
BAND_THRESHOLDS: Tuple[Tuple[float, PostureBand], ...] = (
    (90.0, PostureBand.STRONG),
    (75.0, PostureBand.ADEQUATE),
    (50.0, PostureBand.WEAK),
)


def _recurrence_multiplier(recurrence: int) -> float:
    """Sub-linear in the number of affected sessions, capped."""
    if recurrence <= 1:
        return 1.0
    return min(MAX_RECURRENCE_MULTIPLIER, 1.0 + math.log2(recurrence) / 4.0)


def _ordered(groups: Sequence[IssueGroup]) -> List[IssueGroup]:
    """Total order independent of input order: worst first, ties broken by name."""
    return sorted(
        (g for g in groups if g.penalising),
        key=lambda g: (-SEVERITY_WEIGHT[g.severity], -g.recurrence,
                       g.issue_class.value))


# ------------------------------------------------------------------ formulas
def formula_instance(groups: Sequence[IssueGroup]) -> Tuple[float, List[ScoreComponent]]:
    """F1 -- flat penalty per affected session.

    The obvious formulation, kept as a control. Its weakness is structural: penalty
    scales linearly with how long the capture ran, so the same server scores differently
    depending on how much traffic happened to be recorded.
    """
    components: List[ScoreComponent] = []
    for group in _ordered(groups):
        weight = SEVERITY_WEIGHT[group.severity]
        penalty = weight * group.recurrence
        components.append(ScoreComponent(
            issue_class=group.issue_class, severity=group.severity,
            recurrence=group.recurrence, base_weight=weight,
            recurrence_multiplier=float(group.recurrence), penalty=penalty,
            explanation=(f"{group.severity.value} weight {weight:g} applied once per "
                         f"each of {group.recurrence} affected session(s)")))
    return sum(c.penalty for c in components), components


def formula_group_damped(groups: Sequence[IssueGroup]
                         ) -> Tuple[float, List[ScoreComponent]]:
    """F2 -- one penalty per issue group, with damped recurrence.

    Recurrence still counts, but logarithmically and capped, so a configuration problem
    is scored as a configuration problem rather than as N problems.
    """
    components: List[ScoreComponent] = []
    for group in _ordered(groups):
        weight = SEVERITY_WEIGHT[group.severity]
        multiplier = _recurrence_multiplier(group.recurrence)
        penalty = weight * multiplier
        components.append(ScoreComponent(
            issue_class=group.issue_class, severity=group.severity,
            recurrence=group.recurrence, base_weight=weight,
            recurrence_multiplier=multiplier, penalty=penalty,
            explanation=(f"{group.severity.value} weight {weight:g} x recurrence "
                         f"multiplier {multiplier:.2f} for {group.recurrence} "
                         f"affected session(s)")))
    return sum(c.penalty for c in components), components


def formula_worst_dominant(groups: Sequence[IssueGroup]
                           ) -> Tuple[float, List[ScoreComponent]]:
    """F3 -- worst issue at full weight, each subsequent issue geometrically discounted.

    Prevents a long tail of moderate issues from driving the score to zero, and keeps
    the worst finding visible. The cost is that adding a genuine second problem barely
    moves the number, which makes the score less responsive than it looks.
    """
    components: List[ScoreComponent] = []
    for index, group in enumerate(_ordered(groups)):
        weight = SEVERITY_WEIGHT[group.severity]
        multiplier = _recurrence_multiplier(group.recurrence) * (0.5 ** index)
        penalty = weight * multiplier
        components.append(ScoreComponent(
            issue_class=group.issue_class, severity=group.severity,
            recurrence=group.recurrence, base_weight=weight,
            recurrence_multiplier=multiplier, penalty=penalty,
            explanation=(f"{group.severity.value} weight {weight:g} x recurrence and "
                         f"rank-{index} discount {multiplier:.3f}")))
    return sum(c.penalty for c in components), components


FORMULAS: Dict[str, Callable[[Sequence[IssueGroup]],
                             Tuple[float, List[ScoreComponent]]]] = {
    "F1-instance": formula_instance,
    "F2-group-damped": formula_group_damped,
    "F3-worst-dominant": formula_worst_dominant,
}

#: Selected by the ADR-0016 review. See that ADR for the comparison and the reasoning.
SELECTED_FORMULA = "F2-group-damped"


# --------------------------------------------------------------------- score
def band_for(score: float) -> PostureBand:
    for threshold, band in BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return PostureBand.CRITICAL


def compute_score(groups: Sequence[IssueGroup],
                  coverage: Optional[EvidenceCoverage] = None,
                  formula_id: str = SELECTED_FORMULA) -> PostureScore:
    """Score one scope. Refuses to grade when nothing was established.

    The refusal matters more than the arithmetic: a capture that shows nothing would
    otherwise score a clean 100 for the sole reason that no rule could fire, which would
    make blindness indistinguishable from security.
    """
    formula = FORMULAS.get(formula_id)
    if formula is None:
        raise ValueError(f"unknown scoring formula {formula_id!r}")

    if coverage is not None and coverage.sessions_assessed == 0:
        return PostureScore(
            value=0.0, band=PostureBand.INSUFFICIENT_EVIDENCE, formula_id=formula_id,
            starting_value=STARTING_VALUE, total_penalty=0.0, components=(),
            basis=("no session could be assessed; posture is not graded rather than "
                   "graded well, because absence of evidence is not evidence of "
                   "security"))

    penalty, components = formula(groups)
    value = max(0.0, STARTING_VALUE - penalty)
    band = band_for(value)
    if not components:
        basis = (f"{STARTING_VALUE:g} with no established security issue to penalise; "
                 "see evidence coverage for how much of the traffic this conclusion "
                 "rests on")
    else:
        basis = (f"{STARTING_VALUE:g} minus {penalty:.2f} across "
                 f"{len(components)} issue group(s) under {formula_id}")
    return PostureScore(value=value, band=band, formula_id=formula_id,
                        starting_value=STARTING_VALUE, total_penalty=penalty,
                        components=tuple(components), basis=basis)
