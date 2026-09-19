"""
Model-agnostic explanation (Phase-6 §23).

An analyst cannot act on "the model said 0.87". They need to know which observed
behaviour made the session unlike normal, so they can go back to the frames and check.

Two mechanisms, in preference order:

1. **Native attribution**, when the model has one. `RobustZScoreModel` knows the
   per-feature z-scores that produced its own score, which is exact rather than
   estimated.

2. **Occlusion**, otherwise. Each column that differs from the training reference is
   reset to the reference value and the row is re-scored; the drop in score is that
   column's contribution. This is an *association* measure: it says the score depends on
   that column, not that the column caused anything in the world. The wording of every
   emitted explanation reflects that, and nothing here is permitted to phrase itself as
   a security conclusion (§28, §39).

Both paths are deterministic and require no extra dependency.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from securemailscope.ml.contract import FeatureContribution
from securemailscope.ml.models import AnomalyModel

#: Upper bound on occlusion probes per session. Wide one-hot rows can differ from the
#: reference in many columns; scoring every one of them turns explanation into the
#: dominant cost of analysis for no analytic gain past the leading few.
MAX_PROBES = 40


def reference_row(rows: Sequence[Sequence[float]]) -> Tuple[float, ...]:
    """Column-wise median of the training matrix: the 'typical normal' row."""
    from statistics import median
    if not rows:
        return ()
    return tuple(median([float(r[j]) for r in rows]) for j in range(len(rows[0])))


def explain(model: AnomalyModel,
            row: Sequence[float],
            columns: Sequence[str],
            column_to_feature: Dict[str, str],
            reference: Optional[Sequence[float]] = None,
            top_k: int = 5) -> Tuple[FeatureContribution, ...]:
    """Top contributing columns for one scored row."""
    native = model.contributions(row)
    if native:
        return _package(native[:top_k], row, columns, column_to_feature)

    if reference is None or len(reference) != len(row):
        # No native attribution and no reference to occlude against: say nothing rather
        # than fabricate an explanation.
        return ()
    return _occlusion(model, row, columns, column_to_feature, reference, top_k)


def _occlusion(model: AnomalyModel, row: Sequence[float], columns: Sequence[str],
               column_to_feature: Dict[str, str], reference: Sequence[float],
               top_k: int) -> Tuple[FeatureContribution, ...]:
    candidates = [j for j in range(len(row)) if float(row[j]) != float(reference[j])]
    if not candidates:
        return ()
    candidates.sort(key=lambda j: -abs(float(row[j]) - float(reference[j])))
    candidates = candidates[:MAX_PROBES]

    base = model.score([row])[0]
    probes = []
    for j in candidates:
        probe = list(row)
        probe[j] = float(reference[j])
        probes.append(probe)
    probed = model.score(probes)

    scored: List[Tuple[int, float, str]] = []
    for j, probe_score in zip(candidates, probed):
        delta = base - probe_score
        if delta <= 0:
            continue                      # this column did not raise the score
        direction = ("above_normal" if float(row[j]) > float(reference[j])
                     else "below_normal")
        scored.append((j, delta, direction))
    scored.sort(key=lambda t: -t[1])
    return _package(scored[:top_k], row, columns, column_to_feature)


def _package(items: Sequence[Tuple[int, float, str]], row: Sequence[float],
             columns: Sequence[str],
             column_to_feature: Dict[str, str]) -> Tuple[FeatureContribution, ...]:
    out = []
    for j, contribution, direction in items:
        column = columns[j] if j < len(columns) else f"col_{j}"
        out.append(FeatureContribution(
            column=column,
            feature_id=column_to_feature.get(column, column.split("=")[0]),
            value=float(row[j]),
            contribution=float(contribution),
            direction=direction,
        ))
    return tuple(out)
