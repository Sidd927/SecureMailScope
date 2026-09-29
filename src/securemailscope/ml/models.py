"""
Anomaly model interface and the dependency-free candidate (Phase-6 §14).

The core package has no runtime dependencies, and that property is worth keeping: a
forensic tool that must be installed from a wheel index is a tool that does not run in
the environments this one targets. So the *interface* and one complete, explainable
model live here in stdlib Python; the scikit-learn candidates live in
`ml.sklearn_models` behind a lazy import and are optional.

`RobustZScoreModel` is not a fallback. Per docs/architecture/05 §3 it is the prior
favourite on three grounds -- it is explainable feature-by-feature, it needs little
data, and it has the lowest synthetic-leakage risk of the candidates. Whether it
actually wins is decided by the bake-off, not here.

Score convention across every model: **higher means more anomalous.**
"""
from __future__ import annotations

import math
from abc import ABC, abstractmethod
from statistics import median
from typing import Dict, List, Optional, Sequence, Tuple

#: Consistency factor making the MAD a consistent estimator of sigma for normal data.
_MAD_TO_SIGMA = 1.4826

#: Score charged to a column that was perfectly constant in training when a scored
#: session differs from it. A constant column has no spread to measure, so a difference
#: is a categorical novelty rather than a distance; charging a fixed, documented amount
#: is honest, while dividing by zero or scoring 0.0 would not be.
_CONSTANT_NOVELTY = 3.0

#: Floor on the estimated scale. Without it, a column with a near-zero but non-zero MAD
#: produces enormous z-scores from trivial differences and dominates every explanation.
_MIN_SCALE = 1e-6


class AnomalyModel(ABC):
    """Common interface for every candidate (Phase-6 §14)."""

    model_id: str = "abstract"
    model_type: str = "abstract"
    library: str = "stdlib"
    library_version: str = ""

    @abstractmethod
    def fit(self, rows: Sequence[Sequence[float]]) -> "AnomalyModel":
        """Fit on NORMAL sessions only. Unsupervised: no labels are ever passed in."""

    @abstractmethod
    def score(self, rows: Sequence[Sequence[float]]) -> List[float]:
        """Higher = more anomalous."""

    def contributions(self, row: Sequence[float]) -> List[Tuple[int, float, str]]:
        """(column index, contribution, direction) for explanation.

        Default is empty: a model that cannot explain itself must say so rather than
        have the engine invent an attribution on its behalf.
        """
        return []

    @property
    def config(self) -> Dict[str, object]:
        return {}

    @property
    def fitted(self) -> bool:
        return False


class RobustZScoreModel(AnomalyModel):
    """Per-feature robust z-scores (median / MAD) aggregated into one score.

    Two aggregates, because the obvious one is wrong here:

    * `topk_mean` -- mean of the k largest absolute z-scores. The intuition is sound
      (a plain mean dilutes a real deviation across ~150 mostly-zero columns; a max
      lets one jittery column decide everything) but on this matrix it SATURATES; see
      `SATURATION_NOTE`.
    * `sum` -- total absolute deviation across every column. Keeps counting past the
      k-th column, so sessions that all saturate the top-k remain ordered by how many
      features they deviate on.

    Which one is better was decided by the bake-off on held-out generators, not by
    this docstring: `sum` won on PR-AUC and is the configuration the engine defaults to.
    """

    SATURATION_NOTE = (
        "top-k mean SATURATES on a wide one-hot matrix. Most columns are constant in "
        "training, every constant-column deviation is charged exactly "
        "_CONSTANT_NOVELTY, so any session differing on >= top_k constant columns "
        "scores exactly that value -- identical to every other such session. Ranking "
        "resolution collapses precisely where it is needed. The 'sum' aggregate exists "
        "because of this; both are evaluated by the bake-off rather than assumed."
    )

    model_id = "robust-z"
    model_type = "robust_statistical"
    library = "stdlib"

    def __init__(self, top_k: int = 5, seed: Optional[int] = None,
                 aggregate: str = "topk_mean") -> None:
        if aggregate not in ("topk_mean", "sum"):
            raise ValueError(f"unknown aggregate {aggregate!r}")
        self.top_k = top_k
        self.aggregate = aggregate
        self.seed = seed              # unused: the model is deterministic by construction
        self._median: Tuple[float, ...] = ()
        self._scale: Tuple[float, ...] = ()
        self._constant: Tuple[bool, ...] = ()

    @property
    def fitted(self) -> bool:
        return bool(self._median)

    @property
    def config(self) -> Dict[str, object]:
        return {"top_k": self.top_k, "aggregate": self.aggregate,
                "mad_to_sigma": _MAD_TO_SIGMA,
                "constant_novelty": _CONSTANT_NOVELTY, "min_scale": _MIN_SCALE}

    def fit(self, rows: Sequence[Sequence[float]]) -> "RobustZScoreModel":
        if not rows:
            raise ValueError("cannot fit on an empty training set")
        n_cols = len(rows[0])
        if any(len(r) != n_cols for r in rows):
            raise ValueError("ragged training matrix: all rows must have equal width")
        meds, scales, constants = [], [], []
        for j in range(n_cols):
            column = [float(r[j]) for r in rows]
            m = median(column)
            mad = median([abs(v - m) for v in column])
            scale = _MAD_TO_SIGMA * mad
            constant = scale < _MIN_SCALE
            meds.append(m)
            scales.append(max(scale, _MIN_SCALE))
            constants.append(constant)
        self._median, self._scale, self._constant = (
            tuple(meds), tuple(scales), tuple(constants))
        return self

    def _z(self, row: Sequence[float]) -> List[float]:
        if not self.fitted:
            raise RuntimeError("model is not fitted")
        if len(row) != len(self._median):
            raise ValueError(
                f"width mismatch: row has {len(row)} columns, model expects "
                f"{len(self._median)}")
        out = []
        for j, value in enumerate(row):
            value = float(value)
            if self._constant[j]:
                out.append(0.0 if value == self._median[j] else _CONSTANT_NOVELTY)
            else:
                out.append((value - self._median[j]) / self._scale[j])
        return out

    def score(self, rows: Sequence[Sequence[float]]) -> List[float]:
        scores = []
        for row in rows:
            z = sorted((abs(v) for v in self._z(row)), reverse=True)
            if self.aggregate == "sum":
                # Total deviation. Unlike the top-k mean this keeps counting past the
                # k-th column, so two sessions that both saturate the top-k are still
                # ordered by HOW MANY features they deviate on (see SATURATION_NOTE).
                scores.append(sum(z))
            else:
                k = max(1, min(self.top_k, len(z)))
                scores.append(sum(z[:k]) / k)
        return scores

    def contributions(self, row: Sequence[float]) -> List[Tuple[int, float, str]]:
        z = self._z(row)
        ranked = sorted(range(len(z)), key=lambda j: -abs(z[j]))
        out = []
        for j in ranked:
            if abs(z[j]) < 1e-9:
                break
            if self._constant[j]:
                direction = "differs_from_normal"
            else:
                direction = "above_normal" if z[j] > 0 else "below_normal"
            out.append((j, abs(z[j]), direction))
        return out


class MeanShiftBaselineModel(AnomalyModel):
    """Deliberately weak control: distance from the training mean, no scaling.

    Included in the bake-off as a sanity floor. If a sophisticated candidate cannot
    beat unscaled Euclidean distance, the apparent signal is an artifact of the data,
    not of the model (§15, §32).
    """

    model_id = "mean-distance"
    model_type = "naive_distance"
    library = "stdlib"

    def __init__(self, seed: Optional[int] = None) -> None:
        self.seed = seed
        self._mean: Tuple[float, ...] = ()

    @property
    def fitted(self) -> bool:
        return bool(self._mean)

    def fit(self, rows: Sequence[Sequence[float]]) -> "MeanShiftBaselineModel":
        if not rows:
            raise ValueError("cannot fit on an empty training set")
        n = len(rows)
        self._mean = tuple(sum(float(r[j]) for r in rows) / n for j in range(len(rows[0])))
        return self

    def score(self, rows: Sequence[Sequence[float]]) -> List[float]:
        if not self.fitted:
            raise RuntimeError("model is not fitted")
        return [math.sqrt(sum((float(v) - self._mean[j]) ** 2
                              for j, v in enumerate(row)))
                for row in rows]
