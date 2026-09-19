"""
scikit-learn backed candidates (Phase-6 §14), behind an optional import.

Keeping these out of `ml.models` preserves the core package's zero-dependency property:
importing `securemailscope.ml` never requires scikit-learn, and a deployment that only
uses the stdlib model never installs it. Importing *this* module without scikit-learn
raises a clear, actionable error rather than an opaque ImportError deep in a call stack.

None of these models explains itself natively. Attribution for them is produced by the
engine's model-agnostic perturbation method (`ml.explain`), and is reported as
association, never causation (§23).
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from securemailscope.ml.models import AnomalyModel


def _require_sklearn():
    try:
        import sklearn  # noqa: F401
        import numpy as np
        return np, sklearn
    except ImportError as exc:      # pragma: no cover - environment dependent
        raise ImportError(
            "scikit-learn and numpy are required for the sklearn-backed anomaly "
            "candidates. The stdlib RobustZScoreModel in securemailscope.ml.models "
            "has no such requirement. Install with: pip install scikit-learn"
        ) from exc


class _SklearnModel(AnomalyModel):
    """Shared plumbing: fit on an array, expose a higher-is-more-anomalous score."""

    library = "scikit-learn"

    def __init__(self, seed: int = 42, **params: object) -> None:
        self._np, sklearn = _require_sklearn()
        self.library_version = sklearn.__version__
        self.seed = seed
        self.params: Dict[str, object] = dict(params)
        self._est = None

    @property
    def fitted(self) -> bool:
        return self._est is not None

    @property
    def config(self) -> Dict[str, object]:
        return {"seed": self.seed, **self.params}

    def _build(self):                                    # pragma: no cover - overridden
        raise NotImplementedError

    def fit(self, rows: Sequence[Sequence[float]]) -> "_SklearnModel":
        if not rows:
            raise ValueError("cannot fit on an empty training set")
        X = self._np.asarray(rows, dtype=float)
        self._est = self._build()
        self._est.fit(X)
        return self

    def score(self, rows: Sequence[Sequence[float]]) -> List[float]:
        if not self.fitted:
            raise RuntimeError("model is not fitted")
        X = self._np.asarray(rows, dtype=float)
        # score_samples is "higher = more normal" across these estimators, so negate
        # once here and keep the project-wide convention everywhere else.
        return [float(-v) for v in self._est.score_samples(X)]


class IsolationForestModel(_SklearnModel):
    """Re-tested benchmark, not the expected winner.

    docs/research/10B §9 rejected Isolation Forest on seven crude per-session binary
    features: 2/32 attacks against the deterministic engine's 8/32, with more false
    positives. It is included here to establish whether that result was a property of
    the model or of those features -- a question the original experiment could not
    separate (§16).
    """

    model_id = "isolation-forest"
    model_type = "isolation_forest"

    def __init__(self, seed: int = 42, n_estimators: int = 200,
                 max_samples: object = "auto", contamination: object = "auto") -> None:
        super().__init__(seed=seed, n_estimators=n_estimators,
                         max_samples=max_samples, contamination=contamination)

    def _build(self):
        from sklearn.ensemble import IsolationForest
        return IsolationForest(
            n_estimators=int(self.params["n_estimators"]),
            max_samples=self.params["max_samples"],
            contamination=self.params["contamination"],
            random_state=self.seed, n_jobs=1)


class LocalOutlierFactorModel(_SklearnModel):
    """Density-based. novelty=True so it scores unseen rows against the fitted set."""

    model_id = "lof"
    model_type = "local_outlier_factor"

    def __init__(self, seed: int = 42, n_neighbors: int = 20) -> None:
        super().__init__(seed=seed, n_neighbors=n_neighbors)

    def _build(self):
        from sklearn.neighbors import LocalOutlierFactor
        return LocalOutlierFactor(
            n_neighbors=int(self.params["n_neighbors"]), novelty=True, n_jobs=1)

    def fit(self, rows: Sequence[Sequence[float]]) -> "LocalOutlierFactorModel":
        # LOF needs more samples than neighbours; shrink rather than crash on a small
        # training population, and record what was actually used.
        n = len(rows)
        if n <= int(self.params["n_neighbors"]):
            self.params["n_neighbors"] = max(2, n - 1)
        return super().fit(rows)      # type: ignore[return-value]


class OneClassSVMModel(_SklearnModel):
    """Boundary model. Scaling-sensitive, so it is only meaningful on the same
    standardised matrix every candidate sees."""

    model_id = "ocsvm"
    model_type = "one_class_svm"

    def __init__(self, seed: int = 42, nu: float = 0.05, gamma: object = "scale") -> None:
        super().__init__(seed=seed, nu=nu, gamma=gamma)

    def _build(self):
        from sklearn.svm import OneClassSVM
        return OneClassSVM(nu=float(self.params["nu"]), gamma=self.params["gamma"],
                           kernel="rbf")


class EllipticEnvelopeModel(_SklearnModel):
    """Robust covariance (Mahalanobis distance under MinCovDet).

    Assumes a roughly elliptical normal region, which a wide one-hot matrix violates;
    included precisely so that assumption is tested rather than asserted.
    """

    model_id = "robust-covariance"
    model_type = "elliptic_envelope"

    def __init__(self, seed: int = 42, contamination: float = 0.05,
                 support_fraction: Optional[float] = None) -> None:
        super().__init__(seed=seed, contamination=contamination,
                         support_fraction=support_fraction)

    def _build(self):
        from sklearn.covariance import EllipticEnvelope
        return EllipticEnvelope(
            contamination=float(self.params["contamination"]),
            support_fraction=self.params["support_fraction"],
            random_state=self.seed)
