"""
ML output contract (Phase-6 §27) and model artifact governance (§24).

`MLAnomalyResult` is deliberately NOT a `SecurityFinding`. It carries no severity, no
standards citation, no remediation and no status vocabulary from the deterministic lane.
That separation is the architectural boundary of the whole phase (§28, ADR-0006):

    deterministic rules  ->  standards-bound security FACTS
    ML anomaly lane      ->  a score, a band, and why the score is what it is

An anomaly is "unlike the learned normal for this context". It is not an attack, not a
misconfiguration, and not evidence that anything is wrong. Nothing downstream may read
`AnomalyBand.ANOMALOUS` as a verdict; the posture layer (Phase 8) consumes it through an
explicit, documented policy.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple

#: Bump when the anomaly result shape changes.
ML_CONTRACT_VERSION = "1.0"


class AnomalyBand(str, Enum):
    """Coarse band derived from score vs threshold.

    Deliberately three-valued plus an abstention. `NOT_SCORED` exists because refusing
    to score is a legitimate outcome -- a session whose evidence cannot support a
    comparison should produce no signal rather than a default one.
    """
    NORMAL = "NORMAL"
    BORDERLINE = "BORDERLINE"
    ANOMALOUS = "ANOMALOUS"
    NOT_SCORED = "NOT_SCORED"


@dataclass(frozen=True)
class FeatureContribution:
    """One feature's contribution to the score. Association, not causation (§23)."""
    column: str
    feature_id: str
    value: float
    contribution: float
    direction: str          # "above_normal" | "below_normal" | "differs_from_normal"

    def to_dict(self) -> dict:
        return {"column": self.column, "feature_id": self.feature_id,
                "value": round(self.value, 6),
                "contribution": round(self.contribution, 6),
                "direction": self.direction}


@dataclass(frozen=True)
class MLAnomalyResult:
    """Per-session anomaly signal with full reproducibility metadata."""
    session_key: Optional[str]
    capture_id: str
    model_id: str
    model_version: str
    feature_schema_version: str
    anomaly_score: Optional[float]
    threshold: Optional[float]
    band: AnomalyBand
    top_features: Tuple[FeatureContribution, ...] = ()
    basis: str = ""
    model_artifact_hash: str = ""
    layout_signature: str = ""

    def __post_init__(self) -> None:
        # Fail closed: a band other than NOT_SCORED must be backed by an actual score.
        if self.band is not AnomalyBand.NOT_SCORED and self.anomaly_score is None:
            raise ValueError("a scored band requires an anomaly_score")
        if self.band is AnomalyBand.NOT_SCORED and self.anomaly_score is not None:
            raise ValueError("NOT_SCORED must not carry a score")
        if not self.basis:
            raise ValueError("every anomaly result must record why it says what it says")

    @property
    def scored(self) -> bool:
        return self.band is not AnomalyBand.NOT_SCORED

    def to_dict(self) -> dict:
        return {
            "contract_version": ML_CONTRACT_VERSION,
            "session_key": self.session_key,
            "capture_id": self.capture_id,
            "model": {"id": self.model_id, "version": self.model_version,
                      "artifact_hash": self.model_artifact_hash},
            "feature_schema_version": self.feature_schema_version,
            "layout_signature": self.layout_signature,
            "anomaly_score": (round(self.anomaly_score, 6)
                              if self.anomaly_score is not None else None),
            "threshold": round(self.threshold, 6) if self.threshold is not None else None,
            "band": self.band.value,
            "top_features": [c.to_dict() for c in self.top_features],
            "basis": self.basis,
        }


@dataclass(frozen=True)
class ModelArtifact:
    """Reproducibility record for a trained model (Phase-6 §24, §25).

    Small on purpose. The goal is that a result can be traced to exactly the data,
    schema, seed and threshold that produced it -- not to build an MLOps platform.
    """
    model_id: str
    model_version: str
    model_type: str
    library: str
    library_version: str
    feature_schema_version: str
    layout_signature: str
    training_dataset_hash: str
    training_rows: int
    training_columns: int
    config: Dict[str, object] = field(default_factory=dict)
    seed: Optional[int] = None
    threshold: Optional[float] = None
    threshold_method: str = ""
    trained_at_utc: str = ""
    evaluation_dataset_hash: str = ""
    generator_split: Dict[str, object] = field(default_factory=dict)
    metrics: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id, "model_version": self.model_version,
            "model_type": self.model_type,
            "library": self.library, "library_version": self.library_version,
            "feature_schema_version": self.feature_schema_version,
            "layout_signature": self.layout_signature,
            "training": {"dataset_hash": self.training_dataset_hash,
                         "rows": self.training_rows, "columns": self.training_columns,
                         "seed": self.seed, "trained_at_utc": self.trained_at_utc},
            "config": {k: self.config[k] for k in sorted(self.config)},
            "threshold": {"value": self.threshold, "method": self.threshold_method},
            "evaluation": {"dataset_hash": self.evaluation_dataset_hash,
                           "generator_split": self.generator_split,
                           "metrics": self.metrics},
        }

    @property
    def artifact_hash(self) -> str:
        """Content hash over everything that determines behaviour."""
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


def dataset_hash(rows: Tuple[Tuple[float, ...], ...], columns: Tuple[str, ...]) -> str:
    """Content-addressed identity of a training/evaluation matrix.

    Rounded before hashing: float formatting differences across platforms must not
    change a dataset's identity, while a genuine data change still does.
    """
    h = hashlib.sha256()
    h.update("|".join(columns).encode())
    for row in rows:
        h.update(b"\n")
        h.update(",".join(f"{v:.6f}" for v in row).encode())
    return h.hexdigest()[:16]
