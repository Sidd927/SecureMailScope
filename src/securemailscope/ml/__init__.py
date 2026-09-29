"""
ML anomaly lane (Phase 6).

Separate from the deterministic security lane by design (docs/architecture/16, ADR-0015).
This package may produce a score, a band and a feature attribution. It may not produce a
security fact, modify evidence, or contradict a deterministic finding.

Importing this package requires no third-party dependency. The scikit-learn candidates
live in `securemailscope.ml.sklearn_models` and are imported only on demand.
"""
from securemailscope.ml.contract import (
    ML_CONTRACT_VERSION, AnomalyBand, FeatureContribution, MLAnomalyResult,
    ModelArtifact, dataset_hash,
)
from securemailscope.ml.encoding import EncodedMatrix, FeatureEncoder
from securemailscope.ml.engine import (
    ML_ENGINE_VERSION, AnomalyConfig, AnomalyEngine, AnomalyReport,
)
from securemailscope.ml.features import (
    FEATURE_SCHEMA_VERSION, FEATURE_SPECS, CrossSessionContext, FeatureGroup,
    FeatureKind, FeatureSpec, LeakageRisk, MLFeatureExtractor, MLFeatureVector,
)
from securemailscope.ml.models import (
    AnomalyModel, MeanShiftBaselineModel, RobustZScoreModel,
)

__all__ = [
    "ML_CONTRACT_VERSION", "ML_ENGINE_VERSION", "FEATURE_SCHEMA_VERSION",
    "AnomalyBand", "AnomalyConfig", "AnomalyEngine", "AnomalyReport", "AnomalyModel",
    "CrossSessionContext", "EncodedMatrix", "FEATURE_SPECS", "FeatureContribution",
    "FeatureEncoder", "FeatureGroup", "FeatureKind", "FeatureSpec", "LeakageRisk",
    "MLAnomalyResult", "MLFeatureExtractor", "MLFeatureVector",
    "MeanShiftBaselineModel", "ModelArtifact", "RobustZScoreModel", "dataset_hash",
]
