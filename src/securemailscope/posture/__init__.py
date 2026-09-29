"""
Security posture layer (Phase 7).

`PostureAssessment` is the canonical output of SecureMailScope. The backend, dashboard
and report generators of later phases consume it and must never recompute posture
themselves -- if a conclusion is not in this object, the system has not made it.

The layer aggregates; it does not judge. Every severity, status and standards citation
originates in a Phase-4 or Phase-5 rule. The ML lane contributes bounded prioritisation
metadata and nothing else (ADR-0015).
"""
from securemailscope.posture.engine import (
    BASE_LIMITATIONS, ML_LIMITATIONS, PostureConfig, PostureEngine,
)
from securemailscope.posture.fusion import FusionEngine, FusionResult
from securemailscope.posture.model import (
    ISSUE_DIMENSION, POSTURE_ENGINE_VERSION, POSTURE_SCHEMA_VERSION, RULE_ISSUE_CLASS,
    Abstention, AbstentionReason, EvidenceCertainty, EvidenceCoverage, FactKind,
    FusedFinding, IssueClass, IssueGroup, IssueKey, MLSignal, Observability,
    PostureAssessment, PostureBand, PostureScore, PrioritisedFinding, ProtocolPosture,
    Relation, RemediationGuidance, RiskDimension, ScoreComponent, SourceLane, SourceRef,
    StandardCitation, certainty_from_refs, observability_from_status,
)
from securemailscope.posture.prioritise import MAX_ML_ADJUSTMENT, PriorityRanker
from securemailscope.posture.scoring import (
    FORMULAS, MIN_ASSESSED_FRACTION, SELECTED_FORMULA, SEVERITY_WEIGHT, band_for,
    compute_score,
)

__all__ = [
    "BASE_LIMITATIONS", "ML_LIMITATIONS", "FORMULAS", "ISSUE_DIMENSION",
    "MAX_ML_ADJUSTMENT", "MIN_ASSESSED_FRACTION", "POSTURE_ENGINE_VERSION",
    "POSTURE_SCHEMA_VERSION",
    "RULE_ISSUE_CLASS", "SELECTED_FORMULA", "SEVERITY_WEIGHT",
    "Abstention", "AbstentionReason", "EvidenceCertainty", "EvidenceCoverage",
    "FactKind", "FusedFinding", "FusionEngine", "FusionResult", "IssueClass",
    "IssueGroup", "IssueKey", "MLSignal", "Observability", "PostureAssessment",
    "PostureBand", "PostureConfig", "PostureEngine", "PostureScore",
    "PrioritisedFinding", "PriorityRanker", "ProtocolPosture", "Relation",
    "RemediationGuidance", "RiskDimension", "ScoreComponent", "SourceLane", "SourceRef",
    "StandardCitation", "band_for", "certainty_from_refs", "compute_score",
    "observability_from_status",
]
