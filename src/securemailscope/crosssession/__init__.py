"""Deterministic cross-session reasoning (Phase 5)."""
from securemailscope.crosssession.comparability import (
    Comparability, ComparabilityAssessment, ComparabilityKey, assess, comparable_pair, key_for,
)
from securemailscope.crosssession.baseline import (
    DEFAULT_MAX_HISTORY, DEFAULT_MIN_HISTORY, Baseline, BaselineStatus, FeatureSummary, SessionRef,
    build_baseline, prior_comparable, PopulationIndex,
)
from securemailscope.crosssession.contrast import (
    ContrastResult, ContrastState, evaluate_contrast, find_controls,
)
from securemailscope.crosssession.model import (
    CROSS_ENGINE_VERSION, CROSS_RULES_VERSION, CrossSessionFinding, Deviation,
)
from securemailscope.crosssession.rules import ALL_CROSS_RULES, BLIND_STRIPPING
from securemailscope.crosssession.engine import (
    CrossSessionConfig, CrossSessionEngine, CrossSessionReport,
)

__all__ = [
    "Comparability", "ComparabilityAssessment", "ComparabilityKey", "assess",
    "comparable_pair", "key_for",
    "DEFAULT_MAX_HISTORY", "DEFAULT_MIN_HISTORY", "Baseline", "BaselineStatus", "FeatureSummary", "SessionRef",
    "build_baseline", "prior_comparable", "PopulationIndex",
    "ContrastResult", "ContrastState", "evaluate_contrast", "find_controls",
    "CROSS_ENGINE_VERSION", "CROSS_RULES_VERSION", "CrossSessionFinding", "Deviation",
    "ALL_CROSS_RULES", "BLIND_STRIPPING",
    "CrossSessionConfig", "CrossSessionEngine", "CrossSessionReport",
]
