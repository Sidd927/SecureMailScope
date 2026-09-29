"""
Anomaly engine (Phase-6 §27, §28) -- the ML lane's entry point.

    SessionEvidence[] -> Phase-5 context -> features -> encoding -> score -> band

Three boundaries are enforced structurally rather than by convention:

* **The engine never emits a finding.** Its output type is `MLAnomalyResult`, which has
  no severity, no standards field and no deterministic status vocabulary. Nothing here
  can modify, suppress or create a `SecurityFinding` -- the modules are not even
  imported (§28).

* **The engine abstains rather than guessing.** A truncated session, an unidentified
  protocol or a schema mismatch produces `NOT_SCORED`, not a default score. This is
  aimed squarely at the failure mode of the rejected 10B model, whose only distinctive
  output was re-flagging truncated captures: a capture artifact is a property of the
  capture, not of the traffic, so it must not become an anomaly.

* **Thresholds come from validation data, never from the data being scored.** A fitted
  engine carries its threshold; scoring cannot move it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from securemailscope.crosssession.baseline import (
    DEFAULT_MAX_HISTORY, DEFAULT_MIN_HISTORY, PopulationIndex, build_baseline, _order,
)
from securemailscope.crosssession.comparability import assess
from securemailscope.crosssession.contrast import evaluate_contrast
from securemailscope.ml.contract import (
    AnomalyBand, MLAnomalyResult, ModelArtifact, dataset_hash,
)
from securemailscope.ml.encoding import EncodedMatrix, FeatureEncoder
from securemailscope.ml.explain import explain, reference_row
from securemailscope.ml.features import (
    FEATURE_SCHEMA_VERSION, CrossSessionContext, FeatureGroup, MLFeatureExtractor,
    MLFeatureVector,
)
from securemailscope.ml.models import AnomalyModel, RobustZScoreModel
from securemailscope.session.model import Completeness, SessionEvidence

ML_ENGINE_VERSION = "0.1.0"

#: Band boundary as a fraction of the threshold. A session scoring within this margin
#: below the threshold is BORDERLINE rather than NORMAL: a hard cut would present a
#: score of 0.999*threshold as reassuringly normal, which it is not.
BORDERLINE_MARGIN = 0.15


@dataclass
class AnomalyConfig:
    """Explicit knobs. Every default is documented; none is tuned on test data."""
    groups: Tuple[FeatureGroup, ...] = tuple(FeatureGroup)
    exclude_features: Tuple[str, ...] = ()
    min_history: int = DEFAULT_MIN_HISTORY
    max_history: int = DEFAULT_MAX_HISTORY
    min_controls: int = 1
    top_k_explanations: int = 5
    #: Quantile of VALIDATION scores used as the anomaly threshold (§17).
    threshold_quantile: float = 0.95
    borderline_margin: float = BORDERLINE_MARGIN
    #: Score truncated sessions? Off by default, see the module docstring.
    score_truncated: bool = False


@dataclass
class AnomalyReport:
    capture_id: str
    results: List[MLAnomalyResult] = field(default_factory=list)
    sessions_seen: int = 0
    sessions_scored: int = 0
    abstentions: int = 0
    engine_version: str = ML_ENGINE_VERSION
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    model_id: str = ""
    model_artifact_hash: str = ""

    @property
    def abstention_rate(self) -> float:
        return self.abstentions / self.sessions_seen if self.sessions_seen else 0.0

    def band(self, band: AnomalyBand) -> List[MLAnomalyResult]:
        return [r for r in self.results if r.band is band]

    def to_dict(self) -> dict:
        return {
            "capture_id": self.capture_id,
            "versions": {"engine": self.engine_version,
                         "feature_schema": self.feature_schema_version},
            "model": {"id": self.model_id, "artifact_hash": self.model_artifact_hash},
            "counts": {
                "sessions_seen": self.sessions_seen,
                "sessions_scored": self.sessions_scored,
                "abstentions": self.abstentions,
                "abstention_rate": round(self.abstention_rate, 4),
                "by_band": {b.value: len(self.band(b)) for b in AnomalyBand
                            if self.band(b)},
            },
            "results": [r.to_dict() for r in self.results],
        }


class AnomalyEngine:
    """Fit once on normal traffic; score many captures."""

    def __init__(self, model: Optional[AnomalyModel] = None,
                 config: Optional[AnomalyConfig] = None) -> None:
        self.config = config or AnomalyConfig()
        #: Default is the configuration selected by the Phase-6 bake-off
        #: (docs/architecture/17 §5): robust z-scores aggregated by total deviation.
        self.model = model or RobustZScoreModel(aggregate="sum")
        self.encoder = FeatureEncoder(self.config.groups, self.config.exclude_features)
        self.extractor = MLFeatureExtractor(self.config.groups)
        self.threshold: Optional[float] = None
        self.threshold_method: str = ""
        self._reference: Tuple[float, ...] = ()
        self._artifact: Optional[ModelArtifact] = None

    # ---- context ------------------------------------------------------------
    def contexts(self, sessions: Sequence[SessionEvidence]
                 ) -> Dict[Optional[str], CrossSessionContext]:
        """Phase-5 derived context per session.

        Reuses the Phase-5 primitives rather than reimplementing them, so the ML lane
        and the deterministic cross-session lane always see the same baselines. Note
        these are baselines and contrasts -- measurements -- never findings (§5, §29).
        """
        ordered = sorted(sessions, key=_order)
        index = PopulationIndex(ordered)
        out: Dict[Optional[str], CrossSessionContext] = {}
        for subject in ordered:
            out[subject.stream_key] = CrossSessionContext(
                comparability=assess(subject),
                baseline=build_baseline(subject, ordered, self.config.min_history,
                                        index, self.config.max_history),
                contrast=evaluate_contrast(subject, ordered, self.config.min_controls,
                                           index, self.config.max_history),
            )
        return out

    def vectors(self, sessions: Sequence[SessionEvidence]) -> List[MLFeatureVector]:
        ctx = self.contexts(sessions)
        ordered = sorted(sessions, key=_order)
        return [self.extractor.extract(s, ctx.get(s.stream_key)) for s in ordered]

    def matrix(self, sessions: Sequence[SessionEvidence]) -> EncodedMatrix:
        return self.encoder.encode(self.vectors(sessions))

    # ---- abstention ---------------------------------------------------------
    #: Completeness values that mean "the capture does not show the whole session".
    #:
    #: Both are listed deliberately. Phase 6 established that `Completeness.TRUNCATED`
    #: is NEVER assigned by `session.base._finalise`, which only ever produces COMPLETE
    #: or INCOMPLETE -- the value exists in the enum and in hand-built test fixtures but
    #: no real capture can reach it (see docs/architecture/16 §9 and the Phase-5
    #: comparability guard it makes unreachable). Keying the ML abstention on TRUNCATED
    #: alone would therefore have been a rule that never fires. Rather than change
    #: deterministic semantics from inside the ML phase, the lane abstains on the value
    #: reality actually produces.
    _PARTIAL = (Completeness.TRUNCATED, Completeness.INCOMPLETE)

    def _abstain_reason(self, session: SessionEvidence) -> Optional[str]:
        if session.protocol is None:
            return ("no mail protocol identified for this stream; there is no learned "
                    "normal to compare it against")
        if session.completeness in self._PARTIAL and not self.config.score_truncated:
            return (f"session completeness is {session.completeness.value}; its shape "
                    "partly reflects where the capture begins or ends rather than how "
                    "the traffic behaved, so it is not scored")
        return None

    # ---- fit / threshold ----------------------------------------------------
    def fit(self, rows: Sequence[Sequence[float]],
            columns: Optional[Sequence[str]] = None,
            seed: Optional[int] = None) -> "AnomalyEngine":
        """Fit on an encoded matrix of NORMAL sessions. No labels are accepted."""
        if columns is not None and tuple(columns) != self.encoder.columns:
            raise ValueError("training matrix layout does not match the encoder schema")
        self.model.fit(rows)
        self._reference = reference_row(rows)
        self._artifact = ModelArtifact(
            model_id=self.model.model_id,
            model_version=ML_ENGINE_VERSION,
            model_type=self.model.model_type,
            library=self.model.library,
            library_version=getattr(self.model, "library_version", "") or "",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            layout_signature=self.encoder.layout_signature(),
            training_dataset_hash=dataset_hash(tuple(tuple(r) for r in rows),
                                               self.encoder.columns),
            training_rows=len(rows),
            training_columns=len(self.encoder.columns),
            config=dict(self.model.config),
            seed=seed if seed is not None else getattr(self.model, "seed", None),
            trained_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        return self

    def set_threshold(self, validation_rows: Sequence[Sequence[float]],
                      quantile: Optional[float] = None) -> float:
        """Select the threshold from VALIDATION scores (§17).

        Deliberately a separate call from `fit` and from scoring: a threshold chosen on
        the data being judged is not a threshold, it is a contamination assumption.
        """
        q = self.config.threshold_quantile if quantile is None else quantile
        if not 0.0 < q < 1.0:
            raise ValueError("threshold quantile must be in (0, 1)")
        scores = sorted(self.model.score(validation_rows))
        if not scores:
            raise ValueError("cannot select a threshold from an empty validation set")
        # Nearest-rank quantile: no interpolation, so the threshold is always a value
        # the model actually produced on real validation data.
        rank = max(0, min(len(scores) - 1, int(round(q * (len(scores) - 1)))))
        self.threshold = float(scores[rank])
        self.threshold_method = (
            f"nearest-rank quantile q={q} over {len(scores)} validation sessions")
        return self.threshold

    def set_threshold_value(self, value: float, method: str) -> None:
        """Adopt an externally selected threshold, recording how it was chosen."""
        self.threshold = float(value)
        self.threshold_method = method

    @property
    def artifact(self) -> Optional[ModelArtifact]:
        if self._artifact is None:
            return None
        from dataclasses import replace
        return replace(self._artifact, threshold=self.threshold,
                       threshold_method=self.threshold_method)

    # ---- scoring ------------------------------------------------------------
    def _band(self, score: float) -> AnomalyBand:
        if self.threshold is None:
            return AnomalyBand.BORDERLINE
        if score >= self.threshold:
            return AnomalyBand.ANOMALOUS
        margin = abs(self.threshold) * self.config.borderline_margin
        if score >= self.threshold - margin:
            return AnomalyBand.BORDERLINE
        return AnomalyBand.NORMAL

    def analyse(self, sessions: Sequence[SessionEvidence],
                capture_id: str = "") -> AnomalyReport:
        ordered = sorted(sessions, key=_order)
        report = AnomalyReport(
            capture_id=capture_id or (ordered[0].capture_id if ordered else ""),
            model_id=self.model.model_id,
            model_artifact_hash=self.artifact.artifact_hash if self.artifact else "",
        )
        if not ordered:
            return report

        ctx = self.contexts(ordered)
        artifact_hash = report.model_artifact_hash
        layout = self.encoder.layout_signature()

        # Split first so abstaining sessions are never encoded, scored or explained.
        scorable: List[SessionEvidence] = []
        for session in ordered:
            report.sessions_seen += 1
            reason = self._abstain_reason(session)
            if reason is not None:
                report.abstentions += 1
                report.results.append(MLAnomalyResult(
                    session_key=session.stream_key, capture_id=session.capture_id,
                    model_id=self.model.model_id, model_version=ML_ENGINE_VERSION,
                    feature_schema_version=FEATURE_SCHEMA_VERSION,
                    anomaly_score=None, threshold=self.threshold,
                    band=AnomalyBand.NOT_SCORED, basis=reason,
                    model_artifact_hash=artifact_hash, layout_signature=layout))
            else:
                scorable.append(session)

        if not scorable:
            return report
        if not self.model.fitted:
            raise RuntimeError("anomaly engine has no fitted model; call fit() first")

        vectors = [self.extractor.extract(s, ctx.get(s.stream_key)) for s in scorable]
        matrix = self.encoder.encode(vectors)
        scores = self.model.score(matrix.rows)

        for session, row, score in zip(scorable, matrix.rows, scores):
            band = self._band(score)
            contributions = explain(
                self.model, row, self.encoder.columns, self.encoder.column_to_feature,
                self._reference, self.config.top_k_explanations)
            report.sessions_scored += 1
            report.results.append(MLAnomalyResult(
                session_key=session.stream_key, capture_id=session.capture_id,
                model_id=self.model.model_id, model_version=ML_ENGINE_VERSION,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                anomaly_score=float(score), threshold=self.threshold, band=band,
                top_features=contributions,
                basis=self._basis(band, score, contributions),
                model_artifact_hash=artifact_hash, layout_signature=layout))
        return report

    def _basis(self, band: AnomalyBand, score: float, contributions) -> str:
        """Plain-language basis. Describes distance from learned normal -- never a
        security conclusion, an attack, or an actor (§39)."""
        head = (f"anomaly score {score:.3f} "
                f"{'at or above' if band is AnomalyBand.ANOMALOUS else 'below'} "
                f"threshold {self.threshold:.3f}" if self.threshold is not None
                else f"anomaly score {score:.3f}; no threshold selected")
        if not contributions:
            return head + "; no single feature dominated the score"
        named = ", ".join(f"{c.feature_id} ({c.direction})" for c in contributions[:3])
        return (head + f"; score is most associated with {named}. "
                "Association with learned-normal deviation only; not a security verdict")
