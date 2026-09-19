"""
Posture engine (Phase 7) -- the orchestrator that produces the canonical assessment.

    SessionEvidence[] + findings + cross-session findings + optional ML
        -> fusion -> risk classification -> scoring -> prioritisation -> remediation
        -> PostureAssessment

Design commitments enforced here rather than documented and hoped for:

* **`--no-ai` equivalence.** With `ai_enabled=False` the engine never reads an ML result.
  Findings, issue groups, risk summary, score and band are byte-identical to an
  AI-enabled run; only `PrioritisedFinding.ml_adjustment`, the ordering it induces and
  `model_summary` may differ. Asserted by test.

* **No circularity.** Nothing computed here is fed back upstream. The engine consumes
  findings and ML results; it never influences the rules, the baselines or the model.

* **Determinism.** Every collection is sorted on content, never on input order or dict
  iteration order. `generated_at` is injectable so a caller can produce byte-identical
  output for a golden test.

The engine owns no security logic. Every severity, standard and conclusion it emits was
produced by a Phase-4/5 rule or a Phase-7 remediation template authored in this
repository.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from securemailscope.analysis.model import SecurityFinding
from securemailscope.crosssession.model import CrossSessionFinding
from securemailscope.ml.contract import AnomalyBand, MLAnomalyResult
from securemailscope.posture import risk as risk_module
from securemailscope.posture import scoring
from securemailscope.posture import standards as standards_registry
from securemailscope.posture.fusion import FusionEngine
from securemailscope.posture.model import (
    POSTURE_ENGINE_VERSION, POSTURE_SCHEMA_VERSION, FactKind, PostureAssessment,
    PostureBand, RemediationGuidance, StandardCitation,
)
from securemailscope.posture.prioritise import PriorityRanker
from securemailscope.session.model import SessionEvidence

#: Carried on every assessment. These are boundaries of the method, not of this build,
#: and they are attached to the output so a report cannot be produced without them.
BASE_LIMITATIONS = (
    "passive analysis: conclusions describe what the capture shows, not the server's "
    "configuration",
    "no attacker, intent or attribution is or can be established from a packet capture",
    "certificate chain, expiry and key strength are not observable for TLS 1.3 or "
    "resumed sessions (RFC 8446 SS2, SS2.2)",
    "absence of a STARTTLS advertisement is ambiguous: stripping and genuine "
    "non-support are byte-identical at the application layer",
    "SecureMailScope cannot confirm that any remediation was applied or effective",
)

#: Attached only when the ML lane contributed. States the Phase-6 outcome verbatim so a
#: downstream report cannot present the model as a validated detector.
ML_LIMITATIONS = (
    "the ML lane is a secondary prioritisation signal only; Phase 6 (ADR-0015) measured "
    "zero unique true detections on every held-out split",
    "an anomaly score is a distance from a learned normal, not a vulnerability and not "
    "an attack",
    "the model was trained on synthetic corpora whose feature space is 98.6% separable "
    "by generator, so its generalisation to real traffic is unestablished",
)


@dataclass
class PostureConfig:
    """Explicit knobs. No magic constants are read from anywhere else."""
    ai_enabled: bool = False
    formula_id: str = scoring.SELECTED_FORMULA
    #: Emitted in `remediation_summary`, highest severity first.
    max_remediation_items: int = 20


class PostureEngine:
    """Build a `PostureAssessment`. Pure function of its inputs."""

    def __init__(self, config: Optional[PostureConfig] = None) -> None:
        self.config = config or PostureConfig()
        self.fusion = FusionEngine()
        self.ranker = PriorityRanker()

    def assess(self,
               sessions: Sequence[SessionEvidence] = (),
               findings: Sequence[SecurityFinding] = (),
               cross_findings: Sequence[CrossSessionFinding] = (),
               ml_results: Sequence[MLAnomalyResult] = (),
               capture_id: str = "",
               run_id: Optional[str] = None,
               generated_at: Optional[str] = None) -> PostureAssessment:
        # The --no-ai boundary: when disabled, ML results are dropped here and cannot
        # reach fusion, scoring or ranking by any path.
        ml_in = tuple(ml_results) if self.config.ai_enabled else ()

        fusion_result = self.fusion.fuse(findings, cross_findings, ml_in)
        fused = fusion_result.findings
        abstentions = fusion_result.abstentions

        groups = risk_module.group_findings(fused)
        coverage = risk_module.build_coverage(sessions, fused, abstentions)
        score = scoring.compute_score(groups, coverage, self.config.formula_id)

        prioritised = self.ranker.rank(groups, self.config.ai_enabled)

        capture = capture_id or self._infer_capture_id(sessions, fused)
        citations = self._all_citations(fused)
        limitations = BASE_LIMITATIONS + (ML_LIMITATIONS if ml_in else ())

        return PostureAssessment(
            assessment_id=self._assessment_id(capture, run_id, groups),
            capture_id=capture,
            run_id=run_id,
            generated_at=generated_at or datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            schema_version=POSTURE_SCHEMA_VERSION,
            engine_version=POSTURE_ENGINE_VERSION,
            score=score,
            fused_findings=fused,
            issue_groups=groups,
            prioritised=prioritised,
            abstentions=abstentions,
            coverage=coverage,
            protocol_posture=risk_module.protocol_posture(
                sessions, fused, abstentions, self.config.formula_id),
            risk_summary={**risk_module.risk_summary(groups, fused),
                          "abstentions": risk_module.abstention_summary(
                              abstentions)},
            standards_summary=standards_registry.summarise(citations),
            remediation_summary=self._remediation_summary(groups),
            model_summary=self._model_summary(ml_in),
            provenance=self._provenance(fusion_result, findings, cross_findings, ml_in),
            limitations=limitations,
            ai_enabled=self.config.ai_enabled,
        )

    # ---- helpers ------------------------------------------------------------
    def _infer_capture_id(self, sessions, fused) -> str:
        for session in sessions:
            if session.capture_id:
                return session.capture_id
        for finding in fused:
            if finding.capture_id:
                return finding.capture_id
        return ""

    def _assessment_id(self, capture_id, run_id, groups) -> str:
        """Content-addressed: the same evidence always yields the same id.

        A uuid would make two identical assessments look different, which would defeat
        the reproducibility property the whole pipeline is built around.
        """
        digest = hashlib.sha256()
        digest.update(f"{capture_id}|{run_id}|{POSTURE_SCHEMA_VERSION}".encode())
        for group in groups:
            digest.update(f"|{group.issue_class.value}:{group.fact_kind.value}"
                          f":{group.severity.value}:{group.recurrence}".encode())
        return digest.hexdigest()[:16]

    def _all_citations(self, fused) -> List[StandardCitation]:
        seen: Dict[tuple, StandardCitation] = {}
        for finding in fused:
            for citation in finding.citations:
                seen.setdefault((citation.standard, citation.text), citation)
        return sorted(seen.values(), key=lambda c: (c.standard, c.section, c.text))

    def _remediation_summary(self, groups):
        items: List[RemediationGuidance] = []
        for group in groups:
            if group.penalising and group.remediation is not None:
                items.append(group.remediation)
            if len(items) >= self.config.max_remediation_items:
                break
        return tuple(items)

    def _model_summary(self, ml_results: Sequence[MLAnomalyResult]):
        if not self.config.ai_enabled:
            return {"ai_enabled": False,
                    "note": "ML lane disabled; posture computed from deterministic and "
                            "cross-session evidence only"}
        if not ml_results:
            return {"ai_enabled": True, "results": 0,
                    "note": "ML lane enabled but no scored result was supplied"}
        scored = [r for r in ml_results if r.scored]
        bands: Dict[str, int] = {}
        for result in ml_results:
            bands[result.band.value] = bands.get(result.band.value, 0) + 1
        first = ml_results[0]
        return {
            "ai_enabled": True,
            "model_id": first.model_id,
            "model_version": first.model_version,
            "model_artifact_hash": first.model_artifact_hash,
            "feature_schema_version": first.feature_schema_version,
            "threshold": first.threshold,
            "results": len(ml_results),
            "scored": len(scored),
            "abstained": len(ml_results) - len(scored),
            "by_band": dict(sorted(bands.items())),
            "role": "secondary prioritisation signal only",
            "limitations": list(ML_LIMITATIONS),
        }

    def _provenance(self, fusion_result, findings, cross_findings, ml_results):
        return {
            "source_counts": {
                "deterministic_findings": len(findings),
                "cross_session_findings": len(cross_findings),
                "ml_results": len(ml_results),
                "fused_findings": len(fusion_result.findings),
                "abstentions": len(fusion_result.abstentions),
            },
            "duplicate_sources_merged": fusion_result.duplicate_count,
            "contradictions_recorded": fusion_result.contradiction_count,
            "rule_ids": sorted({f.rule_id for f in findings}
                               | {f.rule_id for f in cross_findings}),
            "versions": {
                "posture_schema": POSTURE_SCHEMA_VERSION,
                "posture_engine": POSTURE_ENGINE_VERSION,
                "scoring_formula": self.config.formula_id,
            },
            "note": ("every severity, status and standard originates in a Phase-4 or "
                     "Phase-5 rule; the posture engine aggregates and never re-judges"),
        }
