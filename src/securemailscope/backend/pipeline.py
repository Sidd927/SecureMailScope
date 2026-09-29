"""
PCAP -> PostureAssessment orchestration (doc 21 §4).

**This module composes. It does not analyse.**

The Phase-8 audit found that no production callable spanned the whole pipeline:
`analyze_capture()` stops at normalized frames and explicitly produces no verdicts, and
the only end-to-end composition in the repository was a helper inside
`tests/test_posture_corpora.py`. This module promotes that sequence into production code
with the same ordering and the same configuration.

What this module may do: call the existing engines in order and pass their outputs on.

What it may not do, and does not: subclass an engine, re-tune a parameter, edit an
intermediate result, interpret an ML score, compute a severity, or construct a
`SecurityFinding`, `CrossSessionFinding` or `PostureAssessment` by hand. Every security
statement it returns was produced by Phase 4-7 code.

The ML lane reproduces the Phase-7 procedure exactly — fit on the capture's own rows,
threshold at 0.95 — because §28 of the Phase-8 brief requires a backend result to equal a
direct invocation. Reproducing it is the point; improving it would break the guarantee
and would be a Phase-6 decision besides.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from securemailscope.analysis import SecurityAnalysisEngine
from securemailscope.analysis.model import SecurityFinding
from securemailscope.backend.errors import AnalysisFailed, TsharkUnavailable
from securemailscope.config import Config
from securemailscope.crosssession import CrossSessionEngine
from securemailscope.crosssession.model import CrossSessionFinding
from securemailscope.dissect import TsharkAdapter, TsharkNotFound, TsharkVersionError
from securemailscope.evidence.run import AnalysisRun, RunStatus
from securemailscope.ingest import analyze_capture
from securemailscope.ml.contract import MLAnomalyResult
from securemailscope.posture import PostureAssessment, PostureConfig, PostureEngine
from securemailscope.session import SessionEvidence, reconstruct_sessions

#: Threshold quantile for the ML lane. Mirrors the Phase-7 corpora tests verbatim.
ML_THRESHOLD_QUANTILE = 0.95


@dataclass
class PipelineResult:
    """Everything one analysis produced, plus stage timings."""
    run: AnalysisRun
    assessment: Optional[PostureAssessment]
    sessions: Sequence[SessionEvidence] = ()
    findings: Sequence[SecurityFinding] = ()
    cross_findings: Sequence[CrossSessionFinding] = ()
    ml_results: Sequence[MLAnomalyResult] = ()
    stage_ms: Dict[str, int] = field(default_factory=dict)

    @property
    def capture_id(self) -> str:
        return self.run.capture.capture_id


class _Timer:
    def __init__(self, sink: Dict[str, int], name: str) -> None:
        self.sink, self.name = sink, name

    def __enter__(self) -> "_Timer":
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.sink[self.name] = int((time.perf_counter() - self.start) * 1000)


def run_pipeline(path: str, *, ai_enabled: bool = False,
                 formula_id: Optional[str] = None,
                 run_id: Optional[str] = None,
                 config: Optional[Config] = None,
                 adapter: Optional[TsharkAdapter] = None) -> PipelineResult:
    """Run the existing engines end to end over one capture.

    `ai_enabled` defaults to False, matching `PostureConfig`. When False the ML lane is
    never constructed, so no model is loaded, fitted or consulted — the `--no-ai`
    boundary is honoured by not taking the branch, in addition to `PostureEngine`
    dropping ML results at the top of `assess()`.
    """
    stage_ms: Dict[str, int] = {}

    # --- ingest + dissection (Phase 2, unmodified) -------------------------
    with _Timer(stage_ms, "ingest"):
        try:
            run, frames = analyze_capture(path, config=config, adapter=adapter)
        except (TsharkNotFound, TsharkVersionError) as exc:
            raise TsharkUnavailable("tshark is unavailable or unsupported",
                                    detail={"reason": str(exc)})

    if run.status is RunStatus.FAILED:
        # Phase 2 already recorded why. Surfaced, never reinterpreted.
        reason = run.errors[-1] if run.errors else "ingest failed"
        if "tshark unavailable" in reason:
            raise TsharkUnavailable("tshark is unavailable or unsupported",
                                    detail={"reason": reason})
        raise AnalysisFailed("capture could not be analysed",
                             detail={"reason": reason,
                                     "ingest_status": run.status.value})

    capture_id = run.capture.capture_id

    # --- session reconstruction (Phase 3) ----------------------------------
    with _Timer(stage_ms, "sessions"):
        sessions = reconstruct_sessions(frames, capture_id)

    # --- deterministic security analysis (Phase 4) -------------------------
    with _Timer(stage_ms, "analysis"):
        findings = SecurityAnalysisEngine().analyse(sessions, capture_id).findings

    # --- cross-session reasoning (Phase 5) ---------------------------------
    with _Timer(stage_ms, "crosssession"):
        cross_findings = CrossSessionEngine().analyse(sessions, capture_id).findings

    # --- ML secondary signal (Phase 6), only when explicitly enabled -------
    ml_results: Tuple[MLAnomalyResult, ...] = ()
    if ai_enabled and sessions:
        with _Timer(stage_ms, "ml"):
            ml_results = _run_ml(sessions, capture_id)

    # --- fusion, scoring, prioritisation, remediation (Phase 7) ------------
    with _Timer(stage_ms, "posture"):
        posture_config = PostureConfig(ai_enabled=ai_enabled)
        if formula_id:
            posture_config = PostureConfig(ai_enabled=ai_enabled,
                                           formula_id=formula_id)
        assessment = PostureEngine(posture_config).assess(
            sessions, findings, cross_findings, ml_results,
            capture_id=capture_id, run_id=run_id)

    return PipelineResult(
        run=run, assessment=assessment, sessions=sessions, findings=findings,
        cross_findings=cross_findings, ml_results=ml_results, stage_ms=stage_ms)


def _run_ml(sessions: Sequence[SessionEvidence],
            capture_id: str) -> Tuple[MLAnomalyResult, ...]:
    """The Phase-7 ML procedure, reproduced exactly.

    Imported lazily so that a run with `ai_enabled=False` never touches the ML package.
    """
    from securemailscope.ml.engine import AnomalyEngine
    from securemailscope.ml.models import RobustZScoreModel

    engine = AnomalyEngine(RobustZScoreModel(aggregate="sum"))
    rows = engine.matrix(sessions).rows
    engine.fit(rows)
    engine.set_threshold(rows, ML_THRESHOLD_QUANTILE)
    return tuple(engine.analyse(sessions, capture_id).results)


def stage_summary(result: PipelineResult) -> List[Dict[str, Any]]:
    """Ordered stage timings, for logging and the run response."""
    order = ["ingest", "sessions", "analysis", "crosssession", "ml", "posture"]
    return [{"stage": name, "ms": result.stage_ms[name]}
            for name in order if name in result.stage_ms]
