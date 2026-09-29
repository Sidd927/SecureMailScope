"""
Cross-session reasoning engine (Phase 5).

    SessionEvidence[] -> comparability -> baseline -> contrast -> CrossSessionFinding[]

Supplements Phase 4; does not replace it. Deterministic: sessions are processed in a
total, explicit order and never in dict/filesystem iteration order. No ML, no network,
no wall-clock dependence (any temporal reasoning uses capture timestamps only).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from securemailscope.analysis.model import FindingStatus, Severity
from securemailscope.crosssession.baseline import (
    DEFAULT_MAX_HISTORY, DEFAULT_MIN_HISTORY, Baseline, BaselineStatus, PopulationIndex,
    build_baseline, _order,
)
from securemailscope.crosssession.comparability import assess
from securemailscope.crosssession.contrast import ContrastState, evaluate_contrast
from securemailscope.crosssession.model import (
    CROSS_ENGINE_VERSION, CROSS_RULES_VERSION, CrossSessionFinding, Deviation,
)
from securemailscope.crosssession.rules import ALL_CROSS_RULES
from securemailscope.session.model import SessionEvidence


@dataclass
class CrossSessionConfig:
    """Explicit, documented knobs. The threshold's empirical basis is docs/research/02A §5."""
    min_history: int = DEFAULT_MIN_HISTORY
    max_history: int = DEFAULT_MAX_HISTORY
    min_controls: int = 1


@dataclass
class CrossSessionReport:
    capture_id: str
    findings: List[CrossSessionFinding] = field(default_factory=list)
    rule_errors: List[Dict[str, str]] = field(default_factory=list)
    sessions_analysed: int = 0
    baselines_established: int = 0
    abstentions: int = 0
    rules_version: str = CROSS_RULES_VERSION
    engine_version: str = CROSS_ENGINE_VERSION

    def by_deviation(self, kind: Deviation) -> List[CrossSessionFinding]:
        return [f for f in self.findings if f.deviation is kind]

    @property
    def abstention_rate(self) -> float:
        return self.abstentions / self.sessions_analysed if self.sessions_analysed else 0.0

    def to_dict(self) -> dict:
        return {
            "capture_id": self.capture_id,
            "sessions_analysed": self.sessions_analysed,
            "baselines_established": self.baselines_established,
            "abstentions": self.abstentions,
            "abstention_rate": round(self.abstention_rate, 4),
            "versions": {"rules": self.rules_version, "engine": self.engine_version},
            "counts": {
                "findings": len(self.findings),
                "by_deviation": {d.value: len(self.by_deviation(d))
                                 for d in Deviation if self.by_deviation(d)},
            },
            "findings": [f.to_dict() for f in self.findings],
            "rule_errors": list(self.rule_errors),
        }


class CrossSessionEngine:
    def __init__(self, config: Optional[CrossSessionConfig] = None,
                 rules: Optional[Sequence] = None) -> None:
        self.config = config or CrossSessionConfig()
        self.rules = [r() for r in (rules or ALL_CROSS_RULES)]

    def analyse(self, sessions: Sequence[SessionEvidence],
                capture_id: str = "") -> CrossSessionReport:
        ordered = sorted(sessions, key=_order)          # total deterministic order
        index = PopulationIndex(ordered)                # built once: avoids O(n^2) rescans
        report = CrossSessionReport(
            capture_id=capture_id or (ordered[0].capture_id if ordered else ""))
        errors: List[Dict[str, str]] = []

        for subject in ordered:
            report.sessions_analysed += 1
            comparability = assess(subject)
            baseline = build_baseline(subject, ordered, self.config.min_history, index,
                                      self.config.max_history)
            contrast = evaluate_contrast(subject, ordered, self.config.min_controls, index,
                                         self.config.max_history)
            if baseline.usable:
                report.baselines_established += 1
            else:
                report.abstentions += 1

            for rule in self.rules:
                try:
                    if not rule.applies_to(subject):
                        continue
                    report.findings.extend(
                        rule.evaluate(subject, baseline, contrast, comparability) or [])
                except Exception as exc:      # fail closed
                    errors.append({
                        "rule_id": rule.rule_id,
                        "stream_key": str(subject.stream_key),
                        "error": f"{type(exc).__name__}: {exc}",
                    })
        report.rule_errors = errors
        return report
