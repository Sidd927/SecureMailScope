"""
Deterministic security analysis engine (Phase 4).

    SessionEvidence[] -> SecurityFinding[]

Strictly per-session. No cross-session baselines, control endpoints, temporal history
or anomaly scoring -- those belong to Phase 5 and are deliberately absent here
(Phase-4 SS16). No ML, no LLM, no network, no randomness (SS17).

The engine is defensive by construction: a rule that raises on malformed or unexpected
evidence must not take down the analysis or silently produce a confident finding. Such
failures surface as an explicit error record, never as a security conclusion.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from securemailscope.analysis.model import (
    ENGINE_VERSION, RULES_VERSION, FindingStatus, SecurityFinding, Severity,
)
from securemailscope.analysis.registry import RuleRegistry, SecurityRule
from securemailscope.analysis.rules import ALL_RULES
from securemailscope.session.model import SessionEvidence


def build_default_registry() -> RuleRegistry:
    registry = RuleRegistry()
    for rule_cls in ALL_RULES:
        registry.register(rule_cls())
    return registry


@dataclass
class AnalysisReport:
    """Result of analysing one capture's sessions. Structured, not presentational."""
    capture_id: str
    findings: List[SecurityFinding] = field(default_factory=list)
    rule_errors: List[Dict[str, str]] = field(default_factory=list)
    sessions_analysed: int = 0
    rules_version: str = RULES_VERSION
    engine_version: str = ENGINE_VERSION

    def by_status(self, status: FindingStatus) -> List[SecurityFinding]:
        return [f for f in self.findings if f.status is status]

    def by_severity(self, severity: Severity) -> List[SecurityFinding]:
        return [f for f in self.findings if f.severity is severity]

    @property
    def issues(self) -> List[SecurityFinding]:
        """Findings that assert an actual problem."""
        return self.by_status(FindingStatus.OBSERVED_ISSUE)

    def to_dict(self) -> dict:
        return {
            "capture_id": self.capture_id,
            "sessions_analysed": self.sessions_analysed,
            "versions": {"rules": self.rules_version, "engine": self.engine_version},
            "counts": {
                "findings": len(self.findings),
                "by_status": {
                    s.value: len(self.by_status(s)) for s in FindingStatus
                    if self.by_status(s)
                },
                "by_severity": {
                    s.value: len(self.by_severity(s)) for s in Severity
                    if self.by_severity(s)
                },
            },
            "findings": [f.to_dict() for f in self.findings],
            "rule_errors": list(self.rule_errors),
        }


class SecurityAnalysisEngine:
    """Applies the rule registry to reconstructed sessions."""

    def __init__(self, registry: Optional[RuleRegistry] = None) -> None:
        self.registry = registry or build_default_registry()

    def analyse_session(self, session: SessionEvidence) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        for rule in self.registry.rules:
            try:
                if not rule.applies_to(session):
                    continue
                findings.extend(rule.evaluate(session) or [])
            except Exception as exc:  # fail closed: never emit a finding from a broken rule
                self._last_errors.append({
                    "rule_id": rule.rule_id,
                    "stream_key": str(session.stream_key),
                    "error": f"{type(exc).__name__}: {exc}",
                })
        return findings

    def analyse(self, sessions: Sequence[SessionEvidence],
                capture_id: str = "") -> AnalysisReport:
        self._last_errors: List[Dict[str, str]] = []
        report = AnalysisReport(
            capture_id=capture_id or (sessions[0].capture_id if sessions else ""))
        for session in sessions:
            report.sessions_analysed += 1
            report.findings.extend(self.analyse_session(session))
        report.rule_errors = list(self._last_errors)
        return report

    # initialised per-analysis; declared here so analyse_session is safe standalone
    _last_errors: List[Dict[str, str]] = []
