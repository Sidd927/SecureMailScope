"""
Analyst dashboard (Phase 10, doc 23).

Projects the canonical `PostureAssessment` into a view model consumed by a
zero-dependency ES-module frontend. **Adds no security capability.** Every severity,
band, score, citation, remediation string and ML statement shown was produced by
Phase 4-7 code and is carried through unaltered.

**Dependency rule:** `dashboard/` consumes the canonical dict. No earlier package
imports it — not the security engine, and not `reporting/`. `backend/api.py` composes
it. Asserted by test.

The projection is Python (ADR-0022 Decision 2) so the AST tests that keep `backend/`
and `reporting/` from growing a severity table guard it too, and its contract tests run
in the existing suite. The frontend has **zero** npm dependencies and no build step.
"""
from securemailscope.dashboard.errors import DashboardError, MalformedAssessment
from securemailscope.dashboard.model import (
    DASHBOARD_SCHEMA_VERSION, PROJECTION_VERSION, AbstentionRow, Bar, Citation,
    Coverage, DashboardViewModel, Distribution, FilterOption, Filters, FindingRow,
    Identity, IssueGroupRow, MLPanel, Posture, ProtocolRow, Provenance, Remediation,
    ScoreComponentRow, StandardRow, Standards,
)
from securemailscope.dashboard.projection import UNAVAILABLE, project

__all__ = [
    "DASHBOARD_SCHEMA_VERSION", "PROJECTION_VERSION", "UNAVAILABLE",
    "AbstentionRow", "Bar", "Citation", "Coverage", "DashboardError",
    "DashboardViewModel", "Distribution", "FilterOption", "Filters", "FindingRow",
    "Identity", "IssueGroupRow", "MLPanel", "MalformedAssessment", "Posture",
    "ProtocolRow", "Provenance", "Remediation", "ScoreComponentRow", "StandardRow",
    "Standards", "project",
]
