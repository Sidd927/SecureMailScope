"""
Forensic reporting (Phase 9, doc 22).

Renders the canonical `PostureAssessment` as HTML and PDF. **Adds no security
capability.** Every severity, score, band, citation, remediation string and ML statement
in a report was produced by Phase 4-7 code and is carried through unaltered. If the
reporting layer ever appears to produce a security fact, that is a defect.

**Dependency rule:** `reporting/` consumes `posture/` and `backend/` contracts. No
earlier package imports `reporting/` — the security engine never depends on its
presentation layer. Asserted by test.

HTML and the projection use the standard library only. PDF requires the optional
`reporting-pdf` extra (ReportLab); its absence yields a structured
`RendererUnavailable` and leaves HTML and JSON fully available.
"""
from securemailscope.reporting.errors import (
    MalformedAssessment, RendererUnavailable, ReportError, ReportTooLarge,
    UnsupportedFormat,
)
from securemailscope.reporting.model import (
    ALWAYS_PRESENT, RENDERER_VERSION, REPORT_SCHEMA_VERSION, SECTION_ORDER, Bar,
    KeyValue, ReportDocument, ReportMetadata, Section, Table,
)
from securemailscope.reporting.projection import (
    MAX_EVIDENCE_CHARS, MAX_REPORT_FINDINGS, project,
)

__all__ = [
    "ALWAYS_PRESENT", "MAX_EVIDENCE_CHARS", "MAX_REPORT_FINDINGS",
    "RENDERER_VERSION", "REPORT_SCHEMA_VERSION", "SECTION_ORDER",
    "Bar", "KeyValue", "MalformedAssessment", "RendererUnavailable", "ReportDocument",
    "ReportError", "ReportMetadata", "ReportTooLarge", "Section", "Table",
    "UnsupportedFormat", "project",
]
