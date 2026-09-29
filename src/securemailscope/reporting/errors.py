"""
Reporting errors (doc 22 §13, §16).

Separate from the backend taxonomy because a report failure and an analysis failure are
different events with different consequences: a report that will not render leaves a
perfectly valid security assessment untouched (ADR-0019 Decision 4). These map onto the
backend error envelope at the API boundary.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


class ReportError(Exception):
    """Base for report generation failures."""
    code = "REPORT_GENERATION_FAILED"
    http_status = 500

    def __init__(self, message: str, detail: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = dict(detail or {})

    def to_dict(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message,
                          "detail": self.detail, "run_id": None}}


class MalformedAssessment(ReportError):
    """The input is not a canonical assessment.

    Raised rather than rendering a partial document: a report built from a structure the
    projection had to guess at would carry the guess as if it were evidence.
    """
    code = "MALFORMED_ASSESSMENT"
    http_status = 422


class RendererUnavailable(ReportError):
    """An optional renderer dependency is not installed.

    503 rather than 500: the request is well-formed and the assessment is intact; this
    deployment simply cannot produce that format right now.
    """
    code = "REPORT_RENDERER_UNAVAILABLE"
    http_status = 503


class UnsupportedFormat(ReportError):
    code = "UNSUPPORTED_REPORT_FORMAT"
    http_status = 400


class ReportTooLarge(ReportError):
    code = "REPORT_TOO_LARGE"
    http_status = 500
