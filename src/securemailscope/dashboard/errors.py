"""
Dashboard errors (doc 23 §9, §11).

Kept separate from the backend and reporting taxonomies because a dashboard-projection
failure is its own event: the assessment is intact, the API is fine, and only this
presentation of it could not be built. Mapped onto the backend error envelope at the
API boundary so a client sees one error shape.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


class DashboardError(Exception):
    code = "DASHBOARD_PROJECTION_FAILED"
    http_status = 500

    def __init__(self, message: str, detail: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = dict(detail or {})

    def to_dict(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message,
                          "detail": self.detail, "run_id": None}}


class MalformedAssessment(DashboardError):
    """The input is not a canonical assessment.

    Raised rather than projecting a partial view: a dashboard built from a structure the
    projection had to guess at would present the guess as evidence.
    """
    code = "MALFORMED_ASSESSMENT"
    http_status = 422
