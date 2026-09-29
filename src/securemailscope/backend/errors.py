"""
Structured backend errors (Phase 8, doc 21 §10).

Every failure a client can provoke has a stable machine-readable code and one HTTP
status. Two properties matter more than the taxonomy itself:

1. **Nothing leaks.** No stack trace, filesystem path, SQL statement or capture byte
   reaches a client. `message` is authored here; `detail` carries only values the
   backend itself produced.
2. **Nothing is swallowed.** Every error is raised, logged and — where a run exists —
   persisted onto that run, so a failed analysis can be explained after the fact.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


class ErrorCode(str):
    """Stable error codes. Plain strings so they serialise without ceremony."""
    INVALID_REQUEST = "INVALID_REQUEST"
    UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
    CAPTURE_VALIDATION_FAILED = "CAPTURE_VALIDATION_FAILED"
    CAPTURE_TOO_LARGE = "CAPTURE_TOO_LARGE"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    NOT_FOUND = "NOT_FOUND"
    INVALID_LIFECYCLE_TRANSITION = "INVALID_LIFECYCLE_TRANSITION"
    ASSESSMENT_IDENTITY_CONFLICT = "ASSESSMENT_IDENTITY_CONFLICT"
    ARTIFACT_INTEGRITY_ERROR = "ARTIFACT_INTEGRITY_ERROR"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    ANALYSIS_INTERRUPTED = "ANALYSIS_INTERRUPTED"
    PERSISTENCE_FAILED = "PERSISTENCE_FAILED"
    SCHEMA_VERSION_UNSUPPORTED = "SCHEMA_VERSION_UNSUPPORTED"
    TSHARK_UNAVAILABLE = "TSHARK_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


#: code -> HTTP status. Kept as data so the API layer maps rather than branches.
HTTP_STATUS: Dict[str, int] = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.UNSUPPORTED_INPUT: 415,
    ErrorCode.CAPTURE_VALIDATION_FAILED: 422,
    ErrorCode.CAPTURE_TOO_LARGE: 413,
    ErrorCode.RESOURCE_LIMIT_EXCEEDED: 429,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.INVALID_LIFECYCLE_TRANSITION: 409,
    ErrorCode.ASSESSMENT_IDENTITY_CONFLICT: 409,
    ErrorCode.ARTIFACT_INTEGRITY_ERROR: 500,
    ErrorCode.ANALYSIS_FAILED: 500,
    ErrorCode.ANALYSIS_INTERRUPTED: 500,
    ErrorCode.PERSISTENCE_FAILED: 500,
    ErrorCode.SCHEMA_VERSION_UNSUPPORTED: 500,
    ErrorCode.TSHARK_UNAVAILABLE: 503,
    ErrorCode.INTERNAL_ERROR: 500,
}


class BackendError(Exception):
    """Base for every backend failure that a client may be told about."""

    code = ErrorCode.INTERNAL_ERROR

    def __init__(self, message: str, detail: Optional[Dict[str, Any]] = None,
                 run_id: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = dict(detail or {})
        self.run_id = run_id

    @property
    def http_status(self) -> int:
        return HTTP_STATUS.get(self.code, 500)

    def to_dict(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message,
                          "detail": self.detail, "run_id": self.run_id}}


class InvalidRequest(BackendError):
    code = ErrorCode.INVALID_REQUEST


class UnsupportedInput(BackendError):
    code = ErrorCode.UNSUPPORTED_INPUT


class CaptureValidationFailed(BackendError):
    code = ErrorCode.CAPTURE_VALIDATION_FAILED


class CaptureTooLarge(BackendError):
    code = ErrorCode.CAPTURE_TOO_LARGE


class ResourceLimitExceeded(BackendError):
    code = ErrorCode.RESOURCE_LIMIT_EXCEEDED


class NotFound(BackendError):
    code = ErrorCode.NOT_FOUND


class InvalidTransition(BackendError):
    """A lifecycle transition absent from the transition table. Fails closed."""
    code = ErrorCode.INVALID_LIFECYCLE_TRANSITION


class AssessmentIdentityConflict(BackendError):
    """Same `assessment_id`, different content (ADR-0017 Decision 4).

    Raised rather than resolved: overwriting a stored forensic conclusion, or silently
    keeping the older one, are both worse than refusing.
    """
    code = ErrorCode.ASSESSMENT_IDENTITY_CONFLICT


class ArtifactIntegrityError(BackendError):
    """A stored artifact no longer hashes to its recorded SHA-256."""
    code = ErrorCode.ARTIFACT_INTEGRITY_ERROR


class AnalysisFailed(BackendError):
    code = ErrorCode.ANALYSIS_FAILED


class PersistenceFailed(BackendError):
    code = ErrorCode.PERSISTENCE_FAILED


class SchemaVersionUnsupported(BackendError):
    """The database was written by a newer backend. Refuse rather than guess."""
    code = ErrorCode.SCHEMA_VERSION_UNSUPPORTED


class TsharkUnavailable(BackendError):
    code = ErrorCode.TSHARK_UNAVAILABLE


#: Raised by the pipeline when analysis exceeds `max_analysis_seconds`.
class AnalysisTimeout(AnalysisFailed):
    pass
