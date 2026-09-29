"""
Backend: orchestration, persistence and API (Phase 8, doc 21).

This package adds **no security capability**. It runs the existing Phase 2–7 engines,
stores the canonical `PostureAssessment` they produce, and serves it unaltered. Every
severity, score, band, citation and remediation string in a backend response was
produced by earlier phases; if the backend ever appears to produce a security fact,
that is a defect.

**Dependency rule:** `backend/` may import from every earlier package; no earlier
package may import `backend/`. Phase 8 is a leaf. Asserted by test.

FastAPI and pydantic are optional extras (`pip install securemailscope[backend]`). The
persistence and lifecycle layers below use the standard library only, so they import
and test without them.
"""
from securemailscope.backend.errors import (
    AnalysisFailed, ArtifactIntegrityError, AssessmentIdentityConflict, BackendError,
    CaptureTooLarge, CaptureValidationFailed, ErrorCode, HTTP_STATUS, InvalidRequest,
    InvalidTransition, NotFound, PersistenceFailed, ResourceLimitExceeded,
    SchemaVersionUnsupported, TsharkUnavailable, UnsupportedInput,
)
from securemailscope.backend.lifecycle import (
    INTERRUPTIBLE, TERMINAL, TRANSITIONS, JobState, can_transition, check_transition,
    is_terminal,
)
from securemailscope.backend.limits import Limits

__all__ = [
    "AnalysisFailed", "ArtifactIntegrityError", "AssessmentIdentityConflict",
    "BackendError", "CaptureTooLarge", "CaptureValidationFailed", "ErrorCode",
    "HTTP_STATUS", "InvalidRequest", "InvalidTransition", "NotFound",
    "PersistenceFailed", "ResourceLimitExceeded", "SchemaVersionUnsupported",
    "TsharkUnavailable", "UnsupportedInput",
    "INTERRUPTIBLE", "TERMINAL", "TRANSITIONS", "JobState", "can_transition",
    "check_transition", "is_terminal",
    "Limits",
]
