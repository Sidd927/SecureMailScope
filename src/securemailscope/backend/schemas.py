"""
API transport schemas (doc 21 §9, ADR-0018 Decision 3).

Pydantic models exist here for **requests, errors, run metadata and artifact
metadata** — things the backend genuinely owns.

There is deliberately **no pydantic model of `PostureAssessment`**. Re-declaring it
would create a second schema for the canonical object, and every future edit to one
would be a chance for the two to disagree about what a posture claim means. The
assessment travels as the document the posture engine produced, typed as a free-form
mapping, and the response model asserts only that the fields which qualify a posture
claim — `coverage`, `limitations`, `model_summary` — are present.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str
    message: str
    detail: Dict[str, Any] = Field(default_factory=dict)
    run_id: Optional[str] = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class HealthResponse(BaseModel):
    status: str
    version: str
    backend_schema_version: Optional[str] = None
    posture_schema_version: str
    posture_engine_version: str
    database: str
    artifact_count: int
    artifact_bytes: int
    limits: Dict[str, int]
    tshark: str = Field(
        description="available | unavailable — analysis requires tshark")


class RunResponse(BaseModel):
    """Backend-owned metadata about one execution attempt."""
    run_id: str
    state: str
    capture_id: Optional[str] = None
    assessment_id: Optional[str] = None
    ai_enabled: bool = False
    formula_id: Optional[str] = None
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    #: Phase-2 RunStatus, verbatim. Describes evidence quality, NOT security and NOT
    #: job state: PARTIAL means the capture was truncated.
    ingest_status: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    source_filename: Optional[str] = None
    backend_version: Optional[str] = None
    #: True when this run already existed and was returned instead of re-analysing.
    replayed: bool = False
    stages: Optional[List[Dict[str, Any]]] = None


class RunListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[RunResponse]


class AssessmentResponse(BaseModel):
    """Envelope around the canonical document.

    `assessment` is the posture engine's `to_dict()`, passed through unaltered. The
    three fields lifted alongside it are duplicated **from** that document for
    convenience and are never computed here; `coverage` in particular travels beside
    `overall_posture` because a band without its evidence coverage is the misleading
    claim ADR-0016 exists to prevent.
    """
    run_id: str
    assessment_id: str
    capture_id: str
    overall_posture: str
    coverage: Optional[Dict[str, Any]] = None
    limitations: List[str] = Field(default_factory=list)
    assessment: Dict[str, Any]


class ArtifactResponse(BaseModel):
    artifact_id: str
    run_id: str
    kind: str
    sha256: str
    size_bytes: int
    created_at: str
    original_filename: Optional[str] = None
    integrity: Optional[str] = None


class ArtifactListResponse(BaseModel):
    run_id: str
    items: List[ArtifactResponse]


def run_to_response(run: Any, *, replayed: bool = False,
                    stages: Optional[List[Dict[str, Any]]] = None) -> RunResponse:
    return RunResponse(
        run_id=run.run_id, state=run.state.value, capture_id=run.capture_id,
        assessment_id=run.assessment_id, ai_enabled=run.ai_enabled,
        formula_id=run.formula_id, created_at=run.created_at,
        started_at=run.started_at, completed_at=run.completed_at,
        duration_ms=run.duration_ms, ingest_status=run.ingest_status,
        error_code=run.error_code, error_message=run.error_message,
        source_filename=run.source_filename, backend_version=run.backend_version,
        replayed=replayed, stages=stages)
