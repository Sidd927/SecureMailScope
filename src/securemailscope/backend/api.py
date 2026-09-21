"""
FastAPI application (doc 21 §9, §10, §16).

The API is transport. It parses a request, calls the service, and serialises what comes
back. It makes no security decision and reshapes no security claim: the assessment
endpoint returns the canonical document verbatim.

Three habits carry the security properties:

* every exception leaves through `BackendError`, so no traceback, path or SQL reaches
  a client;
* identifiers are format-checked before they reach a query, and every query is
  parameterised;
* the request body is bounded by `Content-Length` before it is read, not after.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Optional

from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.responses import JSONResponse
# `request.form()` yields Starlette's UploadFile. `fastapi.UploadFile` *subclasses* it,
# so testing against the FastAPI type would be the wrong direction and always fail.
from starlette.datastructures import UploadFile

from securemailscope import __version__ as SMS_VERSION
from securemailscope.backend.db import BACKEND_SCHEMA_VERSION
from securemailscope.backend.errors import (
    BackendError, ErrorCode, InvalidRequest, InvalidTransition, NotFound,
)
from securemailscope.backend.lifecycle import JobState
from securemailscope.backend.schemas import (
    ArtifactListResponse, AssessmentResponse, HealthResponse, RunListResponse,
    RunResponse, run_to_response,
)
from securemailscope.backend.service import AnalysisService
from securemailscope.dissect import TsharkAdapter
from securemailscope.posture import POSTURE_ENGINE_VERSION, POSTURE_SCHEMA_VERSION

log = logging.getLogger("securemailscope.backend.api")

API_PREFIX = "/api/v1"

#: run_id is a uuid4 hex. Validated before it can reach a query, so a hostile id is a
#: 400 rather than an opportunity.
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
_CAPTURE_ID = re.compile(r"^[0-9a-f]{64}$")


def _validate_run_id(run_id: str) -> str:
    if not _RUN_ID.match(run_id):
        raise InvalidRequest("run_id is not a valid identifier",
                             detail={"expected": "32 hex characters"})
    return run_id


def create_app(service: Optional[AnalysisService] = None,
               data_dir: Optional[str] = None) -> FastAPI:
    """Build the application. `service` is injectable so tests need no global state."""
    svc = service or AnalysisService(
        data_dir or os.environ.get("SMS_DATA_DIR", "./securemailscope-data"))

    app = FastAPI(
        title="SecureMailScope",
        version=SMS_VERSION,
        description=(
            "Passive PCAP cryptographic security posture assessment for email "
            "(SIH26159). This API serves the canonical PostureAssessment produced by "
            "the analysis engine; it does not compute posture itself."),
    )
    app.state.service = svc

    # Interrupted runs are swept once, at construction: a run left non-terminal by a
    # killed process must never be observable as COMPLETED (doc 21 §13).
    recovered = svc.recover()
    if recovered:
        log.warning("recovered %d interrupted run(s) at startup", len(recovered))

    @app.exception_handler(BackendError)
    async def _backend_error(_request: Request, exc: BackendError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())

    @app.exception_handler(Exception)
    async def _unexpected(_request: Request, exc: Exception) -> JSONResponse:
        # Logged in full locally, disclosed as a class name only.
        log.exception("unhandled error")
        return JSONResponse(
            status_code=500,
            content={"error": {"code": ErrorCode.INTERNAL_ERROR,
                               "message": "internal error",
                               "detail": {"reason": type(exc).__name__},
                               "run_id": None}})

    router = APIRouter(prefix=API_PREFIX)

    # ------------------------------------------------------------- health
    @router.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        info = svc.health()
        try:
            TsharkAdapter(svc.config).version()
            tshark = "available"
        except Exception:
            tshark = "unavailable"
        return HealthResponse(
            status="ok" if info["database"] == "ok" else "degraded",
            version=SMS_VERSION,
            backend_schema_version=info["schema_version"],
            posture_schema_version=POSTURE_SCHEMA_VERSION,
            posture_engine_version=POSTURE_ENGINE_VERSION,
            database=info["database"],
            artifact_count=info["artifact_count"],
            artifact_bytes=info["artifact_bytes"],
            limits=info["limits"],
            tshark=tshark)

    # ------------------------------------------------------------- submit
    @router.post("/analyses", response_model=RunResponse, status_code=201)
    async def create_analysis(
        request: Request,
        ai: bool = Query(False, description="enable the ML prioritisation lane"),
        force: bool = Query(False, description="re-run even if this capture was analysed"),
        formula: Optional[str] = Query(None, description="posture scoring formula id"),
    ) -> RunResponse:
        """Submit a capture. Accepts multipart/form-data or application/octet-stream."""
        ceiling = svc.limits.effective_upload_ceiling(svc.config)
        _reject_oversized(request, ceiling)

        content_type = (request.headers.get("content-type") or "").lower()
        if content_type.startswith("multipart/form-data"):
            source, filename = await _from_multipart(request)
        elif (content_type.startswith("application/octet-stream")
                or content_type.startswith("application/vnd.tcpdump.pcap")
                or not content_type):
            body = await request.body()
            if len(body) > ceiling:
                from securemailscope.backend.errors import CaptureTooLarge
                raise CaptureTooLarge("capture exceeds the upload ceiling",
                                      detail={"max_bytes": ceiling})
            import io
            source = io.BytesIO(body)
            filename = request.headers.get("x-filename")
        else:
            from securemailscope.backend.errors import UnsupportedInput
            raise UnsupportedInput(
                "unsupported content type",
                detail={"accepted": ["multipart/form-data",
                                     "application/octet-stream"]})

        result = svc.submit_stream(source, filename=filename, ai_enabled=ai,
                                   formula_id=formula, force=force)
        return run_to_response(result.run, replayed=result.replayed,
                               stages=result.stages)

    # --------------------------------------------------------------- read
    @router.get("/analyses", response_model=RunListResponse)
    def list_analyses(
        limit: int = Query(0, ge=0),
        offset: int = Query(0, ge=0),
        state: Optional[str] = Query(None),
        capture_id: Optional[str] = Query(None),
    ) -> RunListResponse:
        size = svc.limits.page_size(limit)
        job_state = None
        if state:
            try:
                job_state = JobState(state)
            except ValueError:
                raise InvalidRequest(
                    "unknown state filter",
                    detail={"allowed": [s.value for s in JobState]})
        if capture_id and not _CAPTURE_ID.match(capture_id):
            raise InvalidRequest("capture_id is not a valid identifier",
                                 detail={"expected": "64 hex characters"})
        runs, total = svc.list_runs(size, offset, job_state, capture_id)
        return RunListResponse(total=total, limit=size, offset=offset,
                               items=[run_to_response(r) for r in runs])

    @router.get("/analyses/{run_id}", response_model=RunResponse)
    def get_analysis(run_id: str) -> RunResponse:
        return run_to_response(svc.get_run(_validate_run_id(run_id)))

    @router.get("/analyses/{run_id}/assessment", response_model=AssessmentResponse)
    def get_assessment(run_id: str) -> AssessmentResponse:
        """Return the canonical assessment document, unaltered.

        No field is renamed, removed, flattened or recomputed. INSUFFICIENT_EVIDENCE
        stays INSUFFICIENT_EVIDENCE; it is never mapped to UNKNOWN or to a success
        value, and NOT_OBSERVABLE / AMBIGUOUS are never collapsed together.
        """
        rid = _validate_run_id(run_id)
        document: Dict[str, Any] = svc.get_assessment(rid)
        return AssessmentResponse(
            run_id=rid,
            assessment_id=document["assessment_id"],
            capture_id=document["capture_id"],
            overall_posture=document["overall_posture"],
            coverage=document.get("coverage"),
            limitations=list(document.get("limitations") or []),
            assessment=document)

    @router.get("/analyses/{run_id}/artifacts", response_model=ArtifactListResponse)
    def get_artifacts(run_id: str,
                      verify: bool = Query(False)) -> ArtifactListResponse:
        rid = _validate_run_id(run_id)
        return ArtifactListResponse(
            run_id=rid, items=svc.list_artifacts(rid, verify=verify))

    app.include_router(router)
    return app


# ------------------------------------------------------------------ helpers
def _reject_oversized(request: Request, ceiling: int) -> None:
    """Refuse on the declared length, before any body is read."""
    raw = request.headers.get("content-length")
    if raw is None:
        return
    try:
        declared = int(raw)
    except ValueError:
        raise InvalidRequest("malformed content-length header")
    if declared > ceiling:
        from securemailscope.backend.errors import CaptureTooLarge
        raise CaptureTooLarge("capture exceeds the upload ceiling",
                              detail={"max_bytes": ceiling,
                                      "declared_bytes": declared})


async def _from_multipart(request: Request):
    """Extract the single uploaded file. Parser failures become 400, never 500."""
    try:
        form = await request.form()
    except Exception as exc:
        raise InvalidRequest("malformed multipart body",
                             detail={"reason": type(exc).__name__})
    upload = form.get("file") or form.get("capture")
    if upload is None or not isinstance(upload, UploadFile):
        raise InvalidRequest(
            "multipart body must contain a file part named 'file'")
    return upload.file, upload.filename
