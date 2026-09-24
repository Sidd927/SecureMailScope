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
from fastapi.responses import JSONResponse, Response
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
    ArtifactListResponse, AssessmentResponse, HealthResponse, ReportListResponse,
    RunListResponse, RunResponse, SessionListResponse, run_to_response,
)
from securemailscope.backend.service import AnalysisService
from securemailscope.dissect import TsharkAdapter
from securemailscope.posture import POSTURE_ENGINE_VERSION, POSTURE_SCHEMA_VERSION
from securemailscope.dashboard.errors import DashboardError
from securemailscope.reporting.errors import ReportError
from securemailscope.reporting.service import SUPPORTED_FORMATS

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

    @app.exception_handler(DashboardError)
    async def _dashboard_error(_request: Request,
                               exc: DashboardError) -> JSONResponse:
        # A projection failure leaves the assessment intact and the API usable.
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())

    @app.exception_handler(ReportError)
    async def _report_error(_request: Request, exc: ReportError) -> JSONResponse:
        # A report failure is reported as itself and leaves the assessment untouched
        # (ADR-0019 Decision 4). It never changes the run's state.
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

    @router.get("/analyses/{run_id}/sessions", response_model=SessionListResponse)
    def get_sessions(run_id: str) -> SessionListResponse:
        """Per-session detail for a run, verbatim, in reconstruction order.

        Read-only projection over what Phase 3 already computed for this run
        (doc capability audit, V4 investigation rebuild). Not a second authority --
        findings, posture and evidence state remain `.../assessment`'s and
        `.../dashboard`'s. This exists so the console can pivot from a finding
        (`affected_stream_keys`) to the session it was found in.
        """
        rid = _validate_run_id(run_id)
        items = svc.get_sessions(rid)
        capture_id = items[0].get("capture_id") if items else None
        return SessionListResponse(
            run_id=rid, capture_id=capture_id, total=len(items), items=items)

    # ---------------------------------------------------------- dashboard
    @router.get("/analyses/{run_id}/dashboard")
    def get_dashboard(run_id: str) -> Dict[str, Any]:
        """The analyst-console view model for one run (doc 23 §6).

        Serves the output of the single Python projection (ADR-0022 Decision 2). It is
        derived from the canonical assessment on every request and never stored, adds
        no field the assessment does not contain, and is not an authority:
        `.../assessment` remains canonical.
        """
        from securemailscope.dashboard.projection import project
        rid = _validate_run_id(run_id)
        return project(svc.get_assessment(rid)).to_dict()

    # ------------------------------------------------------------ reports
    @router.get("/analyses/{run_id}/reports", response_model=ReportListResponse)
    def list_reports(run_id: str) -> ReportListResponse:
        """Available report formats with integrity metadata (doc 22 §14)."""
        rid = _validate_run_id(run_id)
        reports = _report_service(svc)
        try:
            assessment = svc.get_assessment(rid)
        except NotFound:
            svc.get_run(rid)             # 404 for an unknown run, not an empty list
            assessment = None
        return ReportListResponse(run_id=rid,
                                  items=reports.list_reports(rid, assessment))

    @router.get("/analyses/{run_id}/reports/{fmt}")
    def get_report(run_id: str, fmt: str,
                   download: bool = Query(False)) -> Response:
        """Render (or serve a stored) report.

        A report is a rendering of the canonical assessment. This endpoint reconstructs
        no security conclusion: it fetches the same document `.../assessment` returns
        and hands it to a renderer.
        """
        rid = _validate_run_id(run_id)
        if fmt not in SUPPORTED_FORMATS:
            raise InvalidRequest("unsupported report format",
                                 detail={"format": fmt,
                                         "supported": list(SUPPORTED_FORMATS)})
        assessment = svc.get_assessment(rid)
        payload, meta = _report_service(svc).get_or_create(rid, assessment, fmt)

        headers = {
            "X-Assessment-Id": meta["assessment_id"],
            "X-Report-Schema-Version": meta["report_schema_version"],
            "X-Renderer-Version": meta["renderer_version"],
            "Content-Length": str(len(payload)),
            # A report is a pure function of its assessment, and an assessment is
            # immutable once stored, so this is safe to cache indefinitely.
            "Cache-Control": "private, max-age=86400",
        }
        if meta.get("report_sha256"):
            headers["X-Report-Sha256"] = meta["report_sha256"]
        # PDFs download by default; HTML and JSON render in place unless asked.
        if download or fmt == "pdf":
            headers["Content-Disposition"] = 'attachment; filename="%s"' % meta["filename"]
        return Response(content=payload, media_type=meta["media_type"],
                        headers=headers)

    app.include_router(router)
    _mount_dashboard(app)
    return app


def _mount_dashboard(app: FastAPI) -> None:
    """Serve the analyst console from a fixed package directory (doc 23 §6, §11).

    The path is resolved from this package, never from user input, and the mount is
    read-only. It is added AFTER the API router so it can never shadow an endpoint.
    Absence of the directory is not fatal: the API is fully usable without the console.
    """
    try:
        from fastapi.staticfiles import StaticFiles
    except ImportError:                       # pragma: no cover - fastapi guarantees it
        return
    from securemailscope import dashboard as dashboard_pkg

    static_dir = os.path.join(os.path.dirname(os.path.abspath(
        dashboard_pkg.__file__)), "static")
    if not os.path.isdir(static_dir):         # pragma: no cover - packaging guard
        log.warning("dashboard static directory missing; console not served")
        return
    app.mount("/dashboard", StaticFiles(directory=static_dir, html=True),
              name="dashboard")


def _report_service(svc: AnalysisService):
    """Build the report service over the backend's existing repository and store.

    Reuses the Phase-8 artifact store rather than creating a second one (ADR-0021
    Decision 3).
    """
    from securemailscope.reporting.service import ReportService
    return ReportService(svc.repo, svc.artifacts)


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
