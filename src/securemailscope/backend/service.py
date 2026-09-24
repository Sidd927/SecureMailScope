"""
AnalysisService: the only orchestrator (doc 21 §3, §13, §14).

Responsibilities: create a run, store the capture as an artifact, drive the lifecycle,
invoke the existing pipeline, persist the canonical assessment, and recover interrupted
runs at startup.

Explicitly not a responsibility: interpreting anything the pipeline returned. The
service moves a document from the posture engine into storage and back out. It reads
`overall_posture` only to write the listing projection, and never to decide anything.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from securemailscope.backend.artifacts import ArtifactStore, KIND_PCAP, safe_display_name
from securemailscope.backend.db import Database
from securemailscope.backend.errors import (
    AnalysisFailed, BackendError, CaptureTooLarge, CaptureValidationFailed,
    ErrorCode, NotFound, ResourceLimitExceeded,
)
from securemailscope.backend.lifecycle import JobState
from securemailscope.backend.limits import Limits
from securemailscope.backend.pipeline import PipelineResult, run_pipeline, stage_summary
from securemailscope.backend.repository import Repository, RunRecord
from securemailscope.config import Config
from securemailscope.ingest import validate_capture

log = logging.getLogger("securemailscope.backend")


@dataclass
class SubmissionResult:
    """Outcome of a submission. `replayed` marks an idempotent hit."""
    run: RunRecord
    replayed: bool = False
    stages: Optional[List[Dict[str, Any]]] = None


class AnalysisService:
    """Owns the lifecycle of every analysis in this process."""

    def __init__(self, data_dir: str, *, config: Optional[Config] = None,
                 limits: Optional[Limits] = None) -> None:
        self.data_dir = os.path.abspath(data_dir)
        os.makedirs(self.data_dir, exist_ok=True)
        self.config = config or Config.load()
        self.limits = limits or Limits.load(self.config)
        self.db = Database(os.path.join(self.data_dir, "securemailscope.db"))
        self.repo = Repository(self.db)
        self.artifacts = ArtifactStore(os.path.join(self.data_dir, "artifacts"))
        # One writer. doc 21 §12: an explicit invariant, not an accident.
        self._slots = threading.BoundedSemaphore(self.limits.max_concurrent_analyses)
        self._admission = threading.Lock()
        self._in_flight = 0

    # ------------------------------------------------------------- recovery
    def recover(self) -> List[str]:
        """Sweep runs left non-terminal by an interrupted process (doc 21 §13).

        Nothing but a crash can leave a run in one of these states, because every
        in-process path either completes it or fails it. They are moved
        RECOVERY_REQUIRED -> FAILED so the audit trail distinguishes a crash from a
        failure during analysis. No interrupted run is ever reported COMPLETED.
        """
        recovered: List[str] = []
        for run in self.repo.interrupted_runs():
            try:
                self.repo.transition(
                    run, JobState.RECOVERY_REQUIRED,
                    detail="interrupted; found non-terminal at startup")
                self.repo.transition(
                    run, JobState.FAILED,
                    detail="analysis interrupted before completion",
                    error_code=ErrorCode.ANALYSIS_INTERRUPTED,
                    error_message="analysis was interrupted before completion")
                recovered.append(run.run_id)
                log.warning("recovered interrupted run", extra={"run_id": run.run_id})
            except BackendError as exc:      # pragma: no cover - defensive
                log.error("could not recover run %s: %s", run.run_id, exc.message)
        return recovered

    # ----------------------------------------------------------- submission
    def submit_stream(self, source: BinaryIO, *, filename: Optional[str] = None,
                      ai_enabled: bool = False, formula_id: Optional[str] = None,
                      force: bool = False) -> SubmissionResult:
        """Accept a capture as a stream, then analyse it.

        The stream is written to the artifact store before anything else, so the bytes
        analysed are the bytes stored and the SHA-256 describes both.
        """
        self._admit()
        try:
            run = self.repo.create_run(RunRecord.new(
                ai_enabled=ai_enabled, formula_id=formula_id,
                source_filename=safe_display_name(filename)))
            self.repo.transition(run, JobState.VALIDATING, detail="receiving capture")

            ceiling = self.limits.effective_upload_ceiling(self.config)
            try:
                # Sharded by run_id: the capture_id is not known until the bytes have
                # been hashed, and hashing happens during this write.
                record = self.artifacts.store_stream(
                    source, run_id=run.run_id, capture_id=run.run_id,
                    kind=KIND_PCAP, original_filename=filename, max_bytes=ceiling)
            except CaptureTooLarge as exc:
                self._fail(run, exc)
                raise
            staged = self.artifacts.absolute(record.relative_path)
            return self._analyse_staged(run, staged, record, force=force)
        finally:
            self._release()

    def submit_path(self, path: str, *, ai_enabled: bool = False,
                    formula_id: Optional[str] = None,
                    force: bool = False) -> SubmissionResult:
        """Accept a capture already on disk (local analyst workflow)."""
        self._admit()
        try:
            run = self.repo.create_run(RunRecord.new(
                ai_enabled=ai_enabled, formula_id=formula_id,
                source_filename=safe_display_name(os.path.basename(path))))
            self.repo.transition(run, JobState.VALIDATING, detail="validating capture")
            validation = validate_capture(path, self.config)
            if not validation.ok:
                exc = CaptureValidationFailed(
                    "capture failed validation",
                    detail={"result": validation.result.value,
                            "reason": validation.detail})
                self._fail(run, exc)
                raise exc
            record = self.artifacts.store_file(
                validation.resolved_path or path, run_id=run.run_id,
                capture_id=run.run_id, original_filename=os.path.basename(path))
            staged = self.artifacts.absolute(record.relative_path)
            return self._analyse_staged(run, staged, record, force=force)
        finally:
            self._release()

    # -------------------------------------------------------------- analysis
    def _analyse_staged(self, run: RunRecord, staged_path: str, artifact,
                        *, force: bool) -> SubmissionResult:
        # Validate the stored bytes. The artifact's own SHA-256 is the capture identity
        # Phase 1 defines, so identity comes from what was written, not what was claimed.
        validation = validate_capture(staged_path, self.config)
        if not validation.ok:
            exc = CaptureValidationFailed(
                "capture failed validation",
                detail={"result": validation.result.value,
                        "reason": validation.detail})
            self._fail(run, exc)
            raise exc

        capture_id = artifact.sha256
        run.capture_id = capture_id

        # Idempotency (ADR-0018 Decision 4): keyed on content, never on filename.
        if not force:
            existing = self.repo.find_completed_run_for(
                capture_id, run.ai_enabled, run.formula_id)
            if existing is not None:
                self.repo.transition(
                    run, JobState.CANCELLED, capture_id=capture_id,
                    detail="superseded by completed run " + existing.run_id)
                log.info("idempotent replay", extra={
                    "run_id": existing.run_id, "capture_id": capture_id})
                return SubmissionResult(run=existing, replayed=True)

        self.repo.transition(run, JobState.QUEUED, capture_id=capture_id)
        self.repo.transition(run, JobState.RUNNING, detail="pipeline started")
        started = time.perf_counter()

        try:
            result = run_pipeline(
                staged_path, ai_enabled=run.ai_enabled, formula_id=run.formula_id,
                run_id=run.run_id, config=self.config)
        except BackendError as exc:
            self._fail(run, exc)
            raise
        except Exception as exc:
            # Untrusted input must never surface a raw traceback to a client.
            wrapped = AnalysisFailed("analysis failed",
                                     detail={"reason": type(exc).__name__},
                                     run_id=run.run_id)
            log.exception("pipeline raised for run %s", run.run_id)
            self._fail(run, wrapped)
            raise wrapped

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        if result.assessment is None:       # pragma: no cover - engine always returns one
            exc = AnalysisFailed("pipeline produced no assessment", run_id=run.run_id)
            self._fail(run, exc)
            raise exc

        self.repo.transition(run, JobState.FINALIZING, detail="persisting assessment")
        self._finalise(run, result, artifact, elapsed_ms)
        return SubmissionResult(run=run, stages=stage_summary(result))

    def _finalise(self, run: RunRecord, result: PipelineResult, artifact,
                  elapsed_ms: int) -> None:
        """Persist the assessment, the artifact and COMPLETED in ONE transaction.

        ADR-0018 Decision 2: there is no code path that marks a run complete and then
        writes the result. A crash before commit leaves neither; a crash after leaves
        both.
        """
        document = result.assessment.to_dict()
        try:
            with self.db.transaction() as cur:
                assessment_id = self.repo.store_assessment(document, cursor=cur)
                # Per-session detail, in the same transaction as the assessment it was
                # computed alongside: a crash before commit leaves neither stored, a
                # crash after leaves both (ADR-0018 Decision 2, extended here rather
                # than re-litigated). Read-only projection -- these are the exact
                # `SessionEvidence` objects `result.assessment` was already derived
                # from, not a new computation.
                self.repo.store_sessions(
                    run.run_id, [s.to_dict() for s in result.sessions], cursor=cur)
                # Re-home the artifact record under the real capture_id now that it is
                # known. The file itself is content-addressed by its own hash already.
                self.repo.add_artifact(artifact, cursor=cur)
                self.repo.transition(
                    run, JobState.COMPLETED, cursor=cur,
                    detail="assessment " + assessment_id,
                    assessment_id=assessment_id,
                    capture_id=result.capture_id,
                    ingest_status=result.run.status.value,
                    duration_ms=elapsed_ms)
        except BackendError as exc:
            self._fail(run, exc)
            raise
        log.info("analysis completed", extra={
            "run_id": run.run_id, "capture_id": run.capture_id,
            "assessment_id": run.assessment_id, "duration_ms": elapsed_ms})

    # --------------------------------------------------------------- reading
    def get_run(self, run_id: str) -> RunRecord:
        return self.repo.get_run(run_id)

    def get_assessment(self, run_id: str) -> Dict[str, Any]:
        """The canonical document for a run, returned verbatim."""
        run = self.repo.get_run(run_id)
        if not run.assessment_id:
            raise NotFound(
                "this run has no assessment",
                detail={"run_id": run_id, "state": run.state.value},
                run_id=run_id)
        return self.repo.get_assessment(run.assessment_id)

    def get_sessions(self, run_id: str) -> List[Dict[str, Any]]:
        """Per-session detail for a run, verbatim, in reconstruction order.

        A run that exists but has no sessions stored (e.g. it failed before Phase 3,
        or predates this table) returns an empty list rather than 404 -- the run
        itself is real, it simply has nothing here to show.
        """
        self.repo.get_run(run_id)          # 404 for an unknown run id
        return self.repo.get_sessions(run_id)

    def list_runs(self, limit: int, offset: int,
                  state: Optional[JobState] = None,
                  capture_id: Optional[str] = None) -> Tuple[List[RunRecord], int]:
        return self.repo.list_runs(limit=limit, offset=offset, state=state,
                                   capture_id=capture_id)

    def list_artifacts(self, run_id: str, *, verify: bool = False) -> List[Dict[str, Any]]:
        self.repo.get_run(run_id)          # 404 rather than an empty list
        out: List[Dict[str, Any]] = []
        for record in self.repo.list_artifacts(run_id):
            item = record.to_dict()
            # The stored path is internal detail; a client gets identity, not location.
            item.pop("relative_path", None)
            if verify:
                item["integrity"] = "OK" if self.artifacts.is_intact(record) else "MISMATCH"
            out.append(item)
        return out

    def events(self, run_id: str) -> List[Dict[str, Any]]:
        return self.repo.events(run_id)

    def health(self) -> Dict[str, Any]:
        count, total = self.artifacts.size_on_disk()
        return {
            "database": "ok" if self.db.healthy() else "unavailable",
            "schema_version": self.db.schema_version(),
            "artifact_count": count,
            "artifact_bytes": total,
            "limits": self.limits.to_dict(),
        }

    # --------------------------------------------------------------- helpers
    def _fail(self, run: RunRecord, exc: BackendError) -> None:
        """Record a failure on the run. Never swallows; the caller still raises."""
        try:
            self.repo.transition(
                run, JobState.FAILED, detail=exc.code,
                error_code=exc.code,
                error_message=exc.message)
        except BackendError:               # pragma: no cover - already terminal
            log.error("could not record failure for run %s", run.run_id)
        log.warning("run failed", extra={"run_id": run.run_id, "code": exc.code})

    def _admit(self) -> None:
        with self._admission:
            if self._in_flight >= self.limits.max_queued_jobs:
                raise ResourceLimitExceeded(
                    "too many analyses in flight",
                    detail={"max_queued_jobs": self.limits.max_queued_jobs})
            self._in_flight += 1
        self._slots.acquire()

    def _release(self) -> None:
        self._slots.release()
        with self._admission:
            self._in_flight = max(0, self._in_flight - 1)

    def close(self) -> None:
        self.db.close()
