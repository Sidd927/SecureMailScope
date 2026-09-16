"""
Ingest pipeline: the single application-level entry point (Phase-2 §13).

    analyze_capture(path) -> (AnalysisRun, [FrameEvidence])

    PCAP -> validation -> hashing/identity -> tshark dissection -> normalization -> AnalysisRun

Callers never construct tshark commands or see tshark field names. This module owns
orchestration and status mapping only; it produces NO security verdicts (Phase-2 §9).
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from securemailscope.config import Config
from securemailscope.dissect import (
    DissectStatus, TsharkAdapter, TsharkNotFound, TsharkVersionError,
    FrameEvidence, normalize_stream, summarize,
)
from securemailscope.evidence.capture import Capture
from securemailscope.evidence.run import AnalysisRun, RunStatus
from securemailscope.ingest.validate import ValidationResult, validate_capture

#: Dissection outcomes that carry usable evidence, and the run status they imply.
_STATUS_MAP = {
    DissectStatus.OK: RunStatus.COMPLETED,
    DissectStatus.TRUNCATED: RunStatus.PARTIAL,
    DissectStatus.LIMIT_EXCEEDED: RunStatus.PARTIAL,
    DissectStatus.EMPTY: RunStatus.EMPTY,
}


def analyze_capture(
    path: str,
    config: Optional[Config] = None,
    adapter: Optional[TsharkAdapter] = None,
) -> Tuple[AnalysisRun, List[FrameEvidence]]:
    """Run the ingest/dissection pipeline over an untrusted capture."""
    cfg = config or Config.load()
    adapter = adapter or TsharkAdapter(cfg)

    # --- 1. validation ----------------------------------------------------
    validation = validate_capture(path, cfg)
    if not validation.ok:
        # Build a minimal run so failures are still first-class, traceable records.
        placeholder = Capture(
            capture_id="", sha256="", filename=path.rsplit("/", 1)[-1],
            size_bytes=validation.size_bytes, ingested_at="",
            analysis_version="", tool_versions={},
        )
        run = AnalysisRun.create(placeholder, path)
        run.advance(RunStatus.VALIDATING)
        run.fail(f"validation:{validation.result.value}: {validation.detail}")
        return run, []

    resolved = validation.resolved_path or path

    # --- 2. identity / hashing -------------------------------------------
    capture = Capture.from_file(resolved)
    run = AnalysisRun.create(capture, resolved)
    run.advance(RunStatus.VALIDATING)

    # --- 3. dissection (streaming) ---------------------------------------
    run.advance(RunStatus.DISSECTING)
    try:
        tshark_version = adapter.version()
    except (TsharkNotFound, TsharkVersionError) as exc:
        run.fail(f"tshark unavailable: {exc}")
        return run, []
    run.tshark_version = tshark_version

    frames: List[FrameEvidence] = []
    try:
        with adapter.dissect_streaming(resolved) as (status_of, records):
            run.advance(RunStatus.NORMALIZING)
            for frame in normalize_stream(records, capture_id=capture.capture_id):
                frames.append(frame)
        dissect_status = status_of()
    except Exception as exc:  # defensive: untrusted input must never crash the caller
        run.fail(f"dissection error: {type(exc).__name__}: {exc}")
        return run, []

    run.dissection_status = dissect_status.value
    run.packet_count = len(frames)

    # --- 4. status mapping (no security meaning) --------------------------
    mapped = _STATUS_MAP.get(dissect_status)
    if mapped is None:
        run.fail(f"dissection failed: {dissect_status.value}")
        return run, frames
    if dissect_status is DissectStatus.TRUNCATED:
        run.warn("capture is truncated; evidence retained but completeness is INCOMPLETE")
    if dissect_status is DissectStatus.LIMIT_EXCEEDED:
        run.warn(f"frame ceiling {cfg.max_frames} reached; evidence is partial, not discarded")
    if mapped is RunStatus.EMPTY:
        run.warn("capture parsed cleanly but contains zero packets")

    # --- 5. normalization summary ----------------------------------------
    run.normalization_status = "OK"
    run.evidence_summary = summarize(frames)
    run.capture = capture.with_dissection(
        packet_count=len(frames),
        truncated=dissect_status is DissectStatus.TRUNCATED,
        tool_versions={"tshark": tshark_version},
    )
    run.advance(mapped)
    return run, frames
