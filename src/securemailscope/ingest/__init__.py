"""Ingest layer: validation boundary + pipeline entry point (Phase 2)."""
from securemailscope.ingest.validate import (
    validate_capture, CaptureValidation, ValidationResult,
)
from securemailscope.ingest.pipeline import analyze_capture

__all__ = ["validate_capture", "CaptureValidation", "ValidationResult", "analyze_capture"]
