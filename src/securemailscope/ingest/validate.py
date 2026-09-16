"""
Capture validation boundary (Phase-2 §12).

One place decides whether a path is an acceptable capture, and *why not* when it
isn't. The distinctions EMPTY != MALFORMED != PARTIAL are preserved deliberately:
collapsing them would let "we saw nothing" read as "nothing is wrong".

Security: the path is untrusted input. We resolve it, reject non-regular files and
unreadable files, and never interpolate it into a shell (the adapter uses an
argument array).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from securemailscope.config import Config


class ValidationResult(str, Enum):
    OK = "OK"
    NOT_FOUND = "NOT_FOUND"
    NOT_A_FILE = "NOT_A_FILE"
    UNREADABLE = "UNREADABLE"
    EMPTY_FILE = "EMPTY_FILE"      # zero bytes on disk (distinct from zero packets)
    TOO_LARGE = "TOO_LARGE"


@dataclass(frozen=True)
class CaptureValidation:
    result: ValidationResult
    detail: str
    resolved_path: Optional[str] = None
    size_bytes: int = 0

    @property
    def ok(self) -> bool:
        return self.result is ValidationResult.OK


def validate_capture(path: str, config: Optional[Config] = None) -> CaptureValidation:
    """Validate an untrusted capture path before any subprocess touches it."""
    cfg = config or Config.load()

    if not isinstance(path, str) or not path:
        return CaptureValidation(ValidationResult.NOT_FOUND, "empty or non-string path")

    # Resolve symlinks/relative segments so downstream logging and identity are stable.
    # NOTE: we deliberately do NOT confine to a base directory here -- this is an
    # analyst-run CLI/API on their own files. A server deployment that accepts uploads
    # must add its own containment (docs/architecture/06 §5) before exposing this.
    resolved = os.path.realpath(os.path.expanduser(path))

    if not os.path.exists(resolved):
        return CaptureValidation(ValidationResult.NOT_FOUND, "file does not exist", resolved)
    if not os.path.isfile(resolved):
        return CaptureValidation(ValidationResult.NOT_A_FILE,
                                 "path is not a regular file", resolved)
    if not os.access(resolved, os.R_OK):
        return CaptureValidation(ValidationResult.UNREADABLE, "file is not readable", resolved)

    size = os.path.getsize(resolved)
    if size == 0:
        return CaptureValidation(ValidationResult.EMPTY_FILE, "file is zero bytes",
                                 resolved, size)
    if cfg.max_capture_bytes and size > cfg.max_capture_bytes:
        return CaptureValidation(
            ValidationResult.TOO_LARGE,
            f"{size} bytes exceeds configured ceiling {cfg.max_capture_bytes}",
            resolved, size)

    return CaptureValidation(ValidationResult.OK, "acceptable capture", resolved, size)
