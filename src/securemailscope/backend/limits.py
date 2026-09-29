"""
Backend resource limits (Phase 8, doc 21 §11).

SecureMailScope parses untrusted PCAPs, so limits are a security control rather than a
capacity setting. Two rules govern this module:

1. **Phase-2 limits are reused, never replaced.** `max_capture_bytes`, `max_frames` and
   `tshark_timeout_s` already exist on `Config` and keep their meaning. A backend that
   quietly raised one would remove a safety property the earlier phase established.
2. **Every default has a stated reason.** None of these numbers is derived from a
   benchmark; they are bounded-resource engineering choices for a single analyst
   workstation, and they say so.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from securemailscope.config import Config

_MiB = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    """Backend limits, layered over `Config` rather than duplicating it.

    Defaults are literals; the environment is read in `load()` rather than in field
    defaults. Dataclass defaults evaluate once at import, so reading `os.environ` there
    would make `SMS_*` overrides depend on import order — they would appear to work and
    then silently stop when something imported this module early.
    """

    #: Largest HTTP request body accepted. Lower than `max_capture_bytes` on purpose:
    #: an uploaded body is streamed through the process, whereas the 2 GiB Phase-2
    #: ceiling governs a capture already sitting on disk.
    max_upload_bytes: int = 256 * _MiB

    #: One analysis at a time. ADR-0018 / doc 21 §12: an explicit documented invariant,
    #: not an accidental limitation. SQLite takes one writer; the pipeline is CPU-bound.
    max_concurrent_analyses: int = 1

    #: Bounds memory and disk under a submission burst. Beyond this, submissions are
    #: refused with RESOURCE_LIMIT_EXCEEDED rather than silently dropped.
    max_queued_jobs: int = 8

    #: Whole-pipeline ceiling. Must be >= tshark_timeout_s or the subprocess budget
    #: could not be spent; `load()` enforces that rather than trusting it.
    max_analysis_seconds: int = 600

    #: Bounds a listing response.
    max_page_size: int = 100
    default_page_size: int = 20

    #: Largest JSON request body (submission metadata, not captures).
    max_json_bytes: int = 64 * 1024

    def effective_upload_ceiling(self, config: Config) -> int:
        """The real upload ceiling: never above the Phase-2 capture ceiling.

        Clamped rather than merely documented, so raising `SMS_MAX_UPLOAD_BYTES` alone
        cannot be used to bypass `SMS_MAX_CAPTURE_BYTES`.
        """
        if config.max_capture_bytes <= 0:       # 0 means unlimited in Phase 2
            return self.max_upload_bytes
        return min(self.max_upload_bytes, config.max_capture_bytes)

    def page_size(self, requested: int) -> int:
        if requested <= 0:
            return self.default_page_size
        return min(requested, self.max_page_size)

    def to_dict(self) -> dict:
        return {
            "max_upload_bytes": self.max_upload_bytes,
            "max_concurrent_analyses": self.max_concurrent_analyses,
            "max_queued_jobs": self.max_queued_jobs,
            "max_analysis_seconds": self.max_analysis_seconds,
            "max_page_size": self.max_page_size,
            "default_page_size": self.default_page_size,
            "max_json_bytes": self.max_json_bytes,
        }

    @staticmethod
    def load(config: Optional[Config] = None) -> "Limits":
        """Build limits from the environment, validating their relationship."""
        def _int(name: str, default: int) -> int:
            raw = os.environ.get(name)
            if raw is None or raw.strip() == "":
                return default
            try:
                return int(raw)
            except ValueError:
                raise ValueError("{0} must be an integer, got {1!r}".format(name, raw))

        limits = Limits(
            max_upload_bytes=_int("SMS_MAX_UPLOAD_BYTES", 256 * _MiB),
            max_concurrent_analyses=_int("SMS_MAX_CONCURRENT_ANALYSES", 1),
            max_queued_jobs=_int("SMS_MAX_QUEUED_JOBS", 8),
            max_analysis_seconds=_int("SMS_MAX_ANALYSIS_SECONDS", 600),
            max_page_size=_int("SMS_MAX_PAGE_SIZE", 100),
            default_page_size=_int("SMS_DEFAULT_PAGE_SIZE", 20),
            max_json_bytes=_int("SMS_MAX_JSON_BYTES", 64 * 1024),
        )
        cfg = config or Config.load()
        if limits.max_analysis_seconds < cfg.tshark_timeout_s:
            raise ValueError(
                "SMS_MAX_ANALYSIS_SECONDS ({0}) is below SMS_TSHARK_TIMEOUT_S ({1}); "
                "the pipeline budget cannot be smaller than the subprocess budget it "
                "contains".format(limits.max_analysis_seconds, cfg.tshark_timeout_s))
        if limits.max_concurrent_analyses < 1 or limits.max_queued_jobs < 1:
            raise ValueError("concurrency and queue limits must be at least 1")
        return limits
