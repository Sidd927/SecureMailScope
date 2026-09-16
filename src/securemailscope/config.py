"""Runtime configuration. Environment-overridable, safe defaults, offline-first."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    # tshark binary: resolved via PATH unless explicitly configured.
    tshark_path: str = os.environ.get("SMS_TSHARK_PATH", "tshark")
    # Minimum acceptable tshark major version (ADR-0001).
    tshark_min_major: int = int(os.environ.get("SMS_TSHARK_MIN_MAJOR", "4"))
    # Hard ceiling on capture size to bound resource use (bytes). 0 = unlimited.
    max_capture_bytes: int = int(os.environ.get("SMS_MAX_CAPTURE_BYTES", str(2 * 1024**3)))
    # tshark subprocess timeout (seconds).
    tshark_timeout_s: int = int(os.environ.get("SMS_TSHARK_TIMEOUT_S", "300"))
    # Ceiling on normalized frames per capture. PROVISIONAL: chosen to bound memory on an
    # analyst workstation, not derived from a benchmark (see Phase-2 §15). Exceeding it
    # yields LIMIT_EXCEEDED -- evidence is never silently discarded.
    max_frames: int = int(os.environ.get("SMS_MAX_FRAMES", "2000000"))

    @staticmethod
    def load() -> "Config":
        return Config()
