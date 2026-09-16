"""Capture metadata: the forensic anchor for an analysis run (docs/architecture/03, 04 §4)."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

from securemailscope import ANALYSIS_VERSION

_HASH_CHUNK = 1024 * 1024  # stream the file; never load a whole PCAP into memory


def sha256_file(path: str) -> str:
    """Streamed SHA-256 of a file. We compute this ourselves (ADR-0001) so forensic
    integrity does not depend on an external tool."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class Capture:
    """Immutable record identifying and describing an ingested capture."""

    capture_id: str            # sha256 (stable, content-addressed)
    sha256: str
    filename: str
    size_bytes: int
    ingested_at: str           # ISO-8601 UTC
    analysis_version: str
    tool_versions: Dict[str, str] = field(default_factory=dict)
    packet_count: Optional[int] = None   # filled after dissection; None until then
    truncated: bool = False              # tshark exit 14 / cut-short

    @classmethod
    def from_file(cls, path: str, *, tool_versions: Optional[Dict[str, str]] = None) -> "Capture":
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        digest = sha256_file(path)
        return cls(
            capture_id=digest,
            sha256=digest,
            filename=os.path.basename(path),
            size_bytes=os.path.getsize(path),
            ingested_at=datetime.now(timezone.utc).isoformat(),
            analysis_version=ANALYSIS_VERSION,
            tool_versions=dict(tool_versions or {}),
        )

    def with_dissection(self, *, packet_count: int, truncated: bool,
                        tool_versions: Optional[Dict[str, str]] = None) -> "Capture":
        """Return a new Capture enriched with post-dissection facts (immutably)."""
        merged = dict(self.tool_versions)
        merged.update(tool_versions or {})
        return Capture(
            capture_id=self.capture_id, sha256=self.sha256, filename=self.filename,
            size_bytes=self.size_bytes, ingested_at=self.ingested_at,
            analysis_version=self.analysis_version, tool_versions=merged,
            packet_count=packet_count, truncated=truncated,
        )

    def to_dict(self) -> dict:
        return {
            "capture_id": self.capture_id, "sha256": self.sha256, "filename": self.filename,
            "size_bytes": self.size_bytes, "ingested_at": self.ingested_at,
            "analysis_version": self.analysis_version, "tool_versions": self.tool_versions,
            "packet_count": self.packet_count, "truncated": self.truncated,
        }
