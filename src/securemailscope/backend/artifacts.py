"""
Artifact store (doc 21 §8, §13).

Forensic identity is the SHA-256, never the filename. Two consequences drive this
module:

1. **Client filenames never build paths.** Every stored path is assembled from
   generated internal identifiers. A filename containing `../`, an absolute prefix, a
   NUL, a drive letter or a shell metacharacter is retained only as
   `original_filename`, a display label that no filesystem call ever sees. This is the
   one place where a traversal could exist, so it is removed structurally rather than
   by sanitising and hoping.
2. **Integrity is re-checkable.** `verify()` re-hashes a stored artifact on demand. A
   file that changed after persistence surfaces as `ArtifactIntegrityError`; it is
   never silently accepted. The project does not claim integrity it cannot demonstrate,
   so this is a real re-read, not a filename comparison.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import BinaryIO, Optional, Tuple

from securemailscope.backend.errors import (
    ArtifactIntegrityError, CaptureTooLarge, PersistenceFailed,
)
from securemailscope.backend.repository import ArtifactRecord
from securemailscope.evidence.capture import sha256_file

_CHUNK = 1024 * 1024

#: Artifact kinds this phase produces. Rendered reports arrive in Phase 9.
KIND_PCAP = "pcap"


def safe_display_name(raw: Optional[str], fallback: str = "capture.pcap") -> str:
    """Reduce a client filename to a harmless display label.

    This value is stored and shown; it is never used to build a path. Control
    characters and separators are stripped anyway, so that a hostile name cannot
    corrupt a log line or a terminal rendering it.
    """
    if not raw:
        return fallback
    name = os.path.basename(raw.replace("\\", "/"))
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '/\x00')
    name = name.strip().lstrip(".")
    if not name:
        return fallback
    return name[:255]


class ArtifactStore:
    """Content-addressed artifacts under a single root directory."""

    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    # ------------------------------------------------------------------ paths
    def _relative_path(self, capture_id: str, artifact_id: str, kind: str) -> str:
        """Built purely from generated identifiers. No client input reaches this."""
        shard = capture_id[:2] if len(capture_id) >= 2 else "00"
        return "{0}/{1}/{2}.{3}".format(shard, capture_id, artifact_id, kind)

    def absolute(self, relative_path: str) -> str:
        """Resolve a stored relative path, refusing anything outside the root.

        The paths this store writes cannot escape by construction; this check exists
        because the value round-trips through a database, and a stored path is input
        again on the way back out.
        """
        candidate = os.path.abspath(os.path.join(self.root, relative_path))
        root = self.root + os.sep
        if not candidate.startswith(root):
            raise PersistenceFailed("artifact path escapes the store root",
                                    detail={"relative_path": relative_path})
        return candidate

    # ------------------------------------------------------------------ write
    def store_stream(self, source: BinaryIO, *, run_id: str, capture_id: str,
                     kind: str = KIND_PCAP,
                     original_filename: Optional[str] = None,
                     max_bytes: Optional[int] = None) -> ArtifactRecord:
        """Copy a stream into the store, hashing as it is written.

        Hashing during the write means the recorded digest describes the bytes that
        actually landed on disk, rather than bytes read separately and assumed equal.
        """
        artifact_id = uuid.uuid4().hex
        relative = self._relative_path(capture_id, artifact_id, kind)
        target = self.absolute(relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)

        digest = hashlib.sha256()
        size = 0
        try:
            with open(target, "wb") as out:
                while True:
                    chunk = source.read(_CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if max_bytes is not None and size > max_bytes:
                        out.close()
                        self._discard(target)
                        raise CaptureTooLarge(
                            "capture exceeds the configured upload ceiling",
                            detail={"max_bytes": max_bytes})
                    digest.update(chunk)
                    out.write(chunk)
        except CaptureTooLarge:
            raise
        except OSError as exc:
            self._discard(target)
            raise PersistenceFailed("could not write artifact",
                                    detail={"reason": type(exc).__name__})

        return ArtifactRecord(
            artifact_id=artifact_id, run_id=run_id, kind=kind,
            sha256=digest.hexdigest(), size_bytes=size, relative_path=relative,
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            original_filename=safe_display_name(original_filename))

    def store_file(self, path: str, *, run_id: str, capture_id: str,
                   kind: str = KIND_PCAP,
                   original_filename: Optional[str] = None) -> ArtifactRecord:
        with open(path, "rb") as handle:
            return self.store_stream(
                handle, run_id=run_id, capture_id=capture_id, kind=kind,
                original_filename=original_filename or os.path.basename(path))

    # ----------------------------------------------------------------- verify
    def verify(self, artifact: ArtifactRecord) -> None:
        """Re-hash a stored artifact. Raises on absence or mismatch."""
        target = self.absolute(artifact.relative_path)
        if not os.path.isfile(target):
            raise ArtifactIntegrityError(
                "stored artifact is missing",
                detail={"artifact_id": artifact.artifact_id})
        actual = sha256_file(target)
        if actual != artifact.sha256:
            raise ArtifactIntegrityError(
                "stored artifact no longer matches its recorded SHA-256",
                detail={"artifact_id": artifact.artifact_id,
                        "recorded_sha256": artifact.sha256,
                        "actual_sha256": actual})

    def is_intact(self, artifact: ArtifactRecord) -> bool:
        try:
            self.verify(artifact)
            return True
        except ArtifactIntegrityError:
            return False

    def size_on_disk(self) -> Tuple[int, int]:
        """(file count, total bytes) — for health reporting and growth awareness."""
        count = total = 0
        for dirpath, _dirs, files in os.walk(self.root):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(dirpath, name))
                    count += 1
                except OSError:            # pragma: no cover - racing deletion
                    continue
        return count, total

    @staticmethod
    def _discard(path: str) -> None:
        try:
            os.remove(path)
        except OSError:                    # pragma: no cover - best effort cleanup
            pass

    def purge(self) -> None:
        """Remove the whole store. Test and operator use only."""
        shutil.rmtree(self.root, ignore_errors=True)
        os.makedirs(self.root, exist_ok=True)
