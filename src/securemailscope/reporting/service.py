"""
Report generation and storage (doc 22 §12, §13, ADR-0021).

Renders a report, stores it through the **Phase-8 artifact store** — not a second one —
and returns identity plus integrity metadata.

The store and repository are injected, and their types are imported only under
`TYPE_CHECKING`. `reporting/` therefore imports nothing from `backend/` at runtime: the
dependency runs one way, `backend/api.py` composing `reporting/` and not the reverse.
An import cycle between the two would otherwise be real, and a lazy import hiding it
would be worse than not having one.

Two properties this module exists to hold:

* **A report failure never touches the assessment.** It raises a `ReportError`; the run
  stays `COMPLETED` and every other format remains available (ADR-0019 Decision 4).
* **A report is regenerated rather than served** when the stored artefact is missing,
  fails verification, or was produced under a different report schema or renderer
  version. A report from an incompatible renderer is never silently handed over.
"""
from __future__ import annotations

import io
import json
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:            # pragma: no cover - typing only
    from securemailscope.backend.artifacts import ArtifactStore
    from securemailscope.backend.repository import ArtifactRecord, Repository

from securemailscope.reporting.errors import (
    ReportError, ReportTooLarge, UnsupportedFormat,
)
from securemailscope.reporting.html import render_html
from securemailscope.reporting.model import (
    RENDERER_VERSION, REPORT_SCHEMA_VERSION, ReportDocument,
)
from securemailscope.reporting.projection import project

FORMAT_HTML = "html"
FORMAT_PDF = "pdf"
FORMAT_JSON = "json"
SUPPORTED_FORMATS = (FORMAT_HTML, FORMAT_PDF, FORMAT_JSON)

MEDIA_TYPE = {
    FORMAT_HTML: "text/html; charset=utf-8",
    FORMAT_PDF: "application/pdf",
    FORMAT_JSON: "application/json",
}

#: Artifact kinds. Extends the Phase-8 vocabulary; the store was already
#: kind-parameterised and reserved this use.
KIND = {FORMAT_HTML: "html", FORMAT_PDF: "pdf"}

#: doc 22 §15. Bounds artifact growth from one pathological assessment.
MAX_REPORT_BYTES = 32 * 1024 * 1024

#: Encoded into the artifact's display name so a stored report records the renderer
#: that produced it. Parsed back out to decide regeneration.
_STAMP = re.compile(r"^securemailscope-(?P<assessment>[0-9a-f]+)"
                    r"\.r(?P<report>[0-9.]+)\.v(?P<renderer>[0-9.]+)\.(?P<ext>\w+)$")


def safe_filename(assessment_id: str, fmt: str) -> str:
    """Download filename built from internal identifiers only (doc 22 §14).

    The uploaded PCAP name never contributes. `assessment_id` is hex from a hash, but it
    is filtered anyway rather than trusted for being usually-safe.
    """
    if fmt not in SUPPORTED_FORMATS:
        raise UnsupportedFormat("unsupported report format",
                                detail={"format": fmt,
                                        "supported": list(SUPPORTED_FORMATS)})
    ident = re.sub(r"[^A-Za-z0-9_-]", "", str(assessment_id))[:64] or "assessment"
    return "securemailscope-{0}.{1}".format(ident, fmt)


def _stamped_name(assessment_id: str, fmt: str) -> str:
    ident = re.sub(r"[^A-Za-z0-9_-]", "", str(assessment_id))[:64] or "assessment"
    return "securemailscope-{0}.r{1}.v{2}.{3}".format(
        ident, REPORT_SCHEMA_VERSION, RENDERER_VERSION, fmt)


def _is_current(record: "ArtifactRecord") -> bool:
    """Whether a stored artefact was produced by this report schema and renderer."""
    match = _STAMP.match(record.original_filename or "")
    if not match:
        return False
    return (match.group("report") == REPORT_SCHEMA_VERSION
            and match.group("renderer") == RENDERER_VERSION)


def render_bytes(assessment: Dict[str, Any], fmt: str) -> Tuple[bytes, ReportDocument]:
    """Render one format. Raises `ReportError` subclasses; never returns a stub."""
    document = project(assessment)
    if fmt == FORMAT_HTML:
        payload = render_html(document).encode("utf-8")
    elif fmt == FORMAT_PDF:
        from securemailscope.reporting.pdf import render_pdf
        payload = render_pdf(document)
    elif fmt == FORMAT_JSON:
        # The canonical document, unaltered. Identical to the assessment endpoint.
        payload = json.dumps(assessment, indent=2, sort_keys=True).encode("utf-8")
    else:
        raise UnsupportedFormat("unsupported report format",
                                detail={"format": fmt,
                                        "supported": list(SUPPORTED_FORMATS)})
    if len(payload) > MAX_REPORT_BYTES:
        raise ReportTooLarge("rendered report exceeds the size ceiling",
                             detail={"bytes": len(payload),
                                     "max_bytes": MAX_REPORT_BYTES})
    return payload, document


class ReportService:
    """Renders, stores and verifies report artifacts for completed runs."""

    def __init__(self, repository: "Repository",
                 artifacts: "ArtifactStore") -> None:
        self.repo = repository
        self.artifacts = artifacts

    # ------------------------------------------------------------- generation
    def get_or_create(self, run_id: str, assessment: Dict[str, Any],
                      fmt: str) -> Tuple[bytes, Dict[str, Any]]:
        """Return report bytes plus metadata, rendering only when necessary.

        JSON is never stored as an artefact: it is the canonical document, already
        persisted by Phase 8, and storing a second copy would create a second place for
        it to drift.
        """
        if fmt == FORMAT_JSON:
            payload, document = render_bytes(assessment, fmt)
            return payload, self._metadata(None, document, fmt, len(payload))

        existing = self._usable_artifact(run_id, fmt)
        if existing is not None:
            path = self.artifacts.absolute(existing.relative_path)
            with open(path, "rb") as handle:
                payload = handle.read()
            document = project(assessment)
            return payload, self._metadata(existing, document, fmt, len(payload))

        payload, document = render_bytes(assessment, fmt)
        record = self._store(run_id, assessment, fmt, payload)
        return payload, self._metadata(record, document, fmt, len(payload))

    def _usable_artifact(self, run_id: str, fmt: str) -> Optional["ArtifactRecord"]:
        """The newest stored report of this format that is current AND intact.

        Missing, tampered or stale-renderer artefacts are ignored so the caller
        regenerates, rather than being served something this build did not produce.
        """
        kind = KIND[fmt]
        candidates = [a for a in self.repo.list_artifacts(run_id) if a.kind == kind]
        for record in reversed(candidates):
            if _is_current(record) and self.artifacts.is_intact(record):
                return record
        return None

    def _store(self, run_id: str, assessment: Dict[str, Any], fmt: str,
               payload: bytes) -> "ArtifactRecord":
        capture_id = str(assessment.get("capture_id") or run_id)
        record = self.artifacts.store_stream(
            io.BytesIO(payload), run_id=run_id, capture_id=capture_id,
            kind=KIND[fmt],
            original_filename=_stamped_name(
                str(assessment.get("assessment_id") or ""), fmt))
        self.repo.add_artifact(record)
        return record

    # --------------------------------------------------------------- metadata
    def _metadata(self, record: Optional["ArtifactRecord"], document: ReportDocument,
                  fmt: str, size: int) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "format": fmt,
            "media_type": MEDIA_TYPE[fmt],
            "filename": safe_filename(document.metadata.assessment_id, fmt),
            "assessment_id": document.metadata.assessment_id,
            "capture_id": document.metadata.capture_id,
            "report_schema_version": document.metadata.report_schema_version,
            "renderer_version": document.metadata.renderer_version,
            "posture_schema_version": document.metadata.posture_schema_version,
            "posture_engine_version": document.metadata.posture_engine_version,
            "size_bytes": size,
            "sections": list(document.section_ids),
            "truncations": list(document.truncations),
        }
        if record is not None:
            meta.update({
                "artifact_id": record.artifact_id,
                "report_sha256": record.sha256,
                "created_at": record.created_at,
                "integrity": "OK" if self.artifacts.is_intact(record) else "MISMATCH",
            })
        else:
            # JSON is served from the canonical document and is not an artefact.
            meta.update({"artifact_id": None, "report_sha256": None,
                         "created_at": None, "integrity": "NOT_STORED"})
        return meta

    def list_reports(self, run_id: str,
                     assessment: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Available report formats, with integrity for anything already stored."""
        from securemailscope.reporting.pdf import available as pdf_available

        stored = {a.kind: a for a in self.repo.list_artifacts(run_id)
                  if a.kind in KIND.values()}
        out: List[Dict[str, Any]] = []
        assessment_id = str((assessment or {}).get("assessment_id") or "")
        for fmt in SUPPORTED_FORMATS:
            entry: Dict[str, Any] = {
                "format": fmt,
                "media_type": MEDIA_TYPE[fmt],
                "filename": safe_filename(assessment_id, fmt),
                "renderer_available": True if fmt != FORMAT_PDF else pdf_available(),
                "report_schema_version": REPORT_SCHEMA_VERSION,
                "renderer_version": RENDERER_VERSION,
            }
            record = stored.get(KIND.get(fmt, ""))
            if record is not None:
                entry.update({
                    "generated": True,
                    "artifact_id": record.artifact_id,
                    "report_sha256": record.sha256,
                    "size_bytes": record.size_bytes,
                    "created_at": record.created_at,
                    "current": _is_current(record),
                    "integrity": "OK" if self.artifacts.is_intact(record)
                                 else "MISMATCH",
                })
            else:
                entry.update({"generated": False, "artifact_id": None,
                              "report_sha256": None, "size_bytes": None,
                              "created_at": None, "current": None,
                              "integrity": None})
            out.append(entry)
        return out
