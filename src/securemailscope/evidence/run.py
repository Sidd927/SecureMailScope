"""
AnalysisRun: the stable contract describing one analysis of one capture.

This is the output of Phase 2 and the input contract for Phase 3 (session
reconstruction). It records what was done, with which tool versions, and what was
observed -- never whether anything is secure.

IMPORTANT (Phase-2 §11): run status describes the *analysis*, not the *security* of
the traffic. PARTIAL means "the capture was truncated", not "the mail server is
partially safe". No security verdict may be derived from RunStatus.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from securemailscope import ANALYSIS_VERSION
from securemailscope.evidence.capture import Capture

#: Version of the canonical evidence schema. Bump when the shape changes so stored
#: runs remain interpretable (docs/architecture/04 §4).
EVIDENCE_SCHEMA_VERSION = "1.0"
#: Version of the ingest/dissection engine specifically.
ENGINE_VERSION = "0.2.0"


class RunStatus(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    DISSECTING = "DISSECTING"
    NORMALIZING = "NORMALIZING"
    COMPLETED = "COMPLETED"    # usable evidence, capture complete
    EMPTY = "EMPTY"            # valid capture, zero packets
    PARTIAL = "PARTIAL"        # usable evidence, capture truncated/limited
    FAILED = "FAILED"          # could not produce evidence


#: Statuses from which usable evidence exists.
_EVIDENCE_BEARING = {RunStatus.COMPLETED, RunStatus.PARTIAL}


@dataclass
class AnalysisRun:
    run_id: str
    capture: Capture
    source_path: str
    status: RunStatus = RunStatus.CREATED
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

    # versions (Phase-2 §14)
    securemailscope_version: str = ANALYSIS_VERSION
    engine_version: str = ENGINE_VERSION
    schema_version: str = EVIDENCE_SCHEMA_VERSION
    tshark_version: Optional[str] = None

    # outcomes
    packet_count: int = 0
    dissection_status: Optional[str] = None
    normalization_status: Optional[str] = None
    evidence_summary: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @classmethod
    def create(cls, capture: Capture, source_path: str) -> "AnalysisRun":
        return cls(run_id=uuid.uuid4().hex, capture=capture, source_path=source_path)

    # ---- transitions --------------------------------------------------------
    def advance(self, status: RunStatus) -> None:
        self.status = status
        if status in (RunStatus.COMPLETED, RunStatus.EMPTY,
                      RunStatus.PARTIAL, RunStatus.FAILED):
            self.completed_at = datetime.now(timezone.utc).isoformat()

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def fail(self, message: str) -> None:
        self.errors.append(message)
        self.advance(RunStatus.FAILED)

    @property
    def has_evidence(self) -> bool:
        """Whether downstream phases have something to analyse. Explicitly NOT a
        statement about security."""
        return self.status in _EVIDENCE_BEARING and self.packet_count > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "capture": self.capture.to_dict(),
            "source_path": self.source_path,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "versions": {
                "securemailscope": self.securemailscope_version,
                "engine": self.engine_version,
                "schema": self.schema_version,
                "tshark": self.tshark_version,
            },
            "packet_count": self.packet_count,
            "dissection_status": self.dissection_status,
            "normalization_status": self.normalization_status,
            "evidence_summary": self.evidence_summary,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }
