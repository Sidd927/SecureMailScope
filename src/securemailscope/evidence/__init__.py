"""Canonical evidence model (docs/architecture/03, 04)."""
from securemailscope.evidence.states import (
    EvidenceState, Provenance, EvidenceField,
)
from securemailscope.evidence.capture import Capture, sha256_file
from securemailscope.evidence.run import (
    AnalysisRun, RunStatus, EVIDENCE_SCHEMA_VERSION, ENGINE_VERSION,
)

__all__ = [
    "EvidenceState", "Provenance", "EvidenceField", "Capture", "sha256_file",
    "AnalysisRun", "RunStatus", "EVIDENCE_SCHEMA_VERSION", "ENGINE_VERSION",
]
