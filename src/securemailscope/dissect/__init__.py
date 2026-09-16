"""Dissection layer: safe tshark adapter + normalization boundary (ADR-0001)."""
from securemailscope.dissect.tshark import (
    TsharkAdapter, DissectResult, DissectStatus, TsharkNotFound, TsharkVersionError,
)
from securemailscope.dissect.normalize import (
    FrameEvidence, TlsEvidence, MailEvidence,
    normalize, normalize_packet, normalize_stream, summarize,
)

__all__ = [
    "TsharkAdapter", "DissectResult", "DissectStatus",
    "TsharkNotFound", "TsharkVersionError",
    "FrameEvidence", "TlsEvidence", "MailEvidence",
    "normalize", "normalize_packet", "normalize_stream", "summarize",
]
