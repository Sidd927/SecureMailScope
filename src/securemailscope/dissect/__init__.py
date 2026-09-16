"""Dissection layer: safe tshark adapter + normalization (ADR-0001)."""
from securemailscope.dissect.tshark import (
    TsharkAdapter, DissectResult, DissectStatus, TsharkNotFound, TsharkVersionError,
)

__all__ = ["TsharkAdapter", "DissectResult", "DissectStatus",
           "TsharkNotFound", "TsharkVersionError"]
from securemailscope.dissect.normalize import NormalizedFrame, normalize, normalize_packet  # noqa: E402
__all__ += ["NormalizedFrame", "normalize", "normalize_packet"]
