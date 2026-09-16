"""
Normalize tshark -T ek records into typed NormalizedFrame objects.

This is the boundary that isolates the rest of the system from tshark's field naming
(ADR-0001): if tshark output changes, only this module changes. Phase 1 extracts the
minimal frame-level facts the session layer (Phase 3) will build on; it deliberately
does NOT reconstruct sessions or make security judgements yet.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class NormalizedFrame:
    frame_number: Optional[int]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    transport: Optional[str]       # "tcp" | "udp" | None
    tcp_seq: Optional[int]
    tcp_flags: Optional[str]
    has_payload: bool


def _flatten(layers: dict) -> dict:
    """tshark -T ek nests fields one level under each protocol (layers.tcp.tcp_tcp_srcport).
    Flatten to a single field->value map so lookups are uniform and version-tolerant."""
    flat: dict = {}
    for v in layers.values():
        if isinstance(v, dict):
            flat.update(v)
    # also keep any already-top-level scalar fields (older tshark layouts)
    flat.update({k: v for k, v in layers.items() if not isinstance(v, dict)})
    return flat


def _first(layers: dict, *keys: str) -> Optional[str]:
    """Look up the first present field. Values may be scalars or single-element lists."""
    for k in keys:
        if k in layers:
            v = layers[k]
            if isinstance(v, list):
                return str(v[0]) if v else None
            return str(v)
    return None


def _int(val: Optional[str]) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val, 0) if val.lower().startswith("0x") else int(val)
    except (ValueError, AttributeError):
        return None


def normalize_packet(record: dict) -> NormalizedFrame:
    raw = record.get("layers", {}) or {}
    layers = _flatten(raw)
    transport = "tcp" if any(k.startswith("tcp_") for k in layers) else (
        "udp" if any(k.startswith("udp_") for k in layers) else None)
    return NormalizedFrame(
        frame_number=_int(_first(layers, "frame_frame_number")),
        src_ip=_first(layers, "ip_ip_src"),
        dst_ip=_first(layers, "ip_ip_dst"),
        src_port=_int(_first(layers, "tcp_tcp_srcport", "udp_udp_srcport")),
        dst_port=_int(_first(layers, "tcp_tcp_dstport", "udp_udp_dstport")),
        transport=transport,
        tcp_seq=_int(_first(layers, "tcp_tcp_seq")),
        tcp_flags=_first(layers, "tcp_tcp_flags"),
        has_payload=any(k in layers for k in ("tcp_tcp_payload", "data_data_data")),
    )


def normalize(records: Iterable[dict]) -> List[NormalizedFrame]:
    return [normalize_packet(r) for r in records]
