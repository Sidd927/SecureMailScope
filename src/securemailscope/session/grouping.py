"""
Group normalized frames into TCP streams and determine endpoint roles.

We do NOT rebuild TCP (ADR-0001) -- tshark already did reassembly and assigned
tcp.stream. This layer consumes that identity and orders evidence.

Endpoint roles are decided from observed protocol behaviour (who sent the service
greeting), not from a port comparison (Phase-3 §7). Port is only a fallback, and when
neither is available the role is explicitly UNKNOWN.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from securemailscope.dissect import fields as F
from securemailscope.dissect.normalize import FrameEvidence
from securemailscope.session.model import Direction, TransportRole


@dataclass
class StreamGroup:
    """All frames of one TCP stream, ordered, with resolved endpoint roles."""
    capture_id: str
    tcp_stream_id: Optional[int]
    frames: List[FrameEvidence] = field(default_factory=list)
    server_ip: Optional[str] = None
    server_port: Optional[int] = None
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    role_basis: str = "undetermined"

    @property
    def stream_key(self) -> Optional[str]:
        if self.tcp_stream_id is None:
            return None
        return f"{self.capture_id}:{self.tcp_stream_id}"

    def direction_of(self, frame: FrameEvidence) -> Direction:
        if self.server_ip is None or self.server_port is None:
            return Direction.UNKNOWN
        if frame.src_ip == self.server_ip and frame.src_port == self.server_port:
            return Direction.SERVER_TO_CLIENT
        if frame.dst_ip == self.server_ip and frame.dst_port == self.server_port:
            return Direction.CLIENT_TO_SERVER
        return Direction.UNKNOWN

    def transport_flags(self) -> Tuple[TransportRole, ...]:
        flags = []
        saw_syn = saw_synack = saw_fin = saw_rst = False
        for f in self.frames:
            flag_value = _flags_int(f.tcp_flags)
            if flag_value is None:
                continue
            syn, ack = bool(flag_value & 0x02), bool(flag_value & 0x10)
            if syn and not ack:
                saw_syn = True
            if syn and ack:
                saw_synack = True
            if flag_value & 0x01:
                saw_fin = True
            if flag_value & 0x04:
                saw_rst = True
        if saw_syn and saw_synack:
            flags.append(TransportRole.SETUP_OBSERVED)
        if saw_fin:
            flags.append(TransportRole.TEARDOWN_OBSERVED)
        if saw_rst:
            flags.append(TransportRole.RESET_OBSERVED)
        return tuple(flags)


def _flags_int(raw: Optional[str]) -> Optional[int]:
    if raw is None:
        return None
    try:
        text = raw.strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


#: Frame-level signals that identify the *server* side, by protocol greeting.
def _is_server_greeting(frame: FrameEvidence) -> bool:
    mail = frame.mail
    if mail.smtp_response_code:            # SMTP server speaks first with a 2xx banner
        return True
    if mail.pop_response_indicator:        # POP3 "+OK"/"-ERR" come from the server
        return True
    for line in mail.imap_lines:           # IMAP untagged "* OK ..." greeting
        if line.lstrip().startswith("*"):
            return True
    if mail.imap_response_status:
        return True
    return False


def _resolve_roles(group: StreamGroup) -> None:
    """Prefer protocol evidence; fall back to well-known port; else leave UNKNOWN."""
    # 1. protocol evidence -- whoever sent a service greeting/response is the server
    for frame in group.frames:
        if _is_server_greeting(frame) and frame.src_ip and frame.src_port is not None:
            group.server_ip, group.server_port = frame.src_ip, frame.src_port
            group.client_ip, group.client_port = frame.dst_ip, frame.dst_port
            group.role_basis = "observed service greeting/response"
            return

    # 2. fallback -- a well-known mail port on one side
    for frame in group.frames:
        for ip, port, peer_ip, peer_port in (
            (frame.src_ip, frame.src_port, frame.dst_ip, frame.dst_port),
            (frame.dst_ip, frame.dst_port, frame.src_ip, frame.src_port),
        ):
            if port in F.MAIL_PORTS:
                group.server_ip, group.server_port = ip, port
                group.client_ip, group.client_port = peer_ip, peer_port
                group.role_basis = f"well-known mail port {port} (no greeting observed)"
                return

    group.role_basis = "indeterminate: no greeting and no well-known port"


def group_streams(frames: List[FrameEvidence], capture_id: str) -> List[StreamGroup]:
    """Bucket frames by TCP stream, preserving capture order, then resolve roles.

    Single pass plus one pass per stream -- linear, no O(n^2) scan (Phase-3 §35).
    """
    buckets: Dict[Optional[int], StreamGroup] = {}
    order: List[Optional[int]] = []
    for frame in frames:
        sid = frame.tcp_stream_id
        if sid not in buckets:
            buckets[sid] = StreamGroup(capture_id=capture_id, tcp_stream_id=sid)
            order.append(sid)
        buckets[sid].frames.append(frame)

    groups = []
    for sid in order:
        group = buckets[sid]
        # Frames arrive in capture order. Order is stable; we do not re-sort by seq
        # because tshark has already resolved reassembly and per-direction ordering,
        # and re-sorting a bidirectional stream by seq would interleave incorrectly.
        _resolve_roles(group)
        groups.append(group)
    return groups
