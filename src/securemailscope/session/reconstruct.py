"""
Orchestration: FrameEvidence -> [SessionEvidence].

Chooses a protocol reconstructor per stream from observed evidence, falling back to
port only when the dissector gave no application protocol. Streams with no identifiable
mail protocol are still represented (as transport-only sessions) rather than dropped,
so nothing silently disappears from the evidence record.
"""
from __future__ import annotations

from collections import Counter
from typing import List, Optional, Sequence

from securemailscope.dissect import fields as F
from securemailscope.dissect.normalize import FrameEvidence
from securemailscope.session.grouping import StreamGroup, group_streams
from securemailscope.session.model import (
    AppState, Completeness, SessionEvidence, TlsState,
)
from securemailscope.session.protocols import RECONSTRUCTORS


def _protocol_for(group: StreamGroup) -> Optional[str]:
    """Protocol from the dissector's own identification (majority across frames),
    falling back to the well-known server port."""
    votes = Counter(f.app_protocol for f in group.frames if f.app_protocol)
    if votes:
        return votes.most_common(1)[0][0]
    if group.server_port in F.MAIL_PORTS:
        return F.MAIL_PORTS[group.server_port][0]
    return None


def _transport_only_session(group: StreamGroup, protocol: Optional[str]) -> SessionEvidence:
    """A stream we cannot interpret as mail dialogue is still recorded, with its
    uninterpretable nature made explicit rather than hidden."""
    frames = group.frames
    session = SessionEvidence(
        capture_id=group.capture_id,
        tcp_stream_id=group.tcp_stream_id,
        protocol=protocol,
        client_ip=group.client_ip, client_port=group.client_port,
        server_ip=group.server_ip, server_port=group.server_port,
        endpoint_basis=group.role_basis,
        first_frame=frames[0].frame_number if frames else None,
        last_frame=frames[-1].frame_number if frames else None,
        start_epoch=frames[0].timestamp_epoch if frames else None,
        end_epoch=frames[-1].timestamp_epoch if frames else None,
        packet_count=len(frames),
        transport_flags=group.transport_flags(),
        app_state=AppState.CONNECTED,
        tls_state=TlsState.NONE,
        completeness=Completeness.INCOMPLETE,
    )
    session.notes.append("no mail-protocol dialogue identified in this stream")
    return session


def reconstruct_sessions(frames: Sequence[FrameEvidence],
                         capture_id: str) -> List[SessionEvidence]:
    """Reconstruct every TCP stream in a capture into SessionEvidence."""
    sessions: List[SessionEvidence] = []
    for group in group_streams(list(frames), capture_id):
        protocol = _protocol_for(group)
        reconstructor_cls = RECONSTRUCTORS.get(protocol) if protocol else None
        if reconstructor_cls is None:
            sessions.append(_transport_only_session(group, protocol))
            continue
        sessions.append(reconstructor_cls().reconstruct(group))
    return sessions
