"""
Canonical session model: what the capture shows happened.

Phase 3 reconstructs *behaviour*, never *intent*. Nothing in this module may express
a security verdict (no severity, no "attack", no "downgrade"). Those belong to Phase 4
and must be derived from this evidence, not smuggled into it.

The hardest semantics, established experimentally in docs/research/02B:
  - An absent STARTTLS advertisement is AMBIGUOUS, never False. Stripping and genuine
    non-support are byte-identical at the application layer (02B §3.1).
  - Implicit TLS is NOT a STARTTLS upgrade; it is a different protocol behaviour.
  - A ClientHello (or even ClientHello+ServerHello) is not proof of an established
    session; completion needs stronger evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from securemailscope.evidence.states import EvidenceField, EvidenceState


class Direction(str, Enum):
    CLIENT_TO_SERVER = "CLIENT_TO_SERVER"
    SERVER_TO_CLIENT = "SERVER_TO_CLIENT"
    UNKNOWN = "UNKNOWN"


class AppState(str, Enum):
    """Application-layer dialogue state. Observation, not judgement."""
    CONNECTED = "CONNECTED"
    GREETING_OBSERVED = "GREETING_OBSERVED"
    CAPABILITY_REQUESTED = "CAPABILITY_REQUESTED"
    CAPABILITY_OBSERVED = "CAPABILITY_OBSERVED"
    STARTTLS_ADVERTISED = "STARTTLS_ADVERTISED"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    STARTTLS_ACCEPTED = "STARTTLS_ACCEPTED"
    STARTTLS_REJECTED = "STARTTLS_REJECTED"
    TLS_NEGOTIATING = "TLS_NEGOTIATING"
    TLS_ESTABLISHED = "TLS_ESTABLISHED"
    PLAINTEXT_CONTINUATION = "PLAINTEXT_CONTINUATION"
    IMPLICIT_TLS = "IMPLICIT_TLS"
    CLOSED = "CLOSED"
    INCOMPLETE = "INCOMPLETE"


class TlsState(str, Enum):
    """TLS evidence state.

    Completion semantics (Phase-3 §19), chosen to avoid over-claiming:
      NONE                   no TLS records in this stream
      CLIENT_HELLO_OBSERVED  a ClientHello only -- negotiation began
      SERVER_HELLO_OBSERVED  both hellos -- negotiation progressed, completion unproven
      ESTABLISHED            both hellos AND encrypted application data observed. This is
                             the strongest completion evidence available passively: the
                             Finished messages are themselves encrypted, so application
                             records flowing is what demonstrates the handshake completed.
      HANDSHAKE_INTERRUPTED  negotiation began then the stream ended/alerted without data
    """
    NONE = "NONE"
    CLIENT_HELLO_OBSERVED = "CLIENT_HELLO_OBSERVED"
    SERVER_HELLO_OBSERVED = "SERVER_HELLO_OBSERVED"
    ESTABLISHED = "ESTABLISHED"
    HANDSHAKE_INTERRUPTED = "HANDSHAKE_INTERRUPTED"


class Completeness(str, Enum):
    """Whether the capture shows the whole session. Independent of security."""
    COMPLETE = "COMPLETE"        # setup, dialogue and teardown all observed
    INCOMPLETE = "INCOMPLETE"    # some boundary missing (e.g. no teardown)
    TRUNCATED = "TRUNCATED"      # capture cut short mid-session


class TransportRole(str, Enum):
    SETUP_OBSERVED = "SETUP_OBSERVED"
    TEARDOWN_OBSERVED = "TEARDOWN_OBSERVED"
    RESET_OBSERVED = "RESET_OBSERVED"


@dataclass(frozen=True)
class ProtocolEvent:
    """One observed application-layer event, with provenance."""
    kind: str                       # e.g. "greeting", "capability_response", "starttls_command"
    direction: Direction
    frame_number: Optional[int]
    timestamp_epoch: Optional[float]
    detail: str = ""
    tcp_seq: Optional[int] = None   # used to collapse retransmissions

    @property
    def dedupe_key(self) -> Tuple:
        """Retransmitted segments repeat the same sequence number; collapsing on it
        prevents one command being counted twice (Phase-3 §22)."""
        return (self.kind, self.direction, self.tcp_seq, self.detail)


@dataclass(frozen=True)
class Transition:
    """An auditable state change. Every transition names the frames that caused it."""
    from_state: AppState
    event: str
    to_state: AppState
    evidence_frames: Tuple[int, ...]
    evidence_state: EvidenceState
    timestamp_epoch: Optional[float] = None
    basis: str = ""

    def to_dict(self) -> dict:
        return {
            "from_state": self.from_state.value,
            "event": self.event,
            "to_state": self.to_state.value,
            "evidence_frames": list(self.evidence_frames),
            "evidence_state": self.evidence_state.value,
            "timestamp_epoch": self.timestamp_epoch,
            "basis": self.basis,
        }


@dataclass
class SessionEvidence:
    """Reconstructed protocol session. The Phase-4 input contract."""

    # identity
    capture_id: str
    tcp_stream_id: Optional[int]
    protocol: Optional[str]                 # smtp | imap | pop3 | None

    # endpoints
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    server_ip: Optional[str] = None
    server_port: Optional[int] = None
    endpoint_basis: str = ""                # how client/server roles were determined

    # timing
    first_frame: Optional[int] = None
    last_frame: Optional[int] = None
    start_epoch: Optional[float] = None
    end_epoch: Optional[float] = None
    packet_count: int = 0

    # transport / completeness
    transport_flags: Tuple[TransportRole, ...] = ()
    completeness: Completeness = Completeness.INCOMPLETE

    # state
    app_state: AppState = AppState.CONNECTED
    tls_state: TlsState = TlsState.NONE
    implicit_tls: bool = False

    # ---- the load-bearing evidence fields (all EvidenceField, never bare bools) ----
    #: Was STARTTLS/STLS advertised? AMBIGUOUS when the capability reply was seen but
    #: lacked it -- stripped and unsupported are indistinguishable here.
    starttls_advertised: EvidenceField = field(
        default_factory=lambda: EvidenceField.unknown("no capability response observed"))
    starttls_requested: EvidenceField = field(
        default_factory=lambda: EvidenceField.unknown("no client command observed"))
    starttls_accepted: EvidenceField = field(
        default_factory=lambda: EvidenceField.unknown("no server response observed"))
    tls_transition: EvidenceField = field(
        default_factory=lambda: EvidenceField.unknown("no TLS evidence in this stream"))
    #: Negotiated TLS version, taken from the ServerHello. For TLS 1.3 the authoritative
    #: value is the supported_versions extension -- legacy_version/record_version are
    #: pinned to 0x0303 and would misreport TLS 1.3 as TLS 1.2 (RFC 8446 4.1.3, doc 01A).
    tls_negotiated_version: EvidenceField = field(
        default_factory=lambda: EvidenceField.unknown("no ServerHello observed"))
    tls_cipher_suite: EvidenceField = field(
        default_factory=lambda: EvidenceField.unknown("no ServerHello observed"))
    plaintext_continuation: EvidenceField = field(
        default_factory=lambda: EvidenceField.unknown("insufficient dialogue observed"))
    auth_activity: EvidenceField = field(
        default_factory=lambda: EvidenceField.unknown("no authentication commands observed"))

    # audit trail
    events: List[ProtocolEvent] = field(default_factory=list)
    transitions: List[Transition] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def stream_key(self) -> Optional[str]:
        if self.tcp_stream_id is None:
            return None
        return f"{self.capture_id}:{self.tcp_stream_id}"

    def record(self, transition: Transition) -> None:
        self.transitions.append(transition)
        self.app_state = transition.to_state

    def to_dict(self) -> dict:
        return {
            "stream_key": self.stream_key,
            "capture_id": self.capture_id,
            "tcp_stream_id": self.tcp_stream_id,
            "protocol": self.protocol,
            "client": {"ip": self.client_ip, "port": self.client_port},
            "server": {"ip": self.server_ip, "port": self.server_port},
            "endpoint_basis": self.endpoint_basis,
            "timing": {
                "first_frame": self.first_frame, "last_frame": self.last_frame,
                "start_epoch": self.start_epoch, "end_epoch": self.end_epoch,
                "packet_count": self.packet_count,
            },
            "transport_flags": [t.value for t in self.transport_flags],
            "completeness": self.completeness.value,
            "app_state": self.app_state.value,
            "tls_state": self.tls_state.value,
            "implicit_tls": self.implicit_tls,
            "evidence": {
                "starttls_advertised": self.starttls_advertised.to_dict(),
                "starttls_requested": self.starttls_requested.to_dict(),
                "starttls_accepted": self.starttls_accepted.to_dict(),
                "tls_transition": self.tls_transition.to_dict(),
                "tls_negotiated_version": self.tls_negotiated_version.to_dict(),
                "tls_cipher_suite": self.tls_cipher_suite.to_dict(),
                "plaintext_continuation": self.plaintext_continuation.to_dict(),
                "auth_activity": self.auth_activity.to_dict(),
            },
            "transitions": [t.to_dict() for t in self.transitions],
            "events": [
                {"kind": e.kind, "direction": e.direction.value,
                 "frame": e.frame_number, "detail": e.detail}
                for e in self.events
            ],
            "notes": list(self.notes),
        }
