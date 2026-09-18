"""
Common reconstruction machinery shared by the three protocol state machines.

Each protocol has genuinely different grammar (SMTP response codes vs IMAP tagged
responses vs POP3 +OK/-ERR), so the state machines are separate implementations behind
one interface producing one SessionEvidence contract (Phase-3 §28).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Sequence, Set, Tuple

from securemailscope.dissect import fields as F
from securemailscope.dissect.normalize import FrameEvidence
from securemailscope.evidence.states import EvidenceField, EvidenceState
from securemailscope.session.grouping import StreamGroup
from securemailscope.session.model import (
    AppState, Completeness, Direction, ProtocolEvent, SessionEvidence,
    TlsState, TransportRole, Transition,
)


class ProtocolSessionReconstructor(ABC):
    """Reconstructs one TCP stream into SessionEvidence."""

    protocol: str = ""

    # ---- required per-protocol behaviour ----------------------------------
    @abstractmethod
    def extract_events(self, group: StreamGroup) -> List[ProtocolEvent]:
        """Turn frames into ordered, de-duplicated application events."""

    @abstractmethod
    def advertisement_evidence(
        self, events: Sequence[ProtocolEvent], group: StreamGroup
    ) -> EvidenceField:
        """Was STARTTLS/STLS advertised? Must return AMBIGUOUS (never False) when a
        capability reply was observed without it -- stripping and genuine non-support
        are indistinguishable at this layer (docs/research/02B §3.1)."""

    # ---- shared pipeline ---------------------------------------------------
    def reconstruct(self, group: StreamGroup) -> SessionEvidence:
        session = self._base_session(group)

        if session.implicit_tls:
            # Implicit TLS is a distinct behaviour, NOT a STARTTLS upgrade (§17).
            self._apply_implicit_tls(session, group)
            self._finalise(session, group)
            return session

        events = dedupe(self.extract_events(group))
        session.events = events

        self._walk(session, events, group)
        self._apply_tls(session, group, explicit_upgrade=True)
        self._finalise(session, group)
        return session

    # ---- construction ------------------------------------------------------
    def _base_session(self, group: StreamGroup) -> SessionEvidence:
        frames = group.frames
        implicit = any(f.implicit_tls_port for f in frames)
        return SessionEvidence(
            capture_id=group.capture_id,
            tcp_stream_id=group.tcp_stream_id,
            protocol=self.protocol,
            client_ip=group.client_ip, client_port=group.client_port,
            server_ip=group.server_ip, server_port=group.server_port,
            endpoint_basis=group.role_basis,
            first_frame=frames[0].frame_number if frames else None,
            last_frame=frames[-1].frame_number if frames else None,
            start_epoch=frames[0].timestamp_epoch if frames else None,
            end_epoch=frames[-1].timestamp_epoch if frames else None,
            packet_count=len(frames),
            transport_flags=group.transport_flags(),
            implicit_tls=implicit,
        )

    # ---- state walk --------------------------------------------------------
    def _walk(self, session: SessionEvidence, events: Sequence[ProtocolEvent],
              group: StreamGroup) -> None:
        """Drive the state machine. Every transition records its causing frames."""
        for event in events:
            handler = _EVENT_TRANSITIONS.get(event.kind)
            if handler is None:
                continue
            to_state = handler(session.app_state)
            if to_state is None:
                # Event is not valid from the current state (e.g. STARTTLS after TLS).
                session.notes.append(
                    f"ignored out-of-order event {event.kind} in state {session.app_state.value}"
                    f" (frame {event.frame_number})")
                continue
            session.record(Transition(
                from_state=session.app_state,
                event=event.kind,
                to_state=to_state,
                evidence_frames=(event.frame_number,) if event.frame_number else (),
                evidence_state=EvidenceState.OBSERVED,
                timestamp_epoch=event.timestamp_epoch,
                basis=event.detail or event.kind,
            ))

        session.starttls_advertised = self.advertisement_evidence(events, group)
        session.starttls_requested = _bool_evidence(
            events, "starttls_command",
            yes="client sent the upgrade command",
            no="no upgrade command observed from the client")
        session.starttls_accepted = _acceptance_evidence(events)
        session.auth_activity = _bool_evidence(
            events, "auth_command",
            yes="authentication-related command observed",
            no="no authentication command observed")

    # ---- TLS ---------------------------------------------------------------
    def _apply_tls(self, session: SessionEvidence, group: StreamGroup,
                   explicit_upgrade: bool) -> None:
        tls_state, frames_seen = classify_tls(group)
        session.tls_state = tls_state
        session.tls_negotiated_version = negotiated_version(group)
        session.tls_cipher_suite = negotiated_cipher(group)

        if tls_state is TlsState.NONE:
            session.tls_transition = EvidenceField.observed(
                False, "no TLS records in this stream", frames=[])
        elif tls_state is TlsState.ESTABLISHED:
            session.tls_transition = EvidenceField.observed(
                True, "ClientHello, ServerHello and encrypted application data observed",
                frames=frames_seen)
            session.record(Transition(
                from_state=session.app_state, event="tls_established",
                to_state=AppState.TLS_ESTABLISHED,
                evidence_frames=tuple(frames_seen),
                evidence_state=EvidenceState.OBSERVED,
                basis="handshake plus application data"))
        else:
            # Negotiation began but completion is not evidenced. Do not claim success.
            session.tls_transition = EvidenceField.ambiguous(
                None, f"TLS negotiation observed but completion unproven ({tls_state.value})",
                frames=frames_seen)
            if session.app_state is not AppState.TLS_ESTABLISHED:
                session.record(Transition(
                    from_state=session.app_state, event="tls_negotiation_observed",
                    to_state=AppState.TLS_NEGOTIATING,
                    evidence_frames=tuple(frames_seen),
                    evidence_state=EvidenceState.OBSERVED,
                    basis=tls_state.value))

        # plaintext continuation: cleartext protocol events after the upgrade point
        session.plaintext_continuation = _plaintext_after_upgrade(session, group)

    def _apply_implicit_tls(self, session: SessionEvidence, group: StreamGroup) -> None:
        tls_state, frames_seen = classify_tls(group)
        session.tls_state = tls_state
        session.tls_negotiated_version = negotiated_version(group)
        session.tls_cipher_suite = negotiated_cipher(group)
        session.app_state = AppState.IMPLICIT_TLS
        na = "not applicable: implicit TLS carries no cleartext STARTTLS dialogue"
        session.starttls_advertised = EvidenceField.not_observable(na)
        session.starttls_requested = EvidenceField.not_observable(na)
        session.starttls_accepted = EvidenceField.not_observable(na)
        session.plaintext_continuation = EvidenceField.observed(
            False, "session is encrypted from the first record")
        session.auth_activity = EvidenceField.not_observable(
            "authentication occurs inside TLS and is not passively observable")
        session.tls_transition = (
            EvidenceField.observed(True, "implicit TLS: session encrypted from the start",
                                   frames=frames_seen)
            if tls_state is TlsState.ESTABLISHED else
            EvidenceField.ambiguous(None,
                                    f"implicit TLS but completion unproven ({tls_state.value})",
                                    frames=frames_seen))
        session.record(Transition(
            from_state=AppState.CONNECTED, event="implicit_tls",
            to_state=AppState.IMPLICIT_TLS,
            evidence_frames=tuple(frames_seen),
            evidence_state=EvidenceState.OBSERVED,
            basis="connection opened on an implicit-TLS port with TLS records"))

    # ---- completeness ------------------------------------------------------
    def _finalise(self, session: SessionEvidence, group: StreamGroup) -> None:
        flags = session.transport_flags
        setup = TransportRole.SETUP_OBSERVED in flags
        closed = (TransportRole.TEARDOWN_OBSERVED in flags
                  or TransportRole.RESET_OBSERVED in flags)
        if setup and closed:
            session.completeness = Completeness.COMPLETE
            # A closed stream is recorded, but we never manufacture a *successful*
            # final state for a truncated capture (§33).
            if session.app_state not in (AppState.TLS_ESTABLISHED, AppState.IMPLICIT_TLS):
                session.record(Transition(
                    from_state=session.app_state, event="connection_closed",
                    to_state=AppState.CLOSED,
                    evidence_frames=(session.last_frame,) if session.last_frame else (),
                    evidence_state=EvidenceState.OBSERVED,
                    basis="FIN/RST observed"))
        else:
            session.completeness = Completeness.INCOMPLETE
            session.notes.append(
                "session boundaries incomplete: "
                f"setup={'yes' if setup else 'no'} teardown={'yes' if closed else 'no'}")


# --------------------------------------------------------------------------- helpers
#: Valid transitions per event kind, expressed as from-state -> to-state.
#: Returning None means "not valid here" and the event is ignored with a note.
def _t(mapping):
    def handler(current: AppState) -> Optional[AppState]:
        return mapping.get(current)
    return handler


_EVENT_TRANSITIONS = {
    "greeting": _t({AppState.CONNECTED: AppState.GREETING_OBSERVED}),
    "capability_request": _t({
        AppState.CONNECTED: AppState.CAPABILITY_REQUESTED,
        AppState.GREETING_OBSERVED: AppState.CAPABILITY_REQUESTED,
    }),
    "capability_response": _t({
        AppState.CAPABILITY_REQUESTED: AppState.CAPABILITY_OBSERVED,
        AppState.GREETING_OBSERVED: AppState.CAPABILITY_OBSERVED,
    }),
    "starttls_advertised": _t({AppState.CAPABILITY_OBSERVED: AppState.STARTTLS_ADVERTISED}),
    "starttls_command": _t({
        AppState.STARTTLS_ADVERTISED: AppState.STARTTLS_REQUESTED,
        AppState.CAPABILITY_OBSERVED: AppState.STARTTLS_REQUESTED,
        AppState.GREETING_OBSERVED: AppState.STARTTLS_REQUESTED,
    }),
    "starttls_accepted": _t({AppState.STARTTLS_REQUESTED: AppState.STARTTLS_ACCEPTED}),
    "starttls_rejected": _t({AppState.STARTTLS_REQUESTED: AppState.STARTTLS_REJECTED}),
    "plaintext_command": _t({
        AppState.CAPABILITY_OBSERVED: AppState.PLAINTEXT_CONTINUATION,
        AppState.STARTTLS_ADVERTISED: AppState.PLAINTEXT_CONTINUATION,
        AppState.STARTTLS_REJECTED: AppState.PLAINTEXT_CONTINUATION,
        AppState.GREETING_OBSERVED: AppState.PLAINTEXT_CONTINUATION,
    }),
    "auth_command": _t({
        AppState.CAPABILITY_OBSERVED: AppState.PLAINTEXT_CONTINUATION,
        AppState.STARTTLS_ADVERTISED: AppState.PLAINTEXT_CONTINUATION,
        AppState.STARTTLS_REJECTED: AppState.PLAINTEXT_CONTINUATION,
        AppState.GREETING_OBSERVED: AppState.PLAINTEXT_CONTINUATION,
        AppState.PLAINTEXT_CONTINUATION: AppState.PLAINTEXT_CONTINUATION,
    }),
}


def dedupe(events: Sequence[ProtocolEvent]) -> List[ProtocolEvent]:
    """Collapse retransmissions: identical event on the same sequence number (§22)."""
    seen: Set[Tuple] = set()
    result: List[ProtocolEvent] = []
    for event in events:
        key = event.dedupe_key
        if key in seen:
            continue
        seen.add(key)
        result.append(event)
    return result


#: TLS version wire values -> canonical names (RFC 8446 / RFC 5246 etc.).
TLS_VERSIONS = {
    0x0200: "SSL2.0", 0x0300: "SSL3.0",
    0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3",
}


def _version_name(raw) -> Optional[str]:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return TLS_VERSIONS.get(value)


def negotiated_version(group: StreamGroup) -> EvidenceField:
    """Resolve the negotiated TLS version from the ServerHello ONLY.

    Order matters: supported_versions is authoritative when present because TLS 1.3
    pins legacy_version to 0x0303. Reading handshake/record version first would
    misreport every TLS 1.3 session as TLS 1.2 (doc 01A; RFC 8446 4.1.3/4.2.1).
    """
    for frame in group.frames:
        tls = frame.tls
        if tls.handshake_type != 2:      # ServerHello only; ClientHello is an offer
            continue
        frames = [frame.frame_number] if frame.frame_number else []
        name = _version_name(tls.supported_version)
        if name:
            return EvidenceField.observed(
                name, "ServerHello supported_versions extension (authoritative for TLS 1.3)",
                frames=frames)
        name = _version_name(tls.handshake_version)
        if name:
            return EvidenceField.observed(
                name, "ServerHello handshake version (no supported_versions extension)",
                frames=frames)
        return EvidenceField.ambiguous(
            None, f"ServerHello observed but version value unrecognised "
                  f"(supported={tls.supported_version!r}, handshake={tls.handshake_version!r})",
            frames=frames)
    return EvidenceField.unknown(
        "no ServerHello observed; the negotiated version cannot be established")


def negotiated_cipher(group: StreamGroup) -> EvidenceField:
    """Cipher suite selected by the server, from the ServerHello."""
    for frame in group.frames:
        if frame.tls.handshake_type != 2:
            continue
        frames = [frame.frame_number] if frame.frame_number else []
        raw = frame.tls.cipher_suite
        if raw is None:
            return EvidenceField.unknown("ServerHello observed without a cipher suite value")
        try:
            return EvidenceField.observed(
                f"0x{int(raw):04x}", "cipher suite selected in ServerHello", frames=frames)
        except (TypeError, ValueError):
            return EvidenceField.ambiguous(
                None, f"unrecognised cipher suite value {raw!r}", frames=frames)
    return EvidenceField.unknown("no ServerHello observed")


def classify_tls(group: StreamGroup) -> Tuple[TlsState, List[int]]:
    """Derive TLS state from this stream's own records only (§18)."""
    client_hello = server_hello = app_data = False
    frames: List[int] = []
    for frame in group.frames:
        tls = frame.tls
        if not tls.present:
            continue
        if frame.frame_number is not None:
            frames.append(frame.frame_number)
        if tls.handshake_type == 1:
            client_hello = True
        elif tls.handshake_type == 2:
            server_hello = True
        if tls.has_app_data:
            app_data = True

    if not frames:
        return TlsState.NONE, []
    if client_hello and server_hello and app_data:
        return TlsState.ESTABLISHED, frames
    if client_hello and server_hello:
        return TlsState.SERVER_HELLO_OBSERVED, frames
    if client_hello:
        return TlsState.CLIENT_HELLO_OBSERVED, frames
    return TlsState.HANDSHAKE_INTERRUPTED, frames


def _bool_evidence(events: Sequence[ProtocolEvent], kind: str, *, yes: str,
                   no: str) -> EvidenceField:
    hits = [e for e in events if e.kind == kind]
    if hits:
        return EvidenceField.observed(
            True, yes, frames=[e.frame_number for e in hits if e.frame_number])
    return EvidenceField.observed(False, no)


def _acceptance_evidence(events: Sequence[ProtocolEvent]) -> EvidenceField:
    accepted = [e for e in events if e.kind == "starttls_accepted"]
    rejected = [e for e in events if e.kind == "starttls_rejected"]
    requested = [e for e in events if e.kind == "starttls_command"]
    if accepted and rejected:
        # Contradictory server behaviour (both a rejection and an acceptance for the
        # same upgrade). Preferring either one would be a fabricated reading; the
        # honest answer is that the capture does not settle it.
        return EvidenceField.ambiguous(
            None,
            "contradictory server responses: both rejection and acceptance observed "
            "for the upgrade request",
            frames=[e.frame_number for e in accepted + rejected if e.frame_number])
    if accepted:
        return EvidenceField.observed(
            True, "server accepted the upgrade",
            frames=[e.frame_number for e in accepted if e.frame_number])
    if rejected:
        return EvidenceField.observed(
            False, "server rejected the upgrade command",
            frames=[e.frame_number for e in rejected if e.frame_number])
    if requested:
        return EvidenceField.unknown(
            "upgrade command observed but no server response captured")
    return EvidenceField.unknown("no upgrade command observed")


def _plaintext_after_upgrade(session: SessionEvidence,
                             group: StreamGroup) -> EvidenceField:
    """Cleartext protocol events occurring after the upgrade point, if any."""
    upgrade_frames = [t.evidence_frames[0] for t in session.transitions
                      if t.event in ("starttls_accepted", "tls_established")
                      and t.evidence_frames]
    if not upgrade_frames:
        cleartext = [e for e in session.events
                     if e.kind in ("plaintext_command", "auth_command")]
        if cleartext:
            return EvidenceField.observed(
                True, "cleartext protocol activity observed and no upgrade occurred",
                frames=[e.frame_number for e in cleartext if e.frame_number])
        return EvidenceField.observed(False, "no cleartext activity after dialogue start")

    boundary = min(upgrade_frames)
    after = [e for e in session.events
             if e.frame_number and e.frame_number > boundary
             and e.kind in ("plaintext_command", "auth_command", "capability_response")]
    if after:
        return EvidenceField.observed(
            True, "cleartext protocol activity observed after the upgrade point",
            frames=[e.frame_number for e in after if e.frame_number])
    return EvidenceField.observed(False, "no cleartext activity after the upgrade point")
