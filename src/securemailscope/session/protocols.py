"""
Protocol-specific reconstructors: SMTP, IMAP, POP3.

Each uses its own grammar. SMTP speaks numeric response codes, IMAP tagged responses
with untagged '*' data lines, POP3 '+OK'/'-ERR' indicators -- so these are genuinely
different parsers behind one interface (Phase-3 §8, §15, §16).

Three tshark behaviours are handled explicitly because they silently break naive matching:
  - SMTP request commands are TRUNCATED TO 4 CHARACTERS ("STARTTLS" -> "STAR"), so we
    match on the full smtp_command_line and treat the truncated field as a fallback.
  - The multi-line SMTP 250 reply arrives as a LIST; the STARTTLS capability is one of
    the later elements, so capability checks must scan all of them (see pick_all).
  - When TCP segmentation splits a multi-line 250 reply MID-LINE, tshark's structured
    output becomes lossy in two distinct ways (OQ-47, docs/research/22): the capability
    token is cut ("STARTTLS" -> "STARTTL", trailing "S" dropped entirely), and a
    continuation segment can be parsed as a bogus new response code. Neither is
    recoverable from the structured fields, so the capability line is re-read from the
    reassembled application payload -- the same remedy already used for POP3 CAPA.
"""
from __future__ import annotations

import re
from typing import List, Optional, Sequence, Tuple

from securemailscope.dissect.normalize import FrameEvidence
from securemailscope.evidence.states import EvidenceField
from securemailscope.session.base import ProtocolSessionReconstructor
from securemailscope.session.grouping import StreamGroup
from securemailscope.session.model import Direction, ProtocolEvent

_AMBIGUOUS_ABSENCE = (
    "capability response observed without the upgrade capability; "
    "genuine non-support and upstream stripping are indistinguishable here"
)


def _event(kind: str, frame: FrameEvidence, group: StreamGroup,
           detail: str = "") -> ProtocolEvent:
    return ProtocolEvent(
        kind=kind,
        direction=group.direction_of(frame),
        frame_number=frame.frame_number,
        timestamp_epoch=frame.timestamp_epoch,
        detail=detail,
        tcp_seq=frame.tcp_seq,
    )


# =========================================================================== SMTP
class SMTPReconstructor(ProtocolSessionReconstructor):
    protocol = "smtp"

    _AUTH_PREFIXES = ("AUTH",)
    _PLAINTEXT_COMMANDS = ("MAIL", "RCPT", "DATA", "VRFY", "EXPN", "NOOP", "RSET")

    @staticmethod
    def _command_text(frame: FrameEvidence) -> Optional[str]:
        """Full command line if available (tshark truncates the command field to 4)."""
        line = frame.mail.smtp_command_line
        if line:
            return line.strip().upper()
        cmd = frame.mail.smtp_command
        return cmd.strip().upper() if cmd else None

    def extract_events(self, group: StreamGroup) -> List[ProtocolEvent]:
        events: List[ProtocolEvent] = []
        for frame in group.frames:
            mail = frame.mail
            code = mail.smtp_response_code
            command = self._command_text(frame)

            if code:
                params = mail.smtp_response_params
                if code.startswith("220") and not any("READY TO START TLS" in p.upper()
                                                      for p in params):
                    events.append(_event("greeting", frame, group, code))
                elif code.startswith("250"):
                    events.append(_event("capability_response", frame, group,
                                         f"250 with {len(params)} parameter(s)"))
                    if any("STARTTLS" in p.upper() for p in params):
                        events.append(_event("starttls_advertised", frame, group,
                                             "STARTTLS present in EHLO capabilities"))
                elif code.startswith("220"):
                    events.append(_event("starttls_accepted", frame, group,
                                         "220 ready to start TLS"))
                elif code[:1] in ("4", "5"):
                    events.append(_event("starttls_rejected", frame, group,
                                         f"{code} response"))

            if command:
                if command.startswith(("EHLO", "HELO")):
                    events.append(_event("capability_request", frame, group,
                                         command.split()[0]))
                elif command.startswith("STARTTLS") or command.startswith("STAR"):
                    events.append(_event("starttls_command", frame, group, "STARTTLS"))
                elif command.startswith(self._AUTH_PREFIXES):
                    events.append(_event("auth_command", frame, group,
                                         "SMTP AUTH command observed"))
                elif command.startswith(self._PLAINTEXT_COMMANDS):
                    events.append(_event("plaintext_command", frame, group,
                                         command.split()[0]))
        return events

    #: A capability line in the EHLO response. Anchored and whole-token: a bare mention
    #: of the word anywhere in a payload must never be read as an advertisement.
    _CAPABILITY_LINE = re.compile(r"^250[- ]STARTTLS\s*$", re.IGNORECASE)

    #: Client commands that end the capability phase. Payload after one of these is
    #: message or authentication traffic and is never scanned for capabilities.
    _PHASE_ENDING = ("STARTTLS", "STAR", "AUTH", "MAIL", "RCPT", "DATA", "QUIT",
                     "BDAT", "VRFY", "EXPN", "NOOP", "RSET")

    def _capability_window(self, group: StreamGroup) -> Tuple[Optional[int], Optional[int]]:
        """Frame range of the EHLO response: from the EHLO itself to the next client
        command. Bounding the scan this tightly is what keeps attacker-controlled
        message content out of it -- DATA cannot occur inside this window."""
        start = end = None
        for frame in group.frames:
            command = self._command_text(frame)
            if command is None:
                continue
            if start is None:
                if command.startswith(("EHLO", "HELO")):
                    start = frame.frame_number
                continue
            if command.startswith(self._PHASE_ENDING):
                end = frame.frame_number
                break
        return start, end

    def _reassembled_advertisement(self, group: StreamGroup) -> List[int]:
        """Frames carrying a STARTTLS capability line in the REASSEMBLED payload.

        tshark's structured parameters lose the capability when a segment boundary falls
        inside the line, so the server->client bytes of the EHLO response are rejoined
        by TCP sequence and the capability line is matched against the result. Returns
        the frames that actually carried the matched bytes, so provenance still points
        at real packets rather than at a synthetic reassembly.
        """
        start, end = self._capability_window(group)
        if start is None:
            return []

        chunks: List[Tuple[int, Optional[int], str]] = []
        seen_seq = set()
        for frame in group.frames:
            number = frame.frame_number
            if number is None or number <= start:
                continue
            if end is not None and number >= end:
                break
            if group.direction_of(frame) is not Direction.SERVER_TO_CLIENT:
                continue
            payload = frame.payload_text
            if not payload:
                continue
            # Retransmissions repeat a sequence number; counting them twice would
            # duplicate capability text and corrupt the offsets.
            if frame.tcp_seq is not None:
                if frame.tcp_seq in seen_seq:
                    continue
                seen_seq.add(frame.tcp_seq)
            chunks.append((number, frame.tcp_seq, payload))

        if not chunks:
            return []
        # Order by sequence where tshark gave one, so out-of-order arrival reassembles
        # correctly; fall back to capture order when it did not.
        if all(seq is not None for _, seq, _ in chunks):
            chunks.sort(key=lambda c: c[1])

        spans: List[Tuple[int, int, int]] = []
        buffer = []
        offset = 0
        for number, _, payload in chunks:
            spans.append((offset, offset + len(payload), number))
            buffer.append(payload)
            offset += len(payload)
        stream = "".join(buffer)

        frames: List[int] = []
        cursor = 0
        for line in stream.splitlines(keepends=True):
            if self._CAPABILITY_LINE.match(line.strip("\r\n")):
                line_start, line_end = cursor, cursor + len(line)
                frames.extend(
                    number for begin, stop, number in spans
                    if begin < line_end and stop > line_start)
            cursor += len(line)
        return sorted(set(frames))

    def advertisement_evidence(self, events: Sequence[ProtocolEvent],
                               group: StreamGroup) -> EvidenceField:
        advertised = [e for e in events if e.kind == "starttls_advertised"]
        if advertised:
            return EvidenceField.observed(
                True, "STARTTLS listed in the EHLO capability response",
                frames=[e.frame_number for e in advertised if e.frame_number])
        # Structured parameters gave nothing. Before concluding absence -- the most
        # consequential judgement this system makes -- check whether tshark simply lost
        # the line to a segment boundary (OQ-47).
        reassembled = self._reassembled_advertisement(group)
        if reassembled:
            return EvidenceField.observed(
                True,
                "STARTTLS capability line recovered from the reassembled EHLO response; "
                "TCP segmentation split the line so tshark's structured parameters "
                "did not carry it",
                frames=reassembled)

        capability = [e for e in events if e.kind == "capability_response"]
        if capability:
            return EvidenceField.ambiguous(
                False, _AMBIGUOUS_ABSENCE,
                frames=[e.frame_number for e in capability if e.frame_number])
        return EvidenceField.unknown("no EHLO capability response observed in this capture")


# =========================================================================== IMAP
class IMAPReconstructor(ProtocolSessionReconstructor):
    protocol = "imap"

    def extract_events(self, group: StreamGroup) -> List[ProtocolEvent]:
        events: List[ProtocolEvent] = []
        for frame in group.frames:
            mail = frame.mail
            lines = [ln.strip() for ln in mail.imap_lines if ln.strip()]
            command = (mail.imap_command or "").strip().upper()

            for line in lines:
                upper = line.upper()
                # Untagged server data line: "* OK ..." / "* CAPABILITY ..."
                if upper.startswith("*"):
                    if "CAPABILITY" in upper and "OK [" not in upper:
                        events.append(_event("capability_response", frame, group,
                                             "untagged CAPABILITY response"))
                        if "STARTTLS" in upper:
                            events.append(_event("starttls_advertised", frame, group,
                                                 "STARTTLS in CAPABILITY list"))
                    else:
                        events.append(_event("greeting", frame, group, "untagged greeting"))

            # Tagged client command: "a002 STARTTLS"
            if command:
                if command == "CAPABILITY":
                    events.append(_event("capability_request", frame, group, "CAPABILITY"))
                elif command == "STARTTLS":
                    events.append(_event("starttls_command", frame, group, "STARTTLS"))
                elif command in ("LOGIN", "AUTHENTICATE"):
                    events.append(_event("auth_command", frame, group,
                                         f"IMAP {command} observed"))
                elif command in ("SELECT", "EXAMINE", "LIST", "FETCH", "LOGOUT"):
                    events.append(_event("plaintext_command", frame, group, command))

            # Tagged server completion for a STARTTLS request: "a002 OK Begin TLS ..."
            status = (mail.imap_response_status or "").strip().upper()
            if status:
                joined = " ".join(lines).upper()
                if "BEGIN TLS" in joined or ("STARTTLS" in joined and status == "OK"):
                    events.append(_event("starttls_accepted", frame, group,
                                         f"tagged {status} for STARTTLS"))
                elif status in ("NO", "BAD") and "STARTTLS" in joined:
                    events.append(_event("starttls_rejected", frame, group,
                                         f"tagged {status} for STARTTLS"))
        return events

    #: A capability line in the EHLO response. Anchored and whole-token: a bare mention
    #: of the word anywhere in a payload must never be read as an advertisement.
    _CAPABILITY_LINE = re.compile(r"^250[- ]STARTTLS\s*$", re.IGNORECASE)

    #: Client commands that end the capability phase. Payload after one of these is
    #: message or authentication traffic and is never scanned for capabilities.
    _PHASE_ENDING = ("STARTTLS", "STAR", "AUTH", "MAIL", "RCPT", "DATA", "QUIT",
                     "BDAT", "VRFY", "EXPN", "NOOP", "RSET")

    def _capability_window(self, group: StreamGroup) -> Tuple[Optional[int], Optional[int]]:
        """Frame range of the EHLO response: from the EHLO itself to the next client
        command. Bounding the scan this tightly is what keeps attacker-controlled
        message content out of it -- DATA cannot occur inside this window."""
        start = end = None
        for frame in group.frames:
            command = self._command_text(frame)
            if command is None:
                continue
            if start is None:
                if command.startswith(("EHLO", "HELO")):
                    start = frame.frame_number
                continue
            if command.startswith(self._PHASE_ENDING):
                end = frame.frame_number
                break
        return start, end

    def _reassembled_advertisement(self, group: StreamGroup) -> List[int]:
        """Frames carrying a STARTTLS capability line in the REASSEMBLED payload.

        tshark's structured parameters lose the capability when a segment boundary falls
        inside the line, so the server->client bytes of the EHLO response are rejoined
        by TCP sequence and the capability line is matched against the result. Returns
        the frames that actually carried the matched bytes, so provenance still points
        at real packets rather than at a synthetic reassembly.
        """
        start, end = self._capability_window(group)
        if start is None:
            return []

        chunks: List[Tuple[int, Optional[int], str]] = []
        seen_seq = set()
        for frame in group.frames:
            number = frame.frame_number
            if number is None or number <= start:
                continue
            if end is not None and number >= end:
                break
            if group.direction_of(frame) is not Direction.SERVER_TO_CLIENT:
                continue
            payload = frame.payload_text
            if not payload:
                continue
            # Retransmissions repeat a sequence number; counting them twice would
            # duplicate capability text and corrupt the offsets.
            if frame.tcp_seq is not None:
                if frame.tcp_seq in seen_seq:
                    continue
                seen_seq.add(frame.tcp_seq)
            chunks.append((number, frame.tcp_seq, payload))

        if not chunks:
            return []
        # Order by sequence where tshark gave one, so out-of-order arrival reassembles
        # correctly; fall back to capture order when it did not.
        if all(seq is not None for _, seq, _ in chunks):
            chunks.sort(key=lambda c: c[1])

        spans: List[Tuple[int, int, int]] = []
        buffer = []
        offset = 0
        for number, _, payload in chunks:
            spans.append((offset, offset + len(payload), number))
            buffer.append(payload)
            offset += len(payload)
        stream = "".join(buffer)

        frames: List[int] = []
        cursor = 0
        for line in stream.splitlines(keepends=True):
            if self._CAPABILITY_LINE.match(line.strip("\r\n")):
                line_start, line_end = cursor, cursor + len(line)
                frames.extend(
                    number for begin, stop, number in spans
                    if begin < line_end and stop > line_start)
            cursor += len(line)
        return sorted(set(frames))

    def advertisement_evidence(self, events: Sequence[ProtocolEvent],
                               group: StreamGroup) -> EvidenceField:
        advertised = [e for e in events if e.kind == "starttls_advertised"]
        if advertised:
            return EvidenceField.observed(
                True, "STARTTLS present in the IMAP CAPABILITY list",
                frames=[e.frame_number for e in advertised if e.frame_number])
        capability = [e for e in events if e.kind == "capability_response"]
        if capability:
            return EvidenceField.ambiguous(
                False, _AMBIGUOUS_ABSENCE,
                frames=[e.frame_number for e in capability if e.frame_number])
        return EvidenceField.unknown("no IMAP CAPABILITY response observed in this capture")


# =========================================================================== POP3
class POP3Reconstructor(ProtocolSessionReconstructor):
    protocol = "pop3"

    def extract_events(self, group: StreamGroup) -> List[ProtocolEvent]:
        events: List[ProtocolEvent] = []
        saw_capa_request = False
        for frame in group.frames:
            mail = frame.mail
            indicator = (mail.pop_response_indicator or "").strip()
            description = (mail.pop_response_description or "").strip()
            command = (mail.pop_command or "").strip().upper()

            if command:
                if command == "CAPA":
                    saw_capa_request = True
                    events.append(_event("capability_request", frame, group, "CAPA"))
                elif command == "STLS":
                    events.append(_event("starttls_command", frame, group, "STLS"))
                elif command in ("USER", "PASS", "APOP"):
                    events.append(_event("auth_command", frame, group,
                                         f"POP3 {command} observed"))
                elif command in ("STAT", "LIST", "RETR", "DELE", "QUIT", "UIDL", "TOP"):
                    events.append(_event("plaintext_command", frame, group, command))

            if indicator:
                upper_desc = description.upper()
                if "BEGIN TLS" in upper_desc:
                    events.append(_event("starttls_accepted", frame, group,
                                         "+OK begin TLS negotiation"))
                elif indicator.startswith("-ERR"):
                    events.append(_event("starttls_rejected", frame, group,
                                         f"-ERR {description[:40]}"))
                elif "CAPABILITY LIST" in upper_desc or saw_capa_request:
                    events.append(_event("capability_response", frame, group,
                                         "+OK capability list"))
                    saw_capa_request = False
                else:
                    events.append(_event("greeting", frame, group, "+OK greeting"))

            # STLS is a capability line inside the CAPA multi-line body. tshark's POP
            # dissector reports that body as empty strings, so the only place the
            # capability actually appears is the reassembled payload.
            payload = frame.payload_text
            if payload:
                for line in payload.splitlines():
                    if line.strip().upper() == "STLS":
                        events.append(_event("starttls_advertised", frame, group,
                                             "STLS line in CAPA body"))
                        break
        return events

    #: A capability line in the EHLO response. Anchored and whole-token: a bare mention
    #: of the word anywhere in a payload must never be read as an advertisement.
    _CAPABILITY_LINE = re.compile(r"^250[- ]STARTTLS\s*$", re.IGNORECASE)

    #: Client commands that end the capability phase. Payload after one of these is
    #: message or authentication traffic and is never scanned for capabilities.
    _PHASE_ENDING = ("STARTTLS", "STAR", "AUTH", "MAIL", "RCPT", "DATA", "QUIT",
                     "BDAT", "VRFY", "EXPN", "NOOP", "RSET")

    def _capability_window(self, group: StreamGroup) -> Tuple[Optional[int], Optional[int]]:
        """Frame range of the EHLO response: from the EHLO itself to the next client
        command. Bounding the scan this tightly is what keeps attacker-controlled
        message content out of it -- DATA cannot occur inside this window."""
        start = end = None
        for frame in group.frames:
            command = self._command_text(frame)
            if command is None:
                continue
            if start is None:
                if command.startswith(("EHLO", "HELO")):
                    start = frame.frame_number
                continue
            if command.startswith(self._PHASE_ENDING):
                end = frame.frame_number
                break
        return start, end

    def _reassembled_advertisement(self, group: StreamGroup) -> List[int]:
        """Frames carrying a STARTTLS capability line in the REASSEMBLED payload.

        tshark's structured parameters lose the capability when a segment boundary falls
        inside the line, so the server->client bytes of the EHLO response are rejoined
        by TCP sequence and the capability line is matched against the result. Returns
        the frames that actually carried the matched bytes, so provenance still points
        at real packets rather than at a synthetic reassembly.
        """
        start, end = self._capability_window(group)
        if start is None:
            return []

        chunks: List[Tuple[int, Optional[int], str]] = []
        seen_seq = set()
        for frame in group.frames:
            number = frame.frame_number
            if number is None or number <= start:
                continue
            if end is not None and number >= end:
                break
            if group.direction_of(frame) is not Direction.SERVER_TO_CLIENT:
                continue
            payload = frame.payload_text
            if not payload:
                continue
            # Retransmissions repeat a sequence number; counting them twice would
            # duplicate capability text and corrupt the offsets.
            if frame.tcp_seq is not None:
                if frame.tcp_seq in seen_seq:
                    continue
                seen_seq.add(frame.tcp_seq)
            chunks.append((number, frame.tcp_seq, payload))

        if not chunks:
            return []
        # Order by sequence where tshark gave one, so out-of-order arrival reassembles
        # correctly; fall back to capture order when it did not.
        if all(seq is not None for _, seq, _ in chunks):
            chunks.sort(key=lambda c: c[1])

        spans: List[Tuple[int, int, int]] = []
        buffer = []
        offset = 0
        for number, _, payload in chunks:
            spans.append((offset, offset + len(payload), number))
            buffer.append(payload)
            offset += len(payload)
        stream = "".join(buffer)

        frames: List[int] = []
        cursor = 0
        for line in stream.splitlines(keepends=True):
            if self._CAPABILITY_LINE.match(line.strip("\r\n")):
                line_start, line_end = cursor, cursor + len(line)
                frames.extend(
                    number for begin, stop, number in spans
                    if begin < line_end and stop > line_start)
            cursor += len(line)
        return sorted(set(frames))

    def advertisement_evidence(self, events: Sequence[ProtocolEvent],
                               group: StreamGroup) -> EvidenceField:
        advertised = [e for e in events if e.kind == "starttls_advertised"]
        if advertised:
            return EvidenceField.observed(
                True, "STLS present in the POP3 CAPA list",
                frames=[e.frame_number for e in advertised if e.frame_number])
        capability = [e for e in events if e.kind == "capability_response"]
        if capability:
            return EvidenceField.ambiguous(
                False, _AMBIGUOUS_ABSENCE,
                frames=[e.frame_number for e in capability if e.frame_number])
        return EvidenceField.unknown("no POP3 CAPA response observed in this capture")


RECONSTRUCTORS = {
    "smtp": SMTPReconstructor,
    "imap": IMAPReconstructor,
    "pop3": POP3Reconstructor,
}
