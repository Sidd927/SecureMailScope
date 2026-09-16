"""
Normalize tshark records into canonical FrameEvidence.

This is the boundary isolating the rest of the system from tshark's schema
(ADR-0001 / Phase-2 §17). Downstream code never sees a tshark field name.

SCOPE: observations only. This layer records *what was seen* (protocol present,
TLS handshake type, cipher suite bytes, ...). It makes NO security judgement --
"SMTP observed" is evidence; "SMTP is insecure" is not produced here (Phase-2 §18).
Missing fields are represented explicitly, never fabricated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

#: Cap on decoded cleartext payload retained per frame. Untrusted input: we bound it
#: to avoid unbounded memory and never treat it as anything but data.
PAYLOAD_TEXT_LIMIT = 4096

_TZ_Z = re.compile(r"Z$")
#: keep at most 6 fractional digits (microseconds), drop the rest
_FRACTION = re.compile(r"(\.\d{6})\d+")

from securemailscope.dissect import fields as F


# --------------------------------------------------------------------------- helpers
def flatten_layers(layers: dict) -> dict:
    """tshark -T ek nests fields under each protocol layer; flatten for uniform lookup.
    Tolerates both nested (4.6.x) and flat layouts."""
    flat: dict = {}
    for value in layers.values():
        if isinstance(value, dict):
            flat.update(value)
    flat.update({k: v for k, v in layers.items() if not isinstance(v, dict)})
    return flat


def pick(flat: dict, names: Tuple[str, ...]) -> Optional[str]:
    """First present field from `names`. Values may be scalars or single-element lists."""
    for name in names:
        if name in flat:
            value = flat[name]
            if isinstance(value, list):
                return str(value[0]) if value else None
            return str(value)
    return None


def pick_all(flat: dict, names: Tuple[str, ...]) -> Tuple[str, ...]:
    """ALL values of the first present field. tshark emits multi-line protocol
    responses as a list -- e.g. the SMTP 250 capability reply is
    ['mail.example.org', 'PIPELINING', 'STARTTLS', ...]. Taking only the first
    element would silently lose the capability lines, so callers that care about
    capabilities must use this rather than pick()."""
    for name in names:
        if name in flat:
            value = flat[name]
            if isinstance(value, list):
                return tuple(str(v) for v in value)
            return (str(value),)
    return ()


def decode_payload(raw: Optional[str], limit: int = PAYLOAD_TEXT_LIMIT) -> Optional[str]:
    """Decode tshark's colon-separated hex tcp.payload to text, bounded.

    Needed because some dissectors expose structure but not content -- notably the POP3
    CAPA body, which tshark reports as empty strings while the capability lines (incl.
    STLS) exist only in the raw payload. We are consuming bytes tshark already
    reassembled, not rebuilding TCP.

    SECURITY: the result is attacker-controlled DATA. It is only ever pattern-matched
    for protocol tokens, never executed, rendered unescaped, or used as instructions.
    """
    if not raw:
        return None
    hexdigits = raw.replace(":", "").strip()
    if not hexdigits:
        return None
    try:
        data = bytes.fromhex(hexdigits[: limit * 2])
    except ValueError:
        return None
    return data.decode("utf-8", errors="replace")


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        text = value.strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (ValueError, AttributeError):
        return None


def _to_float(value: Optional[str]) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def _to_epoch(value: Optional[str]) -> Optional[float]:
    """tshark -T ek renders frame.time_epoch as ISO-8601
    ("1970-01-01T00:00:00.000000000Z"), not a float -- an EK-specific formatting quirk.
    Accept both forms. Return None rather than fabricate a timestamp if neither parses.
    """
    if value is None:
        return None
    numeric = _to_float(value)
    if numeric is not None:
        return numeric
    text = value.strip()
    text = _TZ_Z.sub("+00:00", text)
    # datetime.fromisoformat (py3.9) rejects nanosecond precision; trim to microseconds.
    text = _FRACTION.sub(lambda m: m.group(1), text)
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


# --------------------------------------------------------------------------- model
@dataclass(frozen=True)
class TlsEvidence:
    """Raw TLS observations. No interpretation (Phase-2 §20)."""
    record_version: Optional[str] = None
    handshake_type: Optional[int] = None
    handshake_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    sni: Optional[str] = None
    supported_version: Optional[str] = None
    session_id: Optional[str] = None
    has_app_data: bool = False

    @property
    def present(self) -> bool:
        return any((self.record_version, self.handshake_type is not None,
                    self.cipher_suite, self.sni, self.has_app_data))


@dataclass(frozen=True)
class MailEvidence:
    """Raw cleartext mail-protocol observations. No interpretation."""
    smtp_command: Optional[str] = None          # NOTE: tshark truncates to 4 chars ("STAR")
    smtp_command_line: Optional[str] = None     # full line -- prefer this for matching
    smtp_response_code: Optional[str] = None
    smtp_response_params: Tuple[str, ...] = ()  # multi-line 250 reply, all elements
    imap_command: Optional[str] = None
    imap_response_status: Optional[str] = None
    imap_lines: Tuple[str, ...] = ()
    pop_command: Optional[str] = None
    pop_response_indicator: Optional[str] = None
    pop_response_description: Optional[str] = None

    @property
    def smtp_response_param(self) -> Optional[str]:
        """First parameter, for display. Use smtp_response_params for capabilities."""
        return self.smtp_response_params[0] if self.smtp_response_params else None

    @property
    def imap_line(self) -> Optional[str]:
        return self.imap_lines[0] if self.imap_lines else None


@dataclass(frozen=True)
class FrameEvidence:
    """One packet's normalized observations, fully provenanced (Phase-2 §24).

    Every instance answers: which capture, which frame, which stream, when.
    """
    # provenance
    capture_id: str
    frame_number: Optional[int]
    tcp_stream_id: Optional[int]
    timestamp_epoch: Optional[float]
    timestamp_iso: Optional[str] = None

    # network
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport: Optional[str] = None
    frame_length: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_flags: Optional[str] = None
    has_payload: bool = False

    # protocol identification (observation, not verdict)
    protocol_stack: Tuple[str, ...] = field(default_factory=tuple)
    app_protocol: Optional[str] = None      # smtp | imap | pop3 | None (from dissector)
    implicit_tls_port: bool = False         # corroborating evidence only

    # layered evidence
    tls: TlsEvidence = field(default_factory=TlsEvidence)
    mail: MailEvidence = field(default_factory=MailEvidence)

    #: Decoded cleartext payload, retained ONLY for frames carrying a cleartext mail
    #: dialogue (bounded). None elsewhere, so encrypted/bulk frames cost nothing.
    payload_text: Optional[str] = None

    # fields the dissector did not provide for this frame (explicit, not fabricated)
    missing: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def stream_key(self) -> Optional[str]:
        """Stable stream identity: capture_id + tcp stream index (Phase-2 §23).
        Deliberately not the 4-tuple, which can repeat within one capture."""
        if self.tcp_stream_id is None:
            return None
        return f"{self.capture_id}:{self.tcp_stream_id}"


# --------------------------------------------------------------------------- normalize
def _protocol_stack(flat: dict) -> Tuple[str, ...]:
    raw = pick(flat, F.FRAME_PROTOCOLS)
    return tuple(raw.split(":")) if raw else ()


def _app_protocol(stack: Tuple[str, ...]) -> Optional[str]:
    """Canonical mail protocol from the dissector's own protocol stack."""
    for token in reversed(stack):
        if token in F.PROTOCOL_TOKENS and F.PROTOCOL_TOKENS[token] != "tls":
            return F.PROTOCOL_TOKENS[token]
    return None


def _tls(flat: dict) -> TlsEvidence:
    return TlsEvidence(
        record_version=pick(flat, F.TLS_RECORD_VERSION),
        handshake_type=_to_int(pick(flat, F.TLS_HANDSHAKE_TYPE)),
        handshake_version=pick(flat, F.TLS_HANDSHAKE_VERSION),
        cipher_suite=pick(flat, F.TLS_CIPHERSUITE),
        sni=pick(flat, F.TLS_SNI),
        supported_version=pick(flat, F.TLS_SUPPORTED_VERSION),
        session_id=pick(flat, F.TLS_SESSION_ID),
        has_app_data=pick(flat, F.TLS_APP_DATA) is not None,
    )


def _mail(flat: dict) -> MailEvidence:
    return MailEvidence(
        smtp_command=pick(flat, F.SMTP_REQ_COMMAND),
        smtp_command_line=pick(flat, F.SMTP_COMMAND_LINE),
        smtp_response_code=pick(flat, F.SMTP_RSP_CODE),
        smtp_response_params=pick_all(flat, F.SMTP_RSP_PARAM),
        imap_command=pick(flat, F.IMAP_REQ_COMMAND),
        imap_response_status=pick(flat, F.IMAP_RSP_STATUS),
        imap_lines=pick_all(flat, F.IMAP_LINE),
        pop_command=pick(flat, F.POP_REQ_COMMAND),
        pop_response_indicator=pick(flat, F.POP_RSP_INDICATOR),
        pop_response_description=pick(flat, F.POP_RSP_DESCRIPTION),
    )


#: Fields whose absence we record explicitly so downstream can distinguish
#: "not present in this frame" from "never looked".
_TRACKED = {
    "frame_number": F.FRAME_NUMBER,
    "tcp_stream": F.TCP_STREAM,
    "timestamp": F.FRAME_TIME_EPOCH,
}


def normalize_packet(record: dict, capture_id: str) -> FrameEvidence:
    flat = flatten_layers(record.get("layers", {}) or {})

    transport = ("tcp" if any(k.startswith("tcp_") for k in flat)
                 else "udp" if any(k.startswith("udp_") for k in flat) else None)
    stack = _protocol_stack(flat)
    src_port = _to_int(pick(flat, F.SRC_PORT))
    dst_port = _to_int(pick(flat, F.DST_PORT))

    implicit = False
    for port in (dst_port, src_port):
        if port in F.MAIL_PORTS and F.MAIL_PORTS[port][1]:
            implicit = True
            break

    missing = tuple(name for name, keys in _TRACKED.items() if pick(flat, keys) is None)

    app_proto = _app_protocol(stack)
    # Retain decoded payload only for cleartext mail dialogue frames (bounded).
    payload_text = (decode_payload(pick(flat, F.TCP_PAYLOAD))
                    if app_proto is not None else None)

    return FrameEvidence(
        capture_id=capture_id,
        frame_number=_to_int(pick(flat, F.FRAME_NUMBER)),
        tcp_stream_id=_to_int(pick(flat, F.TCP_STREAM)),
        timestamp_epoch=_to_epoch(pick(flat, F.FRAME_TIME_EPOCH)),
        timestamp_iso=pick(flat, F.FRAME_TIME_EPOCH),
        src_ip=pick(flat, F.IP_SRC),
        dst_ip=pick(flat, F.IP_DST),
        src_port=src_port,
        dst_port=dst_port,
        transport=transport,
        frame_length=_to_int(pick(flat, F.FRAME_LEN)),
        tcp_seq=_to_int(pick(flat, F.TCP_SEQ)),
        tcp_flags=pick(flat, F.TCP_FLAGS),
        has_payload=pick(flat, F.TCP_PAYLOAD) is not None,
        protocol_stack=stack,
        app_protocol=app_proto,
        payload_text=payload_text,
        implicit_tls_port=implicit,
        tls=_tls(flat),
        mail=_mail(flat),
        missing=missing,
    )


def normalize(records: Iterable[dict], capture_id: str = "") -> List[FrameEvidence]:
    return [normalize_packet(r, capture_id) for r in records]


def normalize_stream(records: Iterable[dict], capture_id: str = "") -> Iterator[FrameEvidence]:
    """Streaming variant: never materialises the whole capture (Phase-2 §16)."""
    for record in records:
        yield normalize_packet(record, capture_id)


def summarize(frames: Iterable[FrameEvidence]) -> Dict[str, object]:
    """Structural summary for the AnalysisRun. Counts only -- no verdicts."""
    frames = list(frames)
    protocols: Dict[str, int] = {}
    streams = set()
    tls_frames = 0
    handshake_types: Dict[int, int] = {}
    for f in frames:
        if f.app_protocol:
            protocols[f.app_protocol] = protocols.get(f.app_protocol, 0) + 1
        if f.stream_key:
            streams.add(f.stream_key)
        if f.tls.present:
            tls_frames += 1
        if f.tls.handshake_type is not None:
            handshake_types[f.tls.handshake_type] = handshake_types.get(f.tls.handshake_type, 0) + 1
    return {
        "frames": len(frames),
        "tcp_streams": len(streams),
        "app_protocols": dict(sorted(protocols.items())),
        "tls_frames": tls_frames,
        "tls_handshake_types": dict(sorted(handshake_types.items())),
        "implicit_tls_frames": sum(1 for f in frames if f.implicit_tls_port),
    }
