"""
Crafted regression corpora for the Phase-7 hardening workstreams.

Two purpose-built corpora, both real Ethernet/IPv4/TCP with correct sequence numbers so
tshark performs genuine reassembly:

  oq46/  session-completeness scenarios -- clean teardown, capture stopping mid-session,
         mid-STARTTLS, mid-handshake, missing setup, and a stream that goes quiet while
         the capture keeps running (the case that must NOT be called truncation).

  oq47/  SMTP segmentation scenarios -- the capability line whole, split at every
         interesting boundary, retransmitted, reordered, duplicated, absent, refused,
         and advertised-but-never-used.

The point of oq47 is an equivalence property: for a given application byte stream, the
reconstructed semantics must not depend on how that stream was cut into packets. Each
segmented case therefore has an unsegmented twin carrying identical application bytes.

Deterministic: fixed MACs, fixed ISNs, fixed clock. Same input always yields the same
bytes, so the captures can be hash-pinned.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List, Optional, Sequence, Tuple

from scapy.all import Ether, IP, TCP, Raw, wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT46 = os.path.join(HERE, "oq46")
OUT47 = os.path.join(HERE, "oq47")

CMAC, SMAC = "02:00:00:00:46:01", "02:00:00:00:46:02"
CIP, SIP = "10.46.0.5", "10.46.0.80"

BANNER = b"220 mail.test.invalid ESMTP ready\r\n"
EHLO = b"EHLO client.test.invalid\r\n"
CAPS_WITH = (b"250-mail.test.invalid Hello client\r\n"
             b"250-SIZE 52428800\r\n"
             b"250-8BITMIME\r\n"
             b"250-PIPELINING\r\n"
             b"250-STARTTLS\r\n"
             b"250-AUTH PLAIN LOGIN\r\n"
             b"250 HELP\r\n")
CAPS_WITHOUT = (b"250-mail.test.invalid Hello client\r\n"
                b"250-SIZE 52428800\r\n"
                b"250-8BITMIME\r\n"
                b"250-PIPELINING\r\n"
                b"250-AUTH PLAIN LOGIN\r\n"
                b"250 HELP\r\n")
GO_AHEAD = b"220 TLS go ahead\r\n"
QUIT, BYE = b"QUIT\r\n", b"221 Bye\r\n"


def _client_hello() -> bytes:
    ext = (b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
           b"\x00\x0a\x00\x04\x00\x02\x00\x1d")
    body = (b"\x03\x03" + b"\xA5" * 32 + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _server_hello() -> bytes:
    ext = b"\x00\x2b\x00\x02\x03\x04"
    body = (b"\x03\x03" + b"\x5A" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
            + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _app_data(n: int = 200) -> bytes:
    return b"\x17\x03\x03" + n.to_bytes(2, "big") + bytes((i * 11) & 0xFF for i in range(n))


class Stream:
    """TCP conversation with deterministic sequencing and an explicit clock."""

    def __init__(self, cport: int, sport: int = 25, clock: Optional[List[float]] = None):
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.clock = clock if clock is not None else [1790000000.0]
        self.pkts: List = []

    def _tick(self) -> float:
        self.clock[0] += 0.005
        return self.clock[0]

    def _emit(self, client: bool, flags: str, data: bytes = b"",
              seq: Optional[int] = None, advance: bool = True):
        if client:
            p = (Ether(src=CMAC, dst=SMAC) / IP(src=CIP, dst=SIP)
                 / TCP(sport=self.cport, dport=self.sport, flags=flags,
                       seq=self.cseq if seq is None else seq, ack=self.sseq))
            if data:
                p = p / Raw(load=data)
                if advance:
                    self.cseq += len(data)
        else:
            p = (Ether(src=SMAC, dst=CMAC) / IP(src=SIP, dst=CIP)
                 / TCP(sport=self.sport, dport=self.cport, flags=flags,
                       seq=self.sseq if seq is None else seq, ack=self.cseq))
            if data:
                p = p / Raw(load=data)
                if advance:
                    self.sseq += len(data)
        p.time = self._tick()
        self.pkts.append(p)
        return self

    def open(self):
        self._emit(True, "S"); self.cseq += 1
        self._emit(False, "SA"); self.sseq += 1
        return self._emit(True, "A")

    def half_open(self):
        """Capture started after the handshake: no SYN/SYN-ACK in the file."""
        return self

    def cli(self, data: bytes):
        return self._emit(True, "PA", data)

    def srv(self, data: bytes):
        return self._emit(False, "PA", data)

    def srv_split(self, data: bytes, cuts: Sequence[int]):
        """Emit server payload as several segments with correct sequence numbers."""
        bounds = [0, *sorted(c for c in cuts if 0 < c < len(data)), len(data)]
        for start, stop in zip(bounds, bounds[1:]):
            self._emit(False, "PA", data[start:stop])
        return self

    def srv_split_reordered(self, data: bytes, cut: int):
        """Emit the SECOND segment before the first, with correct sequence numbers."""
        first, second = data[:cut], data[cut:]
        base = self.sseq
        self._emit(False, "PA", second, seq=base + len(first), advance=False)
        self._emit(False, "PA", first, seq=base, advance=False)
        self.sseq = base + len(data)
        return self

    def srv_retransmit(self, data: bytes):
        """Same bytes, same sequence number, twice."""
        base = self.sseq
        self._emit(False, "PA", data, seq=base, advance=False)
        self._emit(False, "PA", data, seq=base)
        return self

    def fin(self):
        self._emit(True, "FA"); self.cseq += 1
        self._emit(False, "FA"); self.sseq += 1
        return self._emit(True, "A")

    def rst(self):
        return self._emit(False, "R")


# ----------------------------------------------------------------- OQ-46 corpus
def _upgrade_body(s: Stream) -> Stream:
    return (s.srv(BANNER).cli(EHLO).srv(CAPS_WITH).cli(b"STARTTLS\r\n")
            .srv(GO_AHEAD).cli(_client_hello()).srv(_server_hello())
            .srv(_app_data()))


def build_oq46() -> List[dict]:
    """Each capture is one scenario, so 'ends at the capture's last frame' is
    unambiguous and the classification under test is the only variable."""
    cases: List[dict] = []

    def emit(name: str, pkts: List, expect: str, note: str):
        os.makedirs(OUT46, exist_ok=True)
        path = os.path.join(OUT46, f"{name}.pcap")
        wrpcap(path, pkts)
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]
        cases.append({"case": name, "pcap": f"{name}.pcap", "packets": len(pkts),
                      "sha256_16": digest, "expected_completeness": expect,
                      "note": note})

    s = Stream(40001); s.open(); _upgrade_body(s); s.cli(QUIT); s.srv(BYE); s.fin()
    emit("A_clean_teardown", s.pkts, "COMPLETE",
         "setup and FIN both observed; the ordinary case")

    s = Stream(40002); s.open(); _upgrade_body(s); s.cli(QUIT); s.srv(BYE); s.rst()
    emit("B_reset_teardown", s.pkts, "COMPLETE",
         "RST is a teardown; the session closed even if abruptly")

    s = Stream(40003); s.open(); s.srv(BANNER).cli(EHLO).srv(CAPS_WITH)
    emit("C_cut_mid_dialogue", s.pkts, "TRUNCATED",
         "capture stops after the capability response, session still open")

    s = Stream(40004); s.open(); s.srv(BANNER).cli(EHLO).srv(CAPS_WITH).cli(b"STARTTLS\r\n")
    emit("D_cut_during_starttls", s.pkts, "TRUNCATED",
         "capture stops between the STARTTLS command and the server's answer")

    s = Stream(40005); s.open(); s.srv(BANNER).cli(EHLO).srv(CAPS_WITH)
    s.cli(b"STARTTLS\r\n").srv(GO_AHEAD).cli(_client_hello())
    emit("E_cut_during_handshake", s.pkts, "TRUNCATED",
         "capture stops after the ClientHello; completion is unproven")

    s = Stream(40006); s.half_open(); s.srv(BANNER).cli(EHLO).srv(CAPS_WITH)
    s.cli(QUIT); s.srv(BYE); s.fin()
    emit("F_missing_setup", s.pkts, "INCOMPLETE",
         "capture began mid-session: no SYN/SYN-ACK, but the session did close")

    s = Stream(40007); s.open(); s.srv(BANNER).cli(EHLO)
    emit("G_incomplete_exchange", s.pkts, "TRUNCATED",
         "capture stops before the server answers EHLO")

    # Two streams: the first goes quiet, the second keeps the capture running and then
    # closes. The first must NOT be called truncated -- the recording did not stop.
    clock = [1790000000.0]
    quiet = Stream(40008, clock=clock); quiet.open()
    quiet.srv(BANNER).cli(EHLO).srv(CAPS_WITH)
    later = Stream(40009, clock=clock); later.open(); _upgrade_body(later)
    later.cli(QUIT); later.srv(BYE); later.fin()
    emit("H_quiet_stream_then_more_traffic", quiet.pkts + later.pkts,
         "INCOMPLETE",
         "stream 0 goes quiet while the capture continues; only stream 1 ends the file")
    return cases


# ----------------------------------------------------------------- OQ-47 corpus
#: Offsets inside CAPS_WITH chosen to hit the interesting boundaries.
_STARTTLS_AT = CAPS_WITH.index(b"250-STARTTLS")
_TOKEN_MID = _STARTTLS_AT + len(b"250-START")          # inside the token
_TOKEN_TAIL = _STARTTLS_AT + len(b"250-STARTTL")       # one byte before the token ends
_CRLF_SPLIT = _STARTTLS_AT + len(b"250-STARTTLS\r")    # between CR and LF


def build_oq47() -> List[dict]:
    cases: List[dict] = []

    def emit(name: str, pkts: List, expect_value, expect_state: str, note: str,
             equivalent_to: Optional[str] = None):
        os.makedirs(OUT47, exist_ok=True)
        path = os.path.join(OUT47, f"{name}.pcap")
        wrpcap(path, pkts)
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]
        cases.append({"case": name, "pcap": f"{name}.pcap", "packets": len(pkts),
                      "sha256_16": digest,
                      "expected_advertised": expect_value,
                      "expected_state": expect_state,
                      "equivalent_to": equivalent_to, "note": note})

    def session(build) -> List:
        s = Stream(41000 + len(cases))
        s.open().srv(BANNER).cli(EHLO)
        build(s)
        s.cli(b"STARTTLS\r\n").srv(GO_AHEAD).cli(_client_hello()).srv(_server_hello())
        s.srv(_app_data())
        s.fin()
        return s.pkts

    emit("A_whole_in_one_segment", session(lambda s: s.srv(CAPS_WITH)),
         True, "OBSERVED", "reference case: the reply arrives in one segment")

    emit("B_split_before_capability",
         session(lambda s: s.srv_split(CAPS_WITH, [_STARTTLS_AT])),
         True, "OBSERVED", "split on a line boundary just before the capability",
         equivalent_to="A_whole_in_one_segment")

    emit("C_split_inside_token",
         session(lambda s: s.srv_split(CAPS_WITH, [_TOKEN_MID])),
         True, "OBSERVED", "split INSIDE the STARTTLS token (OQ-47 mode A)",
         equivalent_to="A_whole_in_one_segment")

    emit("D_split_before_final_letter",
         session(lambda s: s.srv_split(CAPS_WITH, [_TOKEN_TAIL])),
         True, "OBSERVED",
         "split one byte before the token ends; tshark drops the trailing S",
         equivalent_to="A_whole_in_one_segment")

    emit("E_split_between_cr_and_lf",
         session(lambda s: s.srv_split(CAPS_WITH, [_CRLF_SPLIT])),
         True, "OBSERVED", "split between CR and LF of the capability line",
         equivalent_to="A_whole_in_one_segment")

    emit("F_split_many_segments",
         session(lambda s: s.srv_split(CAPS_WITH, list(range(7, len(CAPS_WITH), 9)))),
         True, "OBSERVED", "reply shredded into many small segments",
         equivalent_to="A_whole_in_one_segment")

    emit("G_split_mid_numeric",
         session(lambda s: s.srv_split(CAPS_WITH, [CAPS_WITH.index(b"52428800") + 3])),
         True, "OBSERVED",
         "split inside a numeric parameter; tshark invents a bogus code (mode B)",
         equivalent_to="A_whole_in_one_segment")

    emit("H_retransmitted_segment",
         session(lambda s: s.srv_retransmit(CAPS_WITH)),
         True, "OBSERVED", "the whole reply retransmitted at the same sequence number",
         equivalent_to="A_whole_in_one_segment")

    emit("I_reordered_segments",
         session(lambda s: s.srv_split_reordered(CAPS_WITH, _TOKEN_MID)),
         True, "OBSERVED", "second segment on the wire before the first",
         equivalent_to="A_whole_in_one_segment")

    emit("J_absent_whole", session(lambda s: s.srv(CAPS_WITHOUT)),
         False, "AMBIGUOUS", "no capability advertised; absence stays ambiguous")

    emit("K_absent_split",
         session(lambda s: s.srv_split(CAPS_WITHOUT, [30, 60, 90])),
         False, "AMBIGUOUS",
         "no capability advertised, reply segmented; must not invent one",
         equivalent_to="J_absent_whole")

    # Advertised but the client never upgrades: advertisement is still observed.
    s = Stream(41100)
    s.open().srv(BANNER).cli(EHLO).srv_split(CAPS_WITH, [_TOKEN_MID])
    s.cli(b"AUTH LOGIN\r\n").srv(b"334 VXNlcm5hbWU6\r\n")
    s.cli(QUIT).srv(BYE).fin()
    emit("L_advertised_never_used", s.pkts, True, "OBSERVED",
         "segmented advertisement, client declines; advertisement is still observed")

    # Server refuses the upgrade it advertised.
    s = Stream(41101)
    s.open().srv(BANNER).cli(EHLO).srv_split(CAPS_WITH, [_TOKEN_TAIL])
    s.cli(b"STARTTLS\r\n").srv(b"454 TLS not available\r\n")
    s.cli(QUIT).srv(BYE).fin()
    emit("M_server_refuses", s.pkts, True, "OBSERVED",
         "segmented advertisement then a 454 refusal")

    # Hostile: the capability string appears in message content, after the phase ends.
    s = Stream(41102)
    s.open().srv(BANNER).cli(EHLO).srv(CAPS_WITHOUT)
    s.cli(b"MAIL FROM:<a@test.invalid>\r\n").srv(b"250 OK\r\n")
    s.cli(b"RCPT TO:<b@test.invalid>\r\n").srv(b"250 OK\r\n")
    s.cli(b"DATA\r\n").srv(b"354 End data with <CR><LF>.<CR><LF>\r\n")
    s.cli(b"Subject: forged\r\n\r\n250-STARTTLS\r\n250 HELP\r\n.\r\n")
    s.srv(b"250 Queued\r\n").cli(QUIT).srv(BYE).fin()
    emit("N_forged_capability_in_message_body", s.pkts, False, "AMBIGUOUS",
         "attacker writes 250-STARTTLS into the message body; it must not be read "
         "as an advertisement")
    return cases


def main() -> None:
    manifest = {"oq46": build_oq46(), "oq47": build_oq47()}
    with open(os.path.join(HERE, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(f"oq46: {len(manifest['oq46'])} captures -> {OUT46}")
    print(f"oq47: {len(manifest['oq47'])} captures -> {OUT47}")


if __name__ == "__main__":
    main()
