"""
OQ-28 extractor: raw packets -> session facts, via genuine TCP reassembly.

Deliberately does NOT use tshark's dissectors -- the point is to prove the facts
are recoverable from packets, and to be comparable against tshark independently.

Every fact carries an EVIDENCE STATE:
  OBSERVED       - directly present in captured bytes
  INFERRED       - deduced from other observed facts
  NOT_OBSERVABLE - cannot be established from this capture
  AMBIGUOUS      - evidence supports more than one reading
"""
from __future__ import annotations
import sys, os, json, hashlib
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, Raw

OBSERVED, INFERRED, NOT_OBSERVABLE, AMBIGUOUS = "OBSERVED", "INFERRED", "NOT_OBSERVABLE", "AMBIGUOUS"

ADV_TOKENS = {"smtp": b"STARTTLS", "imap": b"STARTTLS", "pop3": b"STLS"}
CMD_TOKENS = {"smtp": b"STARTTLS", "imap": b"STARTTLS", "pop3": b"STLS"}
PORTS = {587: "smtp", 25: "smtp", 143: "imap", 110: "pop3"}


class Reassembler:
    """Seq-ordered byte reassembly. Handles retransmits, gaps, out-of-order."""
    def __init__(self):
        self.segs: dict[int, bytes] = {}
        self.frames: dict[int, int] = {}
        self.retransmits = 0

    def add(self, seq: int, data: bytes, frame: int):
        if seq in self.segs:
            self.retransmits += 1
            return                       # duplicate seq -> retransmission
        self.segs[seq] = data
        self.frames[seq] = frame

    def bytes_in_order(self) -> tuple[bytes, bool]:
        """Returns (reassembled, had_gap). Gap = non-contiguous seq space."""
        if not self.segs:
            return b"", False
        keys = sorted(self.segs)
        out = bytearray(self.segs[keys[0]])
        expect = keys[0] + len(self.segs[keys[0]])
        gap = False
        for k in keys[1:]:
            if k != expect:
                gap = True
            out += self.segs[k]
            expect = k + len(self.segs[k])
        return bytes(out), gap

    def frame_of(self, needle: bytes) -> int | None:
        """First frame whose segment contains needle -- packet-level provenance."""
        for seq in sorted(self.segs):
            if needle in self.segs[seq]:
                return self.frames[seq]
        return None


def extract(pcap_path: str) -> list[dict]:
    pkts = rdpcap(pcap_path)
    streams = defaultdict(lambda: {"c2s": Reassembler(), "s2c": Reassembler(),
                                   "syn": False, "synack": False, "fin": False,
                                   "rst": False, "first": None, "last": None})
    for i, p in enumerate(pkts, start=1):
        if IP not in p or TCP not in p:
            continue
        ip, tcp = p[IP], p[TCP]
        sport, dport = int(tcp.sport), int(tcp.dport)
        # server side = the well-known mail port
        if dport in PORTS:
            key = (ip.src, sport, ip.dst, dport); direction = "c2s"
        elif sport in PORTS:
            key = (ip.dst, dport, ip.src, sport); direction = "s2c"
        else:
            continue
        st = streams[key]
        if st["first"] is None: st["first"] = i
        st["last"] = i
        f = int(tcp.flags)
        if f & 0x02 and not (f & 0x10): st["syn"] = True
        if f & 0x02 and (f & 0x10):     st["synack"] = True
        if f & 0x01: st["fin"] = True
        if f & 0x04: st["rst"] = True
        if Raw in p:
            st[direction].add(int(tcp.seq), bytes(p[Raw].load), i)

    out = []
    for (cip, cport, sip, sport), st in streams.items():
        proto = PORTS[sport]
        c2s, c_gap = st["c2s"].bytes_in_order()
        s2c, s_gap = st["s2c"].bytes_in_order()
        facts = analyse(proto, c2s, s2c, st, c_gap or s_gap)
        facts.update(stream=f"{cip}:{cport}->{sip}:{sport}", client=cip, server=sip,
                     protocol=proto, port=sport,
                     first_frame=st["first"], last_frame=st["last"],
                     retransmits=st["c2s"].retransmits + st["s2c"].retransmits,
                     had_gap=c_gap or s_gap)
        out.append(facts)
    return sorted(out, key=lambda x: x["first_frame"])


def analyse(proto, c2s: bytes, s2c: bytes, st, had_gap: bool) -> dict:
    """Derive facts with explicit evidence states. No ground truth used."""
    f = {}
    banner = s2c[:5] in (b"220 m", b"* OK ", b"+OK P") or s2c.startswith((b"220", b"* OK", b"+OK"))
    f["protocol_identified"] = (OBSERVED if banner else INFERRED,
                                proto, "banner" if banner else "port number only")

    # --- capability advertisement
    adv = ADV_TOKENS[proto] in s2c
    if adv:
        f["starttls_advertised"] = (OBSERVED, True, "capability token present in server bytes")
    elif had_gap:
        f["starttls_advertised"] = (NOT_OBSERVABLE, None, "capability response missing from capture (seq gap)")
    elif not s2c:
        f["starttls_advertised"] = (NOT_OBSERVABLE, None, "no server bytes captured")
    else:
        # CRUX: absence is byte-identical for "stripped" and "not supported"
        f["starttls_advertised"] = (AMBIGUOUS, False,
                                    "token absent: server may not support it, or it was stripped upstream")

    # --- client command
    cmd = any(l.strip().upper().endswith(CMD_TOKENS[proto]) or
              l.strip().upper() == CMD_TOKENS[proto]
              for l in c2s.split(b"\r\n"))
    f["starttls_command"] = (OBSERVED, cmd,
                             "command line present" if cmd else "no command line in client bytes")

    # --- server response to the command
    resp = None
    if cmd:
        ok = {"smtp": b"220 2.0.0 Ready", "imap": b"OK Begin TLS", "pop3": b"+OK Begin TLS"}[proto]
        err= {"smtp": b"454", "imap": b"NO STARTTLS", "pop3": b"-ERR STLS"}[proto]
        if ok in s2c:    resp = ("ACCEPT", OBSERVED)
        elif err in s2c: resp = ("REJECT", OBSERVED)
        else:            resp = (None, NOT_OBSERVABLE)
    f["starttls_response"] = (resp[1] if resp else NOT_OBSERVABLE,
                              resp[0] if resp else None,
                              "no command sent" if not cmd else "response classified")

    # --- TLS
    ch = b"\x16\x03" in c2s and b"\x01" in c2s
    ch = _has_tls_handshake(c2s, 1)
    sh = _has_tls_handshake(s2c, 2)
    alert = b"\x15\x03\x03" in s2c
    f["tls_client_hello"] = (OBSERVED, ch, "TLS handshake record type 1 found" if ch else "none")
    f["tls_server_hello"] = (OBSERVED, sh, "TLS handshake record type 2 found" if sh else "none")
    if ch and sh:
        f["tls_established"] = (OBSERVED, True, "ClientHello and ServerHello both present")
    elif ch and alert:
        f["tls_established"] = (OBSERVED, False, "ClientHello then TLS alert -> negotiation failed")
    elif ch and not sh:
        f["tls_established"] = (NOT_OBSERVABLE, None, "ClientHello seen, no ServerHello captured")
    else:
        f["tls_established"] = (OBSERVED, False, "no TLS handshake in stream")

    # --- plaintext continuation after the negotiation point
    auth = any(t in c2s for t in (b"AUTH LOGIN", b"AUTH PLAIN", b"LOGIN ", b"USER ", b"PASS "))
    f["plaintext_credentials"] = (OBSERVED, auth,
                                  "cleartext auth tokens in client bytes" if auth else "none")

    # --- capture completeness
    complete = st["syn"] and st["synack"] and (st["fin"] or st["rst"])
    f["capture_complete"] = (OBSERVED, complete,
                             "SYN, SYN-ACK and FIN/RST all present" if complete
                             else "stream boundaries incomplete -> truncated capture")
    return f


def _has_tls_handshake(buf: bytes, hs_type: int) -> bool:
    """Walk TLS records properly rather than substring-matching."""
    i = 0
    while i + 5 <= len(buf):
        ct, ver_hi, ver_lo = buf[i], buf[i+1], buf[i+2]
        ln = int.from_bytes(buf[i+3:i+5], "big")
        if ver_hi != 0x03 or ln == 0 or i + 5 + ln > len(buf):
            i += 1; continue
        if ct == 0x16 and i + 5 < len(buf) and buf[i+5] == hs_type:
            return True
        i += 5 + ln
    return False


if __name__ == "__main__":
    path = sys.argv[1]
    for s in extract(path):
        print(f"\n  {s['stream']}  [{s['protocol']}] frames {s['first_frame']}-{s['last_frame']}"
              f"  retrans={s['retransmits']} gap={s['had_gap']}")
        for k, v in s.items():
            if isinstance(v, tuple):
                state, val, why = v
                print(f"      {k:<24} {str(val):<8} {state:<15} {why}")
