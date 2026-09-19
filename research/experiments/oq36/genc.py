"""
GENERATOR C -- "Zimbra/Dovecot dialect" corpus for the Phase-6 bake-off.

Independently written from generators A (oq28/craft.py) and B (genb.py). Differences are
deliberate and structural, not cosmetic, because the point of a cross-generator holdout
is that the model cannot recognise the pipeline that produced a capture:

  * one packet per protocol line ("chatty") instead of B's random segmentation
  * explicit bare-ACK packets between exchanges, so packet counts and directional
    balance differ systematically from B
  * SMTP on 25 rather than 587; different address plan (172.16.x)
  * TLS 1.2-dominant version mix, empty legacy_session_id, different cipher offers
  * larger and more variable inter-packet delays
  * RST teardown on a subset of sessions, and genuinely truncated sessions

The truncated scenarios exist to test that the ML lane ABSTAINS rather than scoring a
capture artifact -- the one distinctive behaviour of the model rejected in 10B §9.
"""
from __future__ import annotations

import json
import os
import random
from typing import List, Tuple

from scapy.all import Ether, IP, TCP, Raw, wrpcap

GEN = "C"
OUT = os.path.join(os.path.dirname(__file__), "corpus", "genC")

MAC_C = "02:00:00:00:0c:aa"
MAC_S = "02:00:00:00:0c:bb"
SRV = "172.16.8.10"
SRV2 = "172.16.8.11"

_VERSION_BYTES = {"TLS1.0": b"\x03\x01", "TLS1.1": b"\x03\x02",
                  "TLS1.2": b"\x03\x03", "TLS1.3": b"\x03\x03"}


def _hello_client(rng: random.Random, host: str) -> bytes:
    h = host.encode()
    sni = (b"\x00\x00" + (len(h) + 5).to_bytes(2, "big")
           + (len(h) + 3).to_bytes(2, "big") + b"\x00"
           + len(h).to_bytes(2, "big") + h)
    groups = b"\x00\x0a\x00\x04\x00\x02\x00\x17"
    versions = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
    exts = sni + groups + versions              # ordering differs from A and B
    body = (b"\x03\x03" + bytes(rng.randrange(256) for _ in range(32))
            + b"\x00"                            # empty legacy_session_id
            + b"\x00\x04\xc0\x2f\x13\x01"
            + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _hello_server(rng: random.Random, version: str) -> bytes:
    legacy = _VERSION_BYTES[version]
    ext = b"\x00\x2b\x00\x02\x03\x04" if version == "TLS1.3" else b""
    suite = b"\x13\x01" if version == "TLS1.3" else b"\xc0\x2f"
    body = (legacy + bytes(rng.randrange(256) for _ in range(32)) + b"\x00"
            + suite + b"\x00" + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16" + legacy + len(hs).to_bytes(2, "big") + hs


def _records(rng: random.Random, n: int = 2) -> List[bytes]:
    out = []
    for _ in range(n):
        size = rng.randrange(96, 340)
        out.append(b"\x17\x03\x03" + size.to_bytes(2, "big")
                   + bytes(rng.randrange(256) for _ in range(size)))
    return out


class Wire:
    """Chatty TCP builder: one payload per packet, with explicit acknowledgements."""

    def __init__(self, rng, cip, sip, cport, sport, clock):
        self.rng, self.cip, self.sip, self.cport, self.sport = rng, cip, sip, cport, sport
        self.cs = rng.randrange(1_000_000, 3_000_000)
        self.ss = rng.randrange(1_000_000, 3_000_000)
        self.clock = clock
        self.out: List = []

    def _t(self):
        self.clock[0] += self.rng.uniform(0.004, 0.045)
        return self.clock[0]

    def _emit(self, client: bool, flags: str, data: bytes = b""):
        if client:
            p = (Ether(src=MAC_C, dst=MAC_S) / IP(src=self.cip, dst=self.sip)
                 / TCP(sport=self.cport, dport=self.sport, flags=flags,
                       seq=self.cs, ack=self.ss))
            if data:
                p = p / Raw(load=data)
                self.cs += len(data)
        else:
            p = (Ether(src=MAC_S, dst=MAC_C) / IP(src=self.sip, dst=self.cip)
                 / TCP(sport=self.sport, dport=self.cport, flags=flags,
                       seq=self.ss, ack=self.cs))
            if data:
                p = p / Raw(load=data)
                self.ss += len(data)
        p.time = self._t()
        self.out.append(p)

    def open(self):
        self._emit(True, "S"); self.cs += 1
        self._emit(False, "SA"); self.ss += 1
        self._emit(True, "A")
        return self

    def srv(self, data: bytes, ack: bool = True):
        self._emit(False, "PA", data)
        if ack:
            self._emit(True, "A")
        return self

    def cli(self, data: bytes, ack: bool = True):
        self._emit(True, "PA", data)
        if ack:
            self._emit(False, "A")
        return self

    def fin(self):
        self._emit(True, "FA"); self.cs += 1
        self._emit(False, "FA"); self.ss += 1
        self._emit(True, "A")
        return self

    def rst(self):
        self._emit(False, "R")
        return self


def _smtp_caps(advert: bool) -> bytes:
    lines = [b"250-mailstore.zcs.example", b"250-PIPELINING", b"250-SIZE 10485760",
             b"250-VRFY", b"250-ETRN"]
    if advert:
        lines.append(b"250-STARTTLS")
    lines += [b"250-AUTH LOGIN PLAIN", b"250-ENHANCEDSTATUSCODES", b"250 DSN"]
    return b"\r\n".join(lines) + b"\r\n"


def _imap_banner(advert: bool) -> bytes:
    caps = b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE"
    if advert:
        caps += b" STARTTLS"
    caps += b" LOGINDISABLED] Dovecot ready.\r\n"
    return caps


def _pop3_capa(advert: bool) -> bytes:
    lines = [b"+OK", b"CAPA", b"TOP", b"UIDL", b"RESP-CODES", b"USER",
             b"SASL PLAIN LOGIN"]
    if advert:
        lines.append(b"STLS")
    lines.append(b".")
    return b"\r\n".join(lines) + b"\r\n"


def session(rng, clock, cip, cport, sip, proto, behaviour, version="TLS1.2",
            teardown="fin") -> List:
    port = {"smtp": 25, "imap": 143, "pop3": 110,
            "smtps": 465, "imaps": 993, "pop3s": 995}[proto]
    w = Wire(rng, cip, sip, cport, port, clock).open()
    advert = behaviour in ("upgrade", "decline", "strip_command", "failed_upgrade",
                           "reject_upgrade")

    if proto in ("smtps", "imaps", "pop3s"):
        w.cli(_hello_client(rng, "mailstore.zcs.example"))
        w.srv(_hello_server(rng, version))
        for rec in _records(rng, 3):
            w.srv(rec, ack=False)
        w.cli(_records(rng, 1)[0])
    elif proto == "smtp":
        w.srv(b"220 mailstore.zcs.example ESMTP Zimbra ready\r\n")
        w.cli(b"EHLO desktop.zcs.example\r\n")
        w.srv(_smtp_caps(advert))
        if behaviour == "upgrade":
            w.cli(b"STARTTLS\r\n")
            w.srv(b"220 Ready to start TLS\r\n")
            w.cli(_hello_client(rng, "mailstore.zcs.example"))
            w.srv(_hello_server(rng, version))
            for rec in _records(rng, 2):
                w.srv(rec, ack=False)
        elif behaviour == "failed_upgrade":
            w.cli(b"STARTTLS\r\n")
            w.srv(b"220 Ready to start TLS\r\n")
            w.cli(_hello_client(rng, "mailstore.zcs.example"))
            w.srv(b"\x15\x03\x03\x00\x02\x02\x28")
        elif behaviour == "reject_upgrade":
            w.cli(b"STARTTLS\r\n")
            w.srv(b"454 TLS not available due to temporary reason\r\n")
            w.cli(b"AUTH LOGIN\r\n")
            w.srv(b"334 VXNlcm5hbWU6\r\n")
        else:
            w.cli(b"AUTH LOGIN\r\n")
            w.srv(b"334 VXNlcm5hbWU6\r\n")
            w.cli(b"YWRtaW5AemNzLmV4YW1wbGU=\r\n")
            w.srv(b"235 2.7.0 Authentication successful\r\n")
            w.cli(b"MAIL FROM:<admin@zcs.example>\r\n")
            w.srv(b"250 2.1.0 Ok\r\n")
        w.cli(b"QUIT\r\n")
        w.srv(b"221 2.0.0 Bye\r\n")
    elif proto == "imap":
        w.srv(_imap_banner(advert))
        w.cli(b"1 CAPABILITY\r\n")
        w.srv(b"* CAPABILITY IMAP4rev1 IDLE"
              + (b" STARTTLS" if advert else b"")
              + b"\r\n1 OK Pre-login capabilities listed\r\n")
        if behaviour == "upgrade":
            w.cli(b"2 STARTTLS\r\n")
            w.srv(b"2 OK Begin TLS negotiation now.\r\n")
            w.cli(_hello_client(rng, "imap.zcs.example"))
            w.srv(_hello_server(rng, version))
            w.srv(_records(rng, 1)[0], ack=False)
        elif behaviour == "failed_upgrade":
            w.cli(b"2 STARTTLS\r\n")
            w.srv(b"2 OK Begin TLS negotiation now.\r\n")
            w.cli(_hello_client(rng, "imap.zcs.example"))
            w.srv(b"\x15\x03\x03\x00\x02\x02\x28")
        else:
            w.cli(b"2 LOGIN admin@zcs.example hunter2\r\n")
            w.srv(b"2 OK Logged in\r\n")
        w.cli(b"3 LOGOUT\r\n")
        w.srv(b"* BYE Logging out\r\n3 OK Logout completed.\r\n")
    else:
        w.srv(b"+OK Dovecot ready.\r\n")
        w.cli(b"CAPA\r\n")
        w.srv(_pop3_capa(advert))
        if behaviour == "upgrade":
            w.cli(b"STLS\r\n")
            w.srv(b"+OK Begin TLS negotiation.\r\n")
            w.cli(_hello_client(rng, "pop.zcs.example"))
            w.srv(_hello_server(rng, version))
            w.srv(_records(rng, 1)[0], ack=False)
        elif behaviour == "failed_upgrade":
            w.cli(b"STLS\r\n")
            w.srv(b"+OK Begin TLS negotiation.\r\n")
            w.cli(_hello_client(rng, "pop.zcs.example"))
            w.srv(b"\x15\x03\x03\x00\x02\x02\x28")
        else:
            w.cli(b"USER admin@zcs.example\r\n")
            w.srv(b"+OK\r\n")
            w.cli(b"PASS hunter2\r\n")
            w.srv(b"+OK Logged in.\r\n")
        w.cli(b"QUIT\r\n")
        w.srv(b"+OK Logging out.\r\n")

    if teardown == "fin":
        w.fin()
    elif teardown == "rst":
        w.rst()
    elif teardown == "cut":
        # Genuine mid-session truncation: drop the tail so neither the dialogue nor
        # the teardown completes. This is what a capture stopped by a full disk or a
        # rotated file actually looks like.
        keep = max(4, int(len(w.out) * rng.uniform(0.35, 0.6)))
        return w.out[:keep]
    return w.out


def _scenarios() -> List[dict]:
    return [
        {"id": "C01_upgrade_smtp", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda c, s: ("upgrade", "BENIGN_TLS"), "teardown": "fin"},
        {"id": "C02_decline_smtp", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda c, s: ("decline", "BENIGN_DECLINE"), "teardown": "fin"},
        {"id": "C03_no_support_smtp", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda c, s: ("no_advert", "BENIGN_NO_SUPPORT"), "teardown": "fin"},
        {"id": "C04_strip_control", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda c, s: (("no_advert", "ATTACK_STRIP_ADVERT") if c == 0
                               else ("upgrade", "BENIGN_TLS")), "teardown": "fin"},
        {"id": "C05_strip_blind", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda c, s: ("no_advert", "ATTACK_STRIP_ADVERT"), "teardown": "fin"},
        {"id": "C06_strip_command", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda c, s: (("strip_command", "ATTACK_STRIP_COMMAND") if c == 0
                               else ("upgrade", "BENIGN_TLS")), "teardown": "fin"},
        # Server-side refusal of an upgrade the client did request: a real condition
        # that is NOT stripping, and a classic false-positive source.
        {"id": "C07_reject_upgrade", "proto": "smtp", "clients": 3, "per": 10,
         "plan": lambda c, s: ("reject_upgrade", "BENIGN_SERVER_REJECT"),
         "teardown": "fin"},
        {"id": "C08_failed_upgrade", "proto": "smtp", "clients": 3, "per": 10,
         "plan": lambda c, s: (("failed_upgrade", "BENIGN_FAILED_UPGRADE") if c == 0
                               else ("upgrade", "BENIGN_TLS")), "teardown": "fin"},
        {"id": "C09_mixed_legit", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda c, s: (("upgrade", "BENIGN_TLS") if c < 2
                               else ("decline", "BENIGN_DECLINE")), "teardown": "fin"},
        {"id": "C10_config_change", "proto": "smtp", "clients": 3, "per": 12,
         "plan": lambda c, s: (("decline", "BENIGN_DECLINE") if s < 6
                               else ("upgrade", "BENIGN_CONFIG_CHANGE")),
         "teardown": "fin"},
        {"id": "C11_imap_strip_control", "proto": "imap", "clients": 4, "per": 10,
         "plan": lambda c, s: (("no_advert", "ATTACK_STRIP_ADVERT") if c == 0
                               else ("upgrade", "BENIGN_TLS")), "teardown": "fin"},
        {"id": "C12_imap_upgrade", "proto": "imap", "clients": 3, "per": 10,
         "plan": lambda c, s: ("upgrade", "BENIGN_TLS"), "teardown": "fin"},
        {"id": "C13_pop3_strip_control", "proto": "pop3", "clients": 4, "per": 10,
         "plan": lambda c, s: (("no_advert", "ATTACK_STRIP_ADVERT") if c == 0
                               else ("upgrade", "BENIGN_TLS")), "teardown": "fin"},
        {"id": "C14_pop3_no_support", "proto": "pop3", "clients": 3, "per": 10,
         "plan": lambda c, s: ("no_advert", "BENIGN_NO_SUPPORT"), "teardown": "fin"},
        {"id": "C15_implicit_smtps", "proto": "smtps", "clients": 3, "per": 10,
         "plan": lambda c, s: ("implicit", "BENIGN_IMPLICIT"), "teardown": "fin"},
        {"id": "C16_implicit_pop3s", "proto": "pop3s", "clients": 3, "per": 10,
         "plan": lambda c, s: ("implicit", "BENIGN_IMPLICIT"), "teardown": "fin"},
        {"id": "C17_legacy_tls", "proto": "smtp", "clients": 3, "per": 10,
         "plan": lambda c, s: ("upgrade", "BENIGN_LEGACY_TLS"), "teardown": "fin"},
        # Abrupt reset: unusual transport shape, entirely legitimate traffic.
        {"id": "C18_reset_teardown", "proto": "smtp", "clients": 3, "per": 10,
         "plan": lambda c, s: ("upgrade", "BENIGN_TLS"), "teardown": "rst"},
        # Capture stops mid-session: the ML lane must abstain, not score.
        {"id": "C19_truncated", "proto": "smtp", "clients": 3, "per": 10,
         "plan": lambda c, s: ("upgrade", "BENIGN_TRUNCATED"), "teardown": "cut"},
    ]


LEGACY = {"C17_legacy_tls": ["TLS1.0", "TLS1.1", "TLS1.2"]}
DEFAULT_VERSIONS = ["TLS1.2", "TLS1.2", "TLS1.3"]        # 1.2-dominant, unlike B


def build(seed: int = 20260920) -> dict:
    os.makedirs(OUT, exist_ok=True)
    captures: List[dict] = []
    for sc in _scenarios():
        rng = random.Random(f"{seed}:{sc['id']}")
        clock = [1789500000.0]
        packets: List = []
        streams: List[dict] = []
        sip = SRV2 if sc["proto"] in ("imap", "imaps") else SRV
        versions = LEGACY.get(sc["id"], DEFAULT_VERSIONS)
        for c in range(sc["clients"]):
            cip = f"172.16.4.{40 + c}"
            for s in range(sc["per"]):
                behaviour, truth = sc["plan"](c, s)
                version = versions[(c * 3 + s) % len(versions)]
                cport = 52000 + c * 1000 + s
                pkts = session(rng, clock, cip, cport, sip, sc["proto"], behaviour,
                               version, sc["teardown"])
                packets.extend(pkts)
                streams.append({"client": cip, "client_port": cport, "server": sip,
                                "protocol": sc["proto"], "behaviour": behaviour,
                                "ground_truth": truth, "tls_version": version,
                                "teardown": sc["teardown"]})
        path = os.path.join(OUT, f"{sc['id']}.pcap")
        wrpcap(path, packets)
        captures.append({"generator": GEN, "scenario": sc["id"],
                         "pcap": os.path.basename(path), "packets": len(packets),
                         "streams": streams})
    meta = {"generator": GEN, "seed": seed, "dialect": "zimbra/dovecot",
            "captures": captures}
    with open(os.path.join(OUT, "ground_truth.json"), "w") as fh:
        json.dump(meta, fh, indent=1, sort_keys=True)
    return meta


if __name__ == "__main__":
    m = build()
    total = sum(len(c["streams"]) for c in m["captures"])
    print(f"generator {GEN}: {len(m['captures'])} captures, {total} sessions -> {OUT}")
