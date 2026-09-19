"""
GENERATOR B -- "Exim dialect" corpus for the Phase-6 bake-off.

Written independently of oq28/craft.py (generator A) on purpose. Sharing helpers would
share artifacts, and a cross-generator holdout whose generators share a code path tests
nothing. Deliberate differences from generator A:

  * address plan, MAC addresses, port mix and client population size
  * randomised initial sequence numbers and inter-packet timing (seeded)
  * Exim/Sendmail-style banners and a different capability ordering
  * TLS 1.3 compatibility mode (non-empty legacy_session_id), different cipher offers,
    different extension ordering, different SNI
  * variable segmentation decided per message rather than per scenario
  * many sessions per client, so cross-session baselines actually establish

Ground truth lives in a sidecar JSON, never in the capture. Fully deterministic: the
same seed produces byte-identical pcaps (verified by tests/test_ml_dataset.py).

HONEST LIMITATION: generators B and C are both synthetic and were authored in the same
project. Cross-generator holdout between them is a weaker control than real multi-vendor
server traffic (OQ-33r), and docs/architecture/17 reports the two separately for that reason.
"""
from __future__ import annotations

import json
import os
import random
from typing import Dict, List, Optional, Tuple

from scapy.all import Ether, IP, TCP, Raw, wrpcap

GEN = "B"
OUT = os.path.join(os.path.dirname(__file__), "corpus", "genB")

CLIENT_MAC = "02:00:00:00:0b:01"
SERVER_MAC = "02:00:00:00:0b:02"
SERVER_IP = "192.168.20.25"
SERVER_ALT = "192.168.20.26"


# ----------------------------------------------------------------- TLS bytes
def _client_hello(rng: random.Random, sni: str) -> bytes:
    """TLS 1.3 ClientHello in compatibility mode (non-empty legacy_session_id)."""
    sni_b = sni.encode()
    ext_vers = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
    ext_grp = b"\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17"
    ext_sni = (b"\x00\x00" + (len(sni_b) + 5).to_bytes(2, "big")
               + (len(sni_b) + 3).to_bytes(2, "big") + b"\x00"
               + len(sni_b).to_bytes(2, "big") + sni_b)
    exts = ext_vers + ext_grp + ext_sni          # ordering differs from generator A
    session_id = bytes(rng.randrange(256) for _ in range(32))
    body = (b"\x03\x03" + bytes(rng.randrange(256) for _ in range(32))
            + b"\x20" + session_id
            + b"\x00\x08\x13\x02\x13\x01\x13\x03\xc0\x30"
            + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _server_hello(rng: random.Random, version: str) -> bytes:
    """ServerHello. For TLS<1.3 the negotiated version rides in legacy_version and no
    supported_versions extension is sent (RFC 8446 4.2.1)."""
    legacy = {"TLS1.0": b"\x03\x01", "TLS1.1": b"\x03\x02",
              "TLS1.2": b"\x03\x03", "TLS1.3": b"\x03\x03"}[version]
    tls13 = version == "TLS1.3"
    ext = b"\x00\x2b\x00\x02\x03\x04" if tls13 else b""
    suite = b"\x13\x02" if tls13 else b"\xc0\x30"
    body = (legacy + bytes(rng.randrange(256) for _ in range(32)) + b"\x00"
            + suite + b"\x00" + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16" + legacy + len(hs).to_bytes(2, "big") + hs


def _app(rng: random.Random) -> bytes:
    n = rng.randrange(180, 520)
    return b"\x17\x03\x03" + n.to_bytes(2, "big") + bytes(
        rng.randrange(256) for _ in range(n))


def _alert() -> bytes:
    return b"\x15\x03\x03\x00\x02\x02\x28"


# ---------------------------------------------------------------- TCP stream
class Conn:
    """TCP conversation builder with randomised ISNs and timing."""

    def __init__(self, rng: random.Random, cip: str, sip: str, cport: int,
                 sport: int, clock: List[float]) -> None:
        self.rng, self.cip, self.sip = rng, cip, sip
        self.cport, self.sport = cport, sport
        self.cseq = rng.randrange(10_000, 900_000)
        self.sseq = rng.randrange(10_000, 900_000)
        self.clock = clock                       # shared capture clock, monotonic
        self.pkts: List = []

    def _tick(self) -> float:
        self.clock[0] += self.rng.uniform(0.0008, 0.011)
        return self.clock[0]

    def _pkt(self, from_client: bool, flags: str, payload: bytes = b""):
        if from_client:
            p = (Ether(src=CLIENT_MAC, dst=SERVER_MAC)
                 / IP(src=self.cip, dst=self.sip)
                 / TCP(sport=self.cport, dport=self.sport, flags=flags,
                       seq=self.cseq, ack=self.sseq))
            if payload:
                p = p / Raw(load=payload)
                self.cseq += len(payload)
        else:
            p = (Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                 / IP(src=self.sip, dst=self.cip)
                 / TCP(sport=self.sport, dport=self.cport, flags=flags,
                       seq=self.sseq, ack=self.cseq))
            if payload:
                p = p / Raw(load=payload)
                self.sseq += len(payload)
        p.time = self._tick()
        self.pkts.append(p)
        return p

    def open(self) -> "Conn":
        self._pkt(True, "S")
        self.cseq += 1
        self._pkt(False, "SA")
        self.sseq += 1
        self._pkt(True, "A")
        return self

    def send(self, from_client: bool, data: bytes) -> "Conn":
        # Segmentation decided per message, not per scenario: a quarter of messages are
        # split at a random boundary so reassembly is exercised throughout the corpus.
        if len(data) > 24 and self.rng.random() < 0.25:
            cut = self.rng.randrange(8, len(data) - 8)
            self._pkt(from_client, "PA", data[:cut])
            self._pkt(from_client, "PA", data[cut:])
        else:
            self._pkt(from_client, "PA", data)
        return self

    def close(self) -> "Conn":
        self._pkt(True, "FA")
        self.cseq += 1
        self._pkt(False, "FA")
        self.sseq += 1
        self._pkt(True, "A")
        return self


# ------------------------------------------------------------- mail dialects
BANNERS = [
    b"220 mx1.corp.internal ESMTP Exim 4.96 Tue, 09 Sep 2026 10:14:02 +0000\r\n",
    b"220 mx2.corp.internal ESMTP Exim 4.94 ready\r\n",
    b"220 relay.corp.internal ESMTP Sendmail 8.17.1/8.17.1; Tue, 9 Sep 2026 10:14:02\r\n",
]

def _ehlo_reply(starttls: bool, host: bytes = b"mx1.corp.internal") -> bytes:
    """Exim-style capability list; ordering differs from generator A's Postfix list."""
    lines = [b"250-" + host + b" Hello client", b"250-SIZE 52428800",
             b"250-8BITMIME", b"250-PIPELINING"]
    if starttls:
        lines.append(b"250-STARTTLS")
    lines += [b"250-AUTH PLAIN LOGIN", b"250-CHUNKING", b"250 HELP"]
    return b"\r\n".join(lines) + b"\r\n"


def _imap_caps(starttls: bool) -> bytes:
    caps = b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE"
    if starttls:
        caps += b" STARTTLS"
    caps += b" AUTH=PLAIN] Courier-IMAP ready\r\n"
    return caps


def _pop3_caps(stls: bool) -> bytes:
    lines = [b"+OK Capability list follows", b"TOP", b"USER", b"SASL PLAIN LOGIN",
             b"UIDL", b"RESP-CODES", b"PIPELINING"]
    if stls:
        lines.append(b"STLS")
    lines.append(b".")
    return b"\r\n".join(lines) + b"\r\n"


# -------------------------------------------------------------- one session
def build_session(rng: random.Random, clock: List[float], cip: str, cport: int,
                  sip: str, proto: str, behaviour: str,
                  version: str = "TLS1.3") -> Tuple[List, str]:
    """Emit one session. Returns (packets, ground-truth label).

    `behaviour` describes what the WIRE shows; the label is assigned by the caller's
    scenario because the same wire bytes can be an attack or a configuration
    (docs/research/02B §3.1 -- that identity is the point of the corpus).
    """
    port = {"smtp": 587, "imap": 143, "pop3": 110,
            "smtps": 465, "imaps": 993, "pop3s": 995}[proto]
    conn = Conn(rng, cip, sip, cport, port, clock).open()
    base = proto.rstrip("s") if proto.endswith("s") and proto != "pop3s" else proto

    if proto in ("smtps", "imaps", "pop3s"):
        conn.send(True, _client_hello(rng, "mx1.corp.internal"))
        conn.send(False, _server_hello(rng, version))
        conn.send(False, _app(rng))
        conn.send(True, _app(rng))
        conn.close()
        return conn.pkts, "IMPLICIT_TLS"

    if proto == "smtp":
        conn.send(False, rng.choice(BANNERS))
        conn.send(True, b"EHLO workstation.corp.internal\r\n")
        conn.send(False, _ehlo_reply(behaviour in ("upgrade", "decline", "strip_command",
                                                   "failed_upgrade")))
        if behaviour == "upgrade":
            conn.send(True, b"STARTTLS\r\n")
            conn.send(False, b"220 TLS go ahead\r\n")
            conn.send(True, _client_hello(rng, "mx1.corp.internal"))
            conn.send(False, _server_hello(rng, version))
            conn.send(False, _app(rng))
            conn.send(True, _app(rng))
        elif behaviour == "failed_upgrade":
            conn.send(True, b"STARTTLS\r\n")
            conn.send(False, b"220 TLS go ahead\r\n")
            conn.send(True, _client_hello(rng, "mx1.corp.internal"))
            conn.send(False, _alert())
        elif behaviour == "strip_command":
            # The client's STARTTLS never reaches the server; it sees a bare AUTH.
            conn.send(True, b"AUTH LOGIN\r\n")
            conn.send(False, b"334 VXNlcm5hbWU6\r\n")
            conn.send(True, b"dXNlckBjb3JwLmludGVybmFs\r\n")
            conn.send(False, b"235 Authentication succeeded\r\n")
        else:                                   # decline / no_advert
            conn.send(True, b"AUTH LOGIN\r\n")
            conn.send(False, b"334 VXNlcm5hbWU6\r\n")
            conn.send(True, b"dXNlckBjb3JwLmludGVybmFs\r\n")
            conn.send(False, b"235 Authentication succeeded\r\n")
            conn.send(True, b"MAIL FROM:<user@corp.internal>\r\n")
            conn.send(False, b"250 OK\r\n")
        conn.send(True, b"QUIT\r\n")
        conn.send(False, b"221 mx1.corp.internal closing connection\r\n")

    elif proto == "imap":
        conn.send(False, _imap_caps(behaviour in ("upgrade", "decline",
                                                  "strip_command", "failed_upgrade")))
        conn.send(True, b"a001 CAPABILITY\r\n")
        conn.send(False, b"* CAPABILITY IMAP4rev1 IDLE"
                         + (b" STARTTLS" if behaviour in ("upgrade", "decline",
                                                          "strip_command",
                                                          "failed_upgrade") else b"")
                         + b"\r\na001 OK CAPABILITY completed\r\n")
        if behaviour == "upgrade":
            conn.send(True, b"a002 STARTTLS\r\n")
            conn.send(False, b"a002 OK Begin TLS negotiation now\r\n")
            conn.send(True, _client_hello(rng, "imap.corp.internal"))
            conn.send(False, _server_hello(rng, version))
            conn.send(False, _app(rng))
        elif behaviour == "failed_upgrade":
            conn.send(True, b"a002 STARTTLS\r\n")
            conn.send(False, b"a002 OK Begin TLS negotiation now\r\n")
            conn.send(True, _client_hello(rng, "imap.corp.internal"))
            conn.send(False, _alert())
        else:
            conn.send(True, b"a002 LOGIN user@corp.internal secret\r\n")
            conn.send(False, b"a002 OK LOGIN completed\r\n")
        conn.send(True, b"a003 LOGOUT\r\n")
        conn.send(False, b"* BYE Courier-IMAP server shutting down\r\n"
                         b"a003 OK LOGOUT completed\r\n")

    else:                                        # pop3
        conn.send(False, b"+OK Hello there, POP3 server ready\r\n")
        conn.send(True, b"CAPA\r\n")
        conn.send(False, _pop3_caps(behaviour in ("upgrade", "decline",
                                                  "strip_command", "failed_upgrade")))
        if behaviour == "upgrade":
            conn.send(True, b"STLS\r\n")
            conn.send(False, b"+OK Begin TLS negotiation\r\n")
            conn.send(True, _client_hello(rng, "pop.corp.internal"))
            conn.send(False, _server_hello(rng, version))
            conn.send(False, _app(rng))
        elif behaviour == "failed_upgrade":
            conn.send(True, b"STLS\r\n")
            conn.send(False, b"+OK Begin TLS negotiation\r\n")
            conn.send(True, _client_hello(rng, "pop.corp.internal"))
            conn.send(False, _alert())
        else:
            conn.send(True, b"USER user@corp.internal\r\n")
            conn.send(False, b"+OK Password required\r\n")
            conn.send(True, b"PASS secret\r\n")
            conn.send(False, b"+OK Logged in\r\n")
        conn.send(True, b"QUIT\r\n")
        conn.send(False, b"+OK Logging out\r\n")

    conn.close()
    return conn.pkts, behaviour


# -------------------------------------------------------------- scenarios
#: (scenario id, protocol, clients, sessions per client, per-client behaviour builder)
#: Every scenario names the ground truth explicitly; nothing is inferred from behaviour.
def _scenarios() -> List[dict]:
    return [
        {"id": "B01_all_upgrade", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda ci, si: ("upgrade", "BENIGN_TLS")},
        {"id": "B02_legit_decline", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda ci, si: ("decline", "BENIGN_DECLINE")},
        {"id": "B03_no_support", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda ci, si: ("no_advert", "BENIGN_NO_SUPPORT")},
        # Victim client is stripped while other clients upgrade: a control exists.
        {"id": "B04_strip_with_control", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda ci, si: (("no_advert", "ATTACK_STRIP_ADVERT") if ci == 0
                                 else ("upgrade", "BENIGN_TLS"))},
        # Every client stripped: no control anywhere. Known-undetectable (02A §9 #1).
        {"id": "B05_strip_blind", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda ci, si: ("no_advert", "ATTACK_STRIP_ADVERT")},
        {"id": "B06_strip_command", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda ci, si: (("strip_command", "ATTACK_STRIP_COMMAND") if ci == 0
                                 else ("upgrade", "BENIGN_TLS"))},
        {"id": "B07_failed_upgrade", "proto": "smtp", "clients": 3, "per": 10,
         "plan": lambda ci, si: (("failed_upgrade", "BENIGN_FAILED_UPGRADE") if ci == 0
                                 else ("upgrade", "BENIGN_TLS"))},
        # A legitimate reconfiguration part-way through: must NOT be an attack.
        {"id": "B08_config_change", "proto": "smtp", "clients": 3, "per": 12,
         "plan": lambda ci, si: (("upgrade", "BENIGN_TLS") if si < 6
                                 else ("no_advert", "BENIGN_CONFIG_CHANGE"))},
        # Heterogeneous but entirely legitimate client population.
        {"id": "B09_mixed_legit", "proto": "smtp", "clients": 4, "per": 10,
         "plan": lambda ci, si: (("upgrade", "BENIGN_TLS") if ci % 2 == 0
                                 else ("decline", "BENIGN_DECLINE"))},
        {"id": "B10_imap_strip_control", "proto": "imap", "clients": 4, "per": 10,
         "plan": lambda ci, si: (("no_advert", "ATTACK_STRIP_ADVERT") if ci == 0
                                 else ("upgrade", "BENIGN_TLS"))},
        {"id": "B11_imap_legit", "proto": "imap", "clients": 3, "per": 10,
         "plan": lambda ci, si: ("upgrade", "BENIGN_TLS")},
        {"id": "B12_pop3_strip_control", "proto": "pop3", "clients": 4, "per": 10,
         "plan": lambda ci, si: (("no_advert", "ATTACK_STRIP_ADVERT") if ci == 0
                                 else ("upgrade", "BENIGN_TLS"))},
        {"id": "B13_pop3_legit", "proto": "pop3", "clients": 3, "per": 10,
         "plan": lambda ci, si: ("decline", "BENIGN_DECLINE")},
        {"id": "B14_implicit", "proto": "smtps", "clients": 3, "per": 10,
         "plan": lambda ci, si: ("implicit", "BENIGN_IMPLICIT")},
        {"id": "B15_implicit_imaps", "proto": "imaps", "clients": 3, "per": 10,
         "plan": lambda ci, si: ("implicit", "BENIGN_IMPLICIT")},
        # Obsolete versions: a real security issue, but NOT a stripping attack. Kept
        # separate so the ML evaluation cannot confuse "weak" with "manipulated".
        {"id": "B16_legacy_tls", "proto": "smtp", "clients": 3, "per": 10,
         "plan": lambda ci, si: ("upgrade", "BENIGN_LEGACY_TLS")},
    ]


LEGACY_VERSIONS = {"B16_legacy_tls": ["TLS1.0", "TLS1.1", "TLS1.2"]}


def build(seed: int = 20260919) -> dict:
    os.makedirs(OUT, exist_ok=True)
    manifest: List[dict] = []
    for scenario in _scenarios():
        rng = random.Random(f"{seed}:{scenario['id']}")
        clock = [1789000000.0]
        packets: List = []
        streams: List[dict] = []
        sip = SERVER_ALT if scenario["id"].endswith("_legit") else SERVER_IP
        versions = LEGACY_VERSIONS.get(scenario["id"], ["TLS1.3"])
        for ci in range(scenario["clients"]):
            cip = f"192.168.10.{20 + ci}"
            for si in range(scenario["per"]):
                behaviour, truth = scenario["plan"](ci, si)
                version = versions[(ci + si) % len(versions)]
                cport = 40000 + ci * 1000 + si
                pkts, _ = build_session(rng, clock, cip, cport, sip,
                                        scenario["proto"], behaviour, version)
                packets.extend(pkts)
                streams.append({"client": cip, "client_port": cport, "server": sip,
                                "protocol": scenario["proto"], "behaviour": behaviour,
                                "ground_truth": truth, "tls_version": version})
        path = os.path.join(OUT, f"{scenario['id']}.pcap")
        wrpcap(path, packets)
        manifest.append({"generator": GEN, "scenario": scenario["id"],
                         "pcap": os.path.basename(path), "packets": len(packets),
                         "streams": streams})
    meta = {"generator": GEN, "seed": seed, "dialect": "exim/sendmail",
            "captures": manifest}
    with open(os.path.join(OUT, "ground_truth.json"), "w") as fh:
        json.dump(meta, fh, indent=1, sort_keys=True)
    return meta


if __name__ == "__main__":
    m = build()
    total = sum(len(c["streams"]) for c in m["captures"])
    print(f"generator {GEN}: {len(m['captures'])} captures, {total} sessions -> {OUT}")
