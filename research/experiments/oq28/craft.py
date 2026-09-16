"""
OQ-28: craft REAL pcap files -- Ethernet/IPv4/TCP with genuine SMTP/IMAP/POP3
payloads and structurally valid TLS handshake records.

Unlike OQ-25 (which modelled session outcomes), this produces actual packets with
real sequence numbers, so the extractor must perform genuine TCP reassembly.

Ground truth is written to a SEPARATE json sidecar, never into the pcap.
"""
from __future__ import annotations
import os, json, hashlib
from scapy.all import Ether, IP, TCP, Raw, wrpcap

# ------------------------------------------------------------------ TLS bytes
def client_hello(sni: str = "mail.example.org") -> bytes:
    """Structurally valid TLS ClientHello (TLS1.2 record, supported_versions incl 1.3)."""
    sni_b = sni.encode()
    ext_sni = b"\x00\x00" + (len(sni_b)+5).to_bytes(2,"big") + (len(sni_b)+3).to_bytes(2,"big") \
              + b"\x00" + len(sni_b).to_bytes(2,"big") + sni_b
    ext_vers = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"          # supported_versions: 1.3,1.2
    ext_grp  = b"\x00\x0a\x00\x04\x00\x02\x00\x1d"              # supported_groups: x25519
    exts = ext_sni + ext_vers + ext_grp
    body = (b"\x03\x03" + b"\xAA"*32 + b"\x00"
            + b"\x00\x06\x13\x01\x13\x02\xc0\x2f"               # 3 cipher suites
            + b"\x01\x00" + len(exts).to_bytes(2,"big") + exts)
    hs = b"\x01" + len(body).to_bytes(3,"big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2,"big") + hs

def server_hello(tls13: bool = True) -> bytes:
    ext = b"\x00\x2b\x00\x02\x03\x04" if tls13 else b""
    body = (b"\x03\x03" + b"\xBB"*32 + b"\x00"
            + (b"\x13\x01" if tls13 else b"\xc0\x2f") + b"\x00"
            + len(ext).to_bytes(2,"big") + ext)
    hs = b"\x02" + len(body).to_bytes(3,"big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2,"big") + hs

def app_data(n: int = 220) -> bytes:
    return b"\x17\x03\x03" + n.to_bytes(2,"big") + bytes((i*7) & 0xFF for i in range(n))

def alert_handshake_failure() -> bytes:
    return b"\x15\x03\x03\x00\x02\x02\x28"      # fatal, handshake_failure


# ------------------------------------------------------------------ TCP stream
class Stream:
    """Builds a real TCP conversation with correct seq/ack bookkeeping."""
    def __init__(self, cip, sip, cport, sport, t0=0.0):
        self.cip, self.sip, self.cport, self.sport = cip, sip, cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.t = t0
        self.pkts = []

    def _emit(self, pkt):
        pkt.time = self.t
        self.t += 0.004
        self.pkts.append(pkt)

    def _c(self, flags, payload=b""):
        p = (Ether()/IP(src=self.cip, dst=self.sip)
             / TCP(sport=self.cport, dport=self.sport, flags=flags,
                   seq=self.cseq, ack=self.sseq))
        if payload:
            p = p/Raw(load=payload); self.cseq += len(payload)
        return p

    def _s(self, flags, payload=b""):
        p = (Ether()/IP(src=self.sip, dst=self.cip)
             / TCP(sport=self.sport, dport=self.cport, flags=flags,
                   seq=self.sseq, ack=self.cseq))
        if payload:
            p = p/Raw(load=payload); self.sseq += len(payload)
        return p

    def handshake(self):
        self._emit(self._c("S")); self.cseq += 1
        self._emit(self._s("SA")); self.sseq += 1
        self._emit(self._c("A"))
        return self

    def c2s(self, data: bytes, mss: int | None = None):
        """Client -> server. mss forces segmentation, exercising reassembly."""
        if mss:
            for i in range(0, len(data), mss):
                self._emit(self._c("PA", data[i:i+mss]))
        else:
            self._emit(self._c("PA", data))
        return self

    def s2c(self, data: bytes, mss: int | None = None):
        if mss:
            for i in range(0, len(data), mss):
                self._emit(self._s("PA", data[i:i+mss]))
        else:
            self._emit(self._s("PA", data))
        return self

    def s2c_retransmit(self, data: bytes):
        """Emit server payload twice with the SAME seq -- a real retransmission."""
        saved = self.sseq
        self._emit(self._s("PA", data))
        self.sseq = saved
        self._emit(self._s("PA", data))
        return self

    def s2c_out_of_order(self, a: bytes, b: bytes):
        """Emit segment B before segment A (correct seqs, wrong wire order)."""
        seq_a = self.sseq
        seq_b = self.sseq + len(a)
        pb = (Ether()/IP(src=self.sip, dst=self.cip)
              / TCP(sport=self.sport, dport=self.cport, flags="PA", seq=seq_b, ack=self.cseq)/Raw(load=b))
        self._emit(pb)
        pa = (Ether()/IP(src=self.sip, dst=self.cip)
              / TCP(sport=self.sport, dport=self.cport, flags="PA", seq=seq_a, ack=self.cseq)/Raw(load=a))
        self._emit(pa)
        self.sseq = seq_b + len(b)
        return self

    def fin(self):
        self._emit(self._c("FA")); self.cseq += 1
        self._emit(self._s("FA")); self.sseq += 1
        self._emit(self._c("A"))
        return self


# ------------------------------------------------------------------ dialogues
BANNER = {"smtp": b"220 mail.example.org ESMTP Postfix\r\n",
          "imap": b"* OK [CAPABILITY IMAP4rev1] mail.example.org ready\r\n",
          "pop3": b"+OK POP3 mail.example.org ready\r\n"}
HELLO  = {"smtp": b"EHLO client.example.net\r\n",
          "imap": b"a001 CAPABILITY\r\n",
          "pop3": b"CAPA\r\n"}
CAPS_WITH = {
 "smtp": b"250-mail.example.org\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
 "imap": b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN LOGINDISABLED\r\na001 OK completed\r\n",
 "pop3": b"+OK Capability list follows\r\nTOP\r\nUSER\r\nSTLS\r\n.\r\n"}
CAPS_WITHOUT = {   # stripped / genuinely unsupported -- byte-identical outcomes
 "smtp": b"250-mail.example.org\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
 "imap": b"* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGINDISABLED\r\na001 OK completed\r\n",
 "pop3": b"+OK Capability list follows\r\nTOP\r\nUSER\r\n.\r\n"}
STCMD  = {"smtp": b"STARTTLS\r\n", "imap": b"a002 STARTTLS\r\n", "pop3": b"STLS\r\n"}
STOK   = {"smtp": b"220 2.0.0 Ready to start TLS\r\n",
          "imap": b"a002 OK Begin TLS negotiation now\r\n",
          "pop3": b"+OK Begin TLS negotiation\r\n"}
STERR  = {"smtp": b"454 4.7.0 TLS not available due to temporary reason\r\n",
          "imap": b"a002 NO STARTTLS unavailable\r\n",
          "pop3": b"-ERR STLS unavailable\r\n"}
PLAIN_AUTH = {"smtp": b"AUTH LOGIN\r\n", "imap": b"a003 LOGIN alice s3cret\r\n",
              "pop3": b"USER alice\r\nPASS s3cret\r\n"}


def build(kind, proto="smtp", cip="10.0.0.5", sip="10.0.0.80", cport=40001,
          sport=None, t0=0.0, mss=None):
    """kind -> a real TCP stream. Returns (packets, ground_truth_label)."""
    sport = sport or {"smtp": 587, "imap": 143, "pop3": 110}[proto]
    s = Stream(cip, sip, cport, sport, t0).handshake()
    s.s2c(BANNER[proto]); s.c2s(HELLO[proto])

    if kind == "normal_tls":
        s.s2c(CAPS_WITH[proto], mss=mss); s.c2s(STCMD[proto]); s.s2c(STOK[proto])
        s.c2s(client_hello()); s.s2c(server_hello()); s.s2c(app_data()); s.fin()
        return s.pkts, "LEGIT_TLS"

    if kind == "legit_decline":
        s.s2c(CAPS_WITH[proto], mss=mss); s.c2s(PLAIN_AUTH[proto]); s.fin()
        return s.pkts, "LEGIT_DECLINE"

    if kind == "strip_advert":
        # MITM removed the capability line. Byte-identical to no_support below.
        s.s2c(CAPS_WITHOUT[proto], mss=mss); s.c2s(PLAIN_AUTH[proto]); s.fin()
        return s.pkts, "ATTACK_STRIP_ADVERT"

    if kind == "no_support":
        s.s2c(CAPS_WITHOUT[proto], mss=mss); s.c2s(PLAIN_AUTH[proto]); s.fin()
        return s.pkts, "LEGIT_PLAINTEXT_CFG"

    if kind == "strip_command":
        s.s2c(CAPS_WITH[proto], mss=mss); s.c2s(STCMD[proto]); s.s2c(STERR[proto])
        s.c2s(PLAIN_AUTH[proto]); s.fin()
        return s.pkts, "ATTACK_STRIP_COMMAND"

    if kind == "failed_upgrade":
        s.s2c(CAPS_WITH[proto], mss=mss); s.c2s(STCMD[proto]); s.s2c(STOK[proto])
        s.c2s(client_hello()); s.s2c(alert_handshake_failure()); s.fin()
        return s.pkts, "FAILED_UPGRADE"

    # ---- truncation variants -------------------------------------------
    if kind == "trunc_before_caps":
        return s.pkts, "INCOMPLETE_CAPTURE"
    if kind == "trunc_after_caps":
        s.s2c(CAPS_WITH[proto], mss=mss); return s.pkts, "INCOMPLETE_CAPTURE"
    if kind == "trunc_after_cmd":
        s.s2c(CAPS_WITH[proto], mss=mss); s.c2s(STCMD[proto]); return s.pkts, "INCOMPLETE_CAPTURE"
    if kind == "trunc_mid_handshake":
        s.s2c(CAPS_WITH[proto], mss=mss); s.c2s(STCMD[proto]); s.s2c(STOK[proto])
        s.c2s(client_hello()); return s.pkts, "INCOMPLETE_CAPTURE"
    if kind == "trunc_after_tls":
        s.s2c(CAPS_WITH[proto], mss=mss); s.c2s(STCMD[proto]); s.s2c(STOK[proto])
        s.c2s(client_hello()); s.s2c(server_hello()); return s.pkts, "LEGIT_TLS"

    # ---- network-condition variants ------------------------------------
    if kind == "retransmit":
        s.s2c_retransmit(CAPS_WITH[proto]); s.c2s(STCMD[proto]); s.s2c(STOK[proto])
        s.c2s(client_hello()); s.s2c(server_hello()); s.fin()
        return s.pkts, "LEGIT_TLS"
    if kind == "out_of_order":
        caps = CAPS_WITH[proto]; half = len(caps)//2
        s.s2c_out_of_order(caps[:half], caps[half:])
        s.c2s(STCMD[proto]); s.s2c(STOK[proto])
        s.c2s(client_hello()); s.s2c(server_hello()); s.fin()
        return s.pkts, "LEGIT_TLS"
    if kind == "loss_caps":
        # The capability response is LOST entirely. Client still sends STARTTLS,
        # proving it saw an advertisement we cannot observe.
        s.c2s(STCMD[proto]); s.s2c(STOK[proto])
        s.c2s(client_hello()); s.s2c(server_hello()); s.fin()
        return s.pkts, "LEGIT_TLS"
    raise ValueError(kind)


def write_corpus(outdir: str):
    os.makedirs(outdir, exist_ok=True)
    manifest = []
    port = 40000

    def add(name, specs):
        nonlocal port
        pkts, truth = [], []
        for (kind, proto, cip, sip) in specs:
            port += 1
            p, gt = build(kind, proto=proto, cip=cip, sip=sip, cport=port,
                          t0=len(pkts)*0.5)
            pkts += p
            truth.append({"stream": f"{cip}:{port}->{sip}", "kind": kind,
                          "protocol": proto, "ground_truth": gt})
        path = os.path.join(outdir, f"{name}.pcap")
        wrpcap(path, pkts)
        h = hashlib.sha256(open(path,"rb").read()).hexdigest()[:16]
        manifest.append({"case": name, "pcap": os.path.basename(path),
                         "packets": len(pkts), "sha256_16": h, "streams": truth})
        return path

    C, S, S2 = "10.0.0.5", "10.0.0.80", "10.0.0.81"
    V = "10.0.0.6"      # victim client
    O = "10.0.0.7"      # control client

    add("A_legit_decline",   [("legit_decline","smtp",C,S)]*6)
    add("B_strip_advert",    [("strip_advert","smtp",C,S)]*6)
    add("C_normal_tls",      [("normal_tls","smtp",C,S)]*6)
    add("D_failed_upgrade",  [("normal_tls","smtp",C,S)]*5 + [("failed_upgrade","smtp",C,S)]*2)
    add("E_incomplete",      [("trunc_before_caps","smtp",C,S),("trunc_after_caps","smtp",C,S),
                              ("trunc_after_cmd","smtp",C,S),("trunc_mid_handshake","smtp",C,S),
                              ("trunc_after_tls","smtp",C,S)])
    add("F_shared_identity", [("normal_tls","smtp",C,S)]*5 + [("legit_decline","smtp",C,S)]*5)
    add("G_control_endpoint",[("strip_advert","smtp",V,S)]*6 + [("normal_tls","smtp",O,S)]*6)
    add("H_no_control",      [("strip_advert","smtp",V,S)]*6)
    add("I_no_support",      [("no_support","smtp",C,S2)]*6)
    add("J_strip_command",   [("normal_tls","smtp",C,S)]*5 + [("strip_command","smtp",C,S)]*2)
    add("K_network_cond",    [("retransmit","smtp",C,S),("out_of_order","smtp",C,S),
                              ("loss_caps","smtp",C,S)])
    for pr in ("imap","pop3"):
        add(f"P_{pr}_decline", [("legit_decline",pr,C,S)]*6)
        add(f"P_{pr}_tls",     [("normal_tls",pr,C,S)]*6)
        add(f"P_{pr}_strip",   [("strip_advert",pr,C,S)]*6)

    with open(os.path.join(outdir,"ground_truth.json"),"w") as f:
        json.dump(manifest, f, indent=2)
    return manifest


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "pcaps")
    m = write_corpus(out)
    print(f"wrote {len(m)} pcap files to {out}")
    for e in m:
        print(f"  {e['case']:<22} {e['packets']:>4} pkts  sha256:{e['sha256_16']}  streams={len(e['streams'])}")
