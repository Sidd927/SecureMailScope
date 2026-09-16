"""
OQ-33: execute the REAL striptls mangling code and compare to the OQ-28 corpus.

striptls (tintinweb/striptls v0.5) is Python 2. `striptls_py3_exceptfix.py` is a
verbatim copy with ONLY `except X, e:` -> `except X as e:` applied (36 sites);
no logic changed. Run: python3 oq33_striptls.py
"""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(__file__))
from craft import Stream, BANNER, HELLO, CAPS_WITH, CAPS_WITHOUT, PLAIN_AUTH
from scapy.all import wrpcap

_STRIPTLS = os.path.join(os.path.dirname(__file__), "striptls_py3_exceptfix.py")
if not os.path.exists(_STRIPTLS):
    raise SystemExit(
        "striptls source not present (GPLv2, intentionally not vendored).\n"
        "Regenerate with: python3 research/experiments/oq28/fetch_striptls.py")
ns = {}
exec(compile(open(_STRIPTLS).read(), "striptls", "exec"), ns)
V = ns["Vectors"]

class _Buf: sndbuf = "ehlo x\r\n"
class _Sess: outbound = _Buf()
class _RW:
    def set_result(self, *a): pass
d = lambda b: b.decode()

def main():
    print("OQ-33 :: executing real striptls manglers\n")
    smtp = V.SMTP.StripFromCapabilities.mangle_server_data(_Sess(), d(CAPS_WITH["smtp"]), _RW())
    assert smtp == d(CAPS_WITHOUT["smtp"]), "SMTP mismatch"
    print("SMTP StripFromCapabilities == corpus CAPS_WITHOUT :", smtp == d(CAPS_WITHOUT["smtp"]))

    s = _Sess(); s.outbound.sndbuf = "CAPA\r\n"
    pop = V.POP3.StripFromCapabilities.mangle_server_data(s, d(CAPS_WITH["pop3"]), _RW())
    print("POP3 STLS stripped                                :", "stls" not in pop.lower())

    s = _Sess(); s.outbound.sndbuf = "a001 CAPABILITY\r\n"
    imap = V.IMAP.StripFromCapabilities.mangle_server_data(s, d(CAPS_WITH["imap"]), _RW())
    print("IMAP STARTTLS stripped                            :", "STARTTLS" not in imap)

    # write a pcap whose server payload came from striptls's own code
    st = Stream("10.0.0.9", "10.0.0.80", 45001, 587).handshake()
    st.s2c(BANNER["smtp"]); st.c2s(HELLO["smtp"]); st.s2c(smtp.encode())
    st.c2s(PLAIN_AUTH["smtp"]); st.fin()
    out = os.path.join(os.path.dirname(__file__), "pcaps", "S_striptls_real.pcap")
    wrpcap(out, st.pkts)
    print("\nwrote", os.path.basename(out), "sha256:",
          hashlib.sha256(open(out, "rb").read()).hexdigest()[:16])

if __name__ == "__main__":
    main()
