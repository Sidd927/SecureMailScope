"""Phase 11 / A-02 re-assessment: do the new D-09/D-13/D-14/D-17 features carry
any information on the corpora that actually exist?

A feature that is constant across every available session carries zero information,
so it cannot change an anomaly ranking. This script measures that directly, with no
model involved. It reads ServerHello suite + negotiated version and the X.509 field
count straight from tshark, exactly as doc 02 measured them.
"""
import collections, glob, json, os, subprocess, sys

# TLS 1.3 suites (RFC 8446 B.4) carry no key exchange; the group comes from key_share.
TLS13 = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
# Minimal IANA-derived map for the suites the corpora actually use.
KEX = {0xc02f: "ECDHE", 0xc030: "ECDHE", 0xc013: "ECDHE", 0xc014: "ECDHE",
       0x009c: "RSA", 0x009d: "RSA", 0x002f: "RSA", 0x0035: "RSA"}


def walk(node, out, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            walk(v, out, path + "." + k if path else k)
    elif isinstance(node, list):
        for v in node:
            walk(v, out, path)
    else:
        out.append((path, node))


def read(pcap):
    p = subprocess.run(["tshark", "-r", pcap, "-T", "ek"],
                       capture_output=True, text=True)
    suites, versions, x509, groups = [], [], 0, []
    for line in p.stdout.splitlines():
        if '"layers"' not in line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        flat = []
        walk(doc, flat)
        for key, val in flat:
            if key.endswith("tls_tls_handshake_ciphersuite"):
                suites.append(val)
            if key.endswith("tls_tls_handshake_extensions_supported_version"):
                versions.append(val)
            if key.endswith("tls_tls_handshake_extensions_key_share_group"):
                groups.append(val)
            if "x509" in key or "pkixalgs" in key:
                x509 += 1
    return suites, versions, groups, x509


def norm(v):
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        return None


def main(targets):
    rows = []
    for label, pattern in targets:
        for pcap in sorted(glob.glob(pattern)):
            suites, versions, groups, x509 = read(pcap)
            # `tls.handshake.ciphersuite` (singular) is the ServerHello selection;
            # `ciphersuites` (plural, not collected) is the ClientHello offer list.
            codes = [c for c in (norm(s) for s in suites) if c is not None]
            sel = codes[-1] if codes else None
            if sel is None:
                fs = None
            elif sel in TLS13:
                fs = True
            elif sel in KEX:
                fs = KEX[sel] in ("ECDHE", "DHE")
            else:
                fs = "AMBIGUOUS"          # unknown suite -> never guess
            rows.append({"corpus": label, "pcap": os.path.basename(pcap),
                         "selected_suite": hex(sel) if sel is not None else None,
                         "kex": ("TLS1.3-key_share" if sel in TLS13
                                 else KEX.get(sel) if sel is not None else None),
                         "key_share_groups": sorted(set(groups)),
                         "forward_secret": fs,
                         "x509_field_count": x509})
    return rows


if __name__ == "__main__":
    targets = [("real_oq33r", "research/experiments/oq33r/out/*.pcap"),
               ("genB", "research/experiments/oq36/corpus/genB/*.pcap"),
               ("genC", "research/experiments/oq36/corpus/genC/*.pcap"),
               ("synthetic_tls12_p11", "research/experiments/p11cert/out/*.pcap")]
    rows = main(targets)
    summary = collections.defaultdict(lambda: collections.defaultdict(set))
    for r in rows:
        for f in ("kex", "forward_secret"):
            summary[r["corpus"]][f].add(r[f])
        summary[r["corpus"]]["x509_present"].add(r["x509_field_count"] > 0)
    out = {"rows": rows,
           "variance": {c: {f: sorted(map(str, v)) for f, v in d.items()}
                        for c, d in summary.items()}}
    print(json.dumps(out, indent=2))
