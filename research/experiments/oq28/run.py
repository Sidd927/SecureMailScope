"""OQ-28: run D1/D2 over facts extracted from REAL pcaps. Ground truth only for scoring."""
from __future__ import annotations
import sys, os, json, hashlib
sys.path.insert(0, os.path.dirname(__file__))
from collections import defaultdict
from extract import extract, OBSERVED, INFERRED, NOT_OBSERVABLE, AMBIGUOUS

PC = os.path.join(os.path.dirname(__file__), "pcaps")
GT = {e["case"]: e for e in json.load(open(os.path.join(PC, "ground_truth.json")))}
ATTACKS = {"ATTACK_STRIP_ADVERT", "ATTACK_STRIP_COMMAND"}

SUSPECT, BENIGN, UNKNOWN, INSUFF = "SUSPECT", "BENIGN", "UNKNOWN", "INSUFFICIENT_HISTORY"


def d1(f):
    """Per-session baseline. Neutral re-implementation of the competitor pattern."""
    if not f["capture_complete"][1]:
        return UNKNOWN, "incomplete capture"
    adv_state, adv_val, _ = f["starttls_advertised"]
    if adv_state == NOT_OBSERVABLE:
        return UNKNOWN, "advertisement not observable"
    tls = f["tls_established"][1]
    if adv_val and not tls:
        return SUSPECT, "advertised but no TLS established"
    return BENIGN, "no trigger"


def d2(sessions):
    """Cross-session: prior-history baseline per (client, server, protocol), min 5."""
    MIN = 5
    hist = defaultdict(list)
    for s in sessions:
        hist[(s["client"], s["server"], s["protocol"])].append(s)
    out = {}
    for s in sessions:
        k = (s["client"], s["server"], s["protocol"])
        if not s["capture_complete"][1]:
            out[s["stream"]] = (UNKNOWN, "incomplete capture"); continue
        if s["tls_established"][1]:
            out[s["stream"]] = (BENIGN, "TLS established"); continue
        peers = [p for p in hist[k] if p["capture_complete"][1]]
        usable = len(peers)
        if usable < MIN:
            out[s["stream"]] = (INSUFF, f"only {usable} usable sessions for endpoint"); continue
        tls_n = sum(1 for p in peers if p["tls_established"][1])
        if tls_n == 0:
            out[s["stream"]] = (BENIGN, f"endpoint never upgrades across {usable} sessions -> configuration")
        elif tls_n == usable:
            out[s["stream"]] = (SUSPECT, f"endpoint upgrades in {tls_n}/{usable} sessions; this one does not")
        else:
            out[s["stream"]] = (SUSPECT, f"deviates from own baseline ({tls_n}/{usable} upgrade)")
    return out


def d2_contrast(sessions):
    """D2 + control-endpoint rule: same server+protocol, a DIFFERENT client upgrades."""
    base = d2(sessions)
    srv = defaultdict(lambda: [0, 0])
    per_client = defaultdict(lambda: [0, 0])
    for s in sessions:
        if not s["capture_complete"][1]: continue
        srv[(s["server"], s["protocol"])][0] += 1
        srv[(s["server"], s["protocol"])][1] += bool(s["tls_established"][1])
        per_client[(s["client"], s["server"], s["protocol"])][0] += 1
        per_client[(s["client"], s["server"], s["protocol"])][1] += bool(s["tls_established"][1])
    for s in sessions:
        v, why = base[s["stream"]]
        if v != BENIGN or "never upgrades" not in why:
            continue
        n, t = srv[(s["server"], s["protocol"])]
        cn, ct = per_client[(s["client"], s["server"], s["protocol"])]
        if t > ct:   # some OTHER client on this server does upgrade
            base[s["stream"]] = (SUSPECT,
                f"server upgrades for other clients ({t}/{n}) but never for this one ({ct}/{cn})")
    return base


def truth_for(case, stream):
    # extracted: "cip:cport->sip:sport"   ground truth: "cip:cport->sip"
    lhs = stream.split("->")[0]                      # "cip:cport"
    for t in GT[case]["streams"]:
        if t["stream"].split("->")[0] == lhs:
            return t["ground_truth"]
    return None


def score(case, sessions, verdicts):
    tp = fp = fn = tn = ab = 0
    for s in sessions:
        gt = truth_for(case, s["stream"])
        v = verdicts[s["stream"]][0]
        atk = gt in ATTACKS
        if v in (UNKNOWN, INSUFF):
            ab += 1
            if atk: fn += 1
            continue
        if v == SUSPECT and atk: tp += 1
        elif v == SUSPECT:       fp += 1
        elif atk:                fn += 1
        else:                    tn += 1
    return tp, fp, fn, tn, ab


if __name__ == "__main__":
    cases = [c for c in sorted(GT) if not c.startswith("P_")] + \
            [c for c in sorted(GT) if c.startswith("P_")]
    print("="*104)
    print(f"{'case':<22}{'GT':<22}{'D1 TP/FP/FN/ab':>18}{'D2 TP/FP/FN/ab':>18}{'D2+contrast':>18}")
    print("="*104)
    tot = [0]*4; tot2 = [0]*4; tot3 = [0]*4
    for case in cases:
        path = os.path.join(PC, GT[case]["pcap"])
        sess = extract(path)
        v1 = {s["stream"]: d1(s) for s in sess}
        v2 = d2(sess); v3 = d2_contrast(sess)
        a = score(case, sess, v1); b = score(case, sess, v2); c = score(case, sess, v3)
        gts = sorted({truth_for(case, s["stream"]) for s in sess})
        gtxt = ",".join(x.replace("ATTACK_","A:").replace("LEGIT_","L:").replace("INCOMPLETE_CAPTURE","TRUNC") for x in gts)
        fmt = lambda r: f"{r[0]}/{r[1]}/{r[2]}/{r[4]}"
        print(f"{case:<22}{gtxt[:21]:<22}{fmt(a):>18}{fmt(b):>18}{fmt(c):>18}")
        for i,(x,y,z) in enumerate(zip(a[:4], b[:4], c[:4])):
            tot[i]+=x; tot2[i]+=y; tot3[i]+=z
    print("-"*104)
    print(f"{'TOTAL':<44}{tot[0]}/{tot[1]}/{tot[2]:<12}{tot2[0]}/{tot2[1]}/{tot2[2]:<12}{tot3[0]}/{tot3[1]}/{tot3[2]}")
    print(f"\n  D1          : TP={tot[0]:3d} FP={tot[1]:3d} FN={tot[2]:3d}")
    print(f"  D2          : TP={tot2[0]:3d} FP={tot2[1]:3d} FN={tot2[2]:3d}")
    print(f"  D2+contrast : TP={tot3[0]:3d} FP={tot3[1]:3d} FN={tot3[2]:3d}")
