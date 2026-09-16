"""OQ-25 part 3: ablation of the two mechanisms; time-aware baseline; infrastructure framing."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from corpus import *
from detectors import *
from run import score, scen_D, scen_E, ABSTAIN

def ev(c, contrast, key="pair+proto", h=5):
    obs = c.observations()
    d1 = score(c, {o.session_id: d1_per_session(o) for o in obs}, "d1")
    idx = build_server_index(obs) if contrast else None
    d2 = score(c, d2_cross_session(obs, KEYS[key], h, idx), "d2")
    return d1, d2

cases = {
 "A  legitimate decline x25":        (lambda: Corpus(1).add(LEGIT_DECLINE, count=25)),
 "C  25 healthy + 5 stripped-cmd":   (lambda: Corpus(3).add(LEGIT_TLS,count=25).add(ATTACK_STRIP_COMMAND,count=5)),
 "D  realistic mix":                 scen_D,
 "E  2 legit client types":          scen_E,
 "11J  100% strip, no control":      (lambda: Corpus(11).add(ATTACK_STRIP_ADVERT,count=30)),
 "11J' 100% strip + control client": (lambda: Corpus(12).add(ATTACK_STRIP_ADVERT,count=30,client="victim")
                                                        .add(LEGIT_TLS,count=30,client="other")),
 "11D  5 legit client types":        (lambda: Corpus(14).add(LEGIT_TLS,count=10,client="a").add(LEGIT_DECLINE,count=10,client="b")
                                                        .add(LEGIT_TLS,count=10,client="c").add(LEGIT_DECLINE,count=10,client="d")
                                                        .add(LEGIT_TLS,count=10,client="e")),
 "11H  NAT shared identity":         (lambda: Corpus(15).add(LEGIT_TLS,count=20,client="nat").add(LEGIT_DECLINE,count=20,client="nat")),
 "11I  attack hides in baseline":    (lambda: Corpus(17).add(LEGIT_DECLINE,count=20).add(ATTACK_STRIP_ADVERT,count=5)),
}

print("#"*104)
print("ABLATION :: consistency rule alone (contrast=N) vs + server-contrast rule (contrast=Y)")
print("#"*104)
print(f"{'case':<36}{'D1 FP/FN':>12}{'D2-noContrast FP/FN':>24}{'D2+Contrast FP/FN':>22}")
print("-"*104)
tot = {"d1_fp":0,"d1_fn":0,"n_fp":0,"n_fn":0,"c_fp":0,"c_fn":0}
for name, mk in cases.items():
    d1,_   = ev(mk(), False)
    _, dn  = ev(mk(), False)
    _, dc  = ev(mk(), True)
    print(f"{name:<36}{str(d1['fp'])+'/'+str(d1['fn']):>12}"
          f"{str(dn['fp'])+'/'+str(dn['fn']):>24}{str(dc['fp'])+'/'+str(dc['fn']):>22}")
    tot["d1_fp"]+=d1['fp']; tot["d1_fn"]+=d1['fn']
    tot["n_fp"]+=dn['fp'];  tot["n_fn"]+=dn['fn']
    tot["c_fp"]+=dc['fp'];  tot["c_fn"]+=dc['fn']
print("-"*104)
print(f"{'TOTAL':<36}{str(tot['d1_fp'])+'/'+str(tot['d1_fn']):>12}"
      f"{str(tot['n_fp'])+'/'+str(tot['n_fn']):>24}{str(tot['c_fp'])+'/'+str(tot['c_fn']):>22}")
print(f"\n  D1            : FP={tot['d1_fp']:3d}  FN={tot['d1_fn']:3d}")
print(f"  D2 consistency: FP={tot['n_fp']:3d}  FN={tot['n_fn']:3d}   "
      f"(FP {(tot['n_fp']-tot['d1_fp'])/max(tot['d1_fp'],1)*100:+.0f}%, FN {tot['n_fn']-tot['d1_fn']:+d})")
print(f"  D2 + contrast : FP={tot['c_fp']:3d}  FN={tot['c_fn']:3d}   "
      f"(FP {(tot['c_fp']-tot['d1_fp'])/max(tot['d1_fp'],1)*100:+.0f}%, FN {tot['c_fn']-tot['d1_fn']:+d})")

# ---------------------------------------------------------------- time-aware
print()
print("#"*104)
print("PART 14 :: TIME-AWARE BASELINE  (does 'changed behaviour' beat 'capture-wide behaviour'?)")
print("#"*104)

def time_aware(obs, min_history=5):
    """Per (client,server,protocol), compare each day against PRIOR days only."""
    from collections import defaultdict
    hist = defaultdict(lambda: defaultdict(lambda: [0,0]))  # key -> day -> [n, tls]
    for o in obs:
        if o.truncated: continue
        h = hist[(o.client,o.server,o.protocol)][o.day]
        h[0]+=1; h[1]+=o.tls_handshake_observed
    out={}
    for o in obs:
        if o.truncated: out[o.session_id]=(UNKNOWN,"truncated"); continue
        if o.tls_handshake_observed: out[o.session_id]=(BENIGN,"TLS established"); continue
        days = hist[(o.client,o.server,o.protocol)]
        prior = [d for d in days if d < o.day]
        pn = sum(days[d][0] for d in prior); pt = sum(days[d][1] for d in prior)
        if pn < min_history: out[o.session_id]=(INSUFFICIENT,f"prior history {pn}"); continue
        if pt == 0: out[o.session_id]=(BENIGN,f"always plaintext in {pn} prior sessions"); continue
        out[o.session_id]=(SUSPECT,f"prior history was {pt}/{pn} TLS; this session is not")
    return out

# Day1 TLS, Day2 stops (ATTACK), Day3 TLS again  -> should be SUSPECT on day 2
c = Corpus(20)
c.add(LEGIT_TLS, count=20, day=1); c.add(ATTACK_STRIP_ADVERT, count=10, day=2); c.add(LEGIT_TLS, count=20, day=3)
obs=c.observations()
d1 = score(c, {o.session_id: d1_per_session(o) for o in obs}, "d1")
d2 = score(c, d2_cross_session(obs, KEYS["pair+proto"], 5, None), "d2")
dt = score(c, time_aware(obs), "time")
print(f"  CASE: client always used TLS (day1), stopped on day2 (ATTACK), resumed day3")
print(f"    D1 per-session : TP={d1['tp']} FP={d1['fp']} FN={d1['fn']}")
print(f"    D2 capture-wide: TP={d2['tp']} FP={d2['fp']} FN={d2['fn']}")
print(f"    D3 time-aware  : TP={dt['tp']} FP={dt['fp']} FN={dt['fn']} abstain={dt['abstain']}")

# legitimate config change: always plaintext day1, upgrades from day2 -> should NOT be suspect
c = Corpus(21)
c.add(LEGIT_DECLINE, count=20, day=1); c.add(LEGIT_TLS, count=20, day=2)
obs=c.observations()
d1 = score(c, {o.session_id: d1_per_session(o) for o in obs}, "d1")
d2 = score(c, d2_cross_session(obs, KEYS["pair+proto"], 5, None), "d2")
dt = score(c, time_aware(obs), "time")
print(f"\n  CASE: legitimate client was plaintext (day1) then upgraded (day2). 0 attacks.")
print(f"    D1 per-session : FP={d1['fp']}")
print(f"    D2 capture-wide: FP={d2['fp']}")
print(f"    D3 time-aware  : FP={dt['fp']} abstain={dt['abstain']}")

# ---------------------------------------------------------------- infrastructure framing
print()
print("#"*104)
print("PART 12 :: INFRASTRUCTURE-LEVEL vs SESSION-LEVEL OUTPUT")
print("#"*104)
c = scen_D(); obs=c.observations()
agg = {}
from collections import defaultdict
st = defaultdict(lambda:[0,0])
for o in obs:
    if o.truncated: continue
    k=(o.client,o.server,o.protocol); st[k][0]+=1; st[k][1]+=o.tls_handshake_observed
print("  SESSION-LEVEL  : 'STARTTLS advertised, no TLS handshake observed.'  (x20 identical lines)")
print("  INFRASTRUCTURE :")
for k,(n,t) in sorted(st.items()):
    print(f"      {k[0]:<8} -> {k[1]:<4} {k[2]:<5}  {t}/{n} sessions upgraded  ({t/n*100:.0f}%)")
