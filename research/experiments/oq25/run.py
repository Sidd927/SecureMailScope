"""OQ-25 experiment runner. Deterministic (seeded). No ML."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from corpus import *            # noqa
from detectors import *         # noqa

ABSTAIN = {UNKNOWN, INSUFFICIENT}


def score(corpus, preds, label):
    tp = fp = fn = tn = abst = 0
    for o in corpus.observations():
        gt = corpus.ground_truth(o.session_id)
        p = preds[o.session_id]
        p = p[0] if isinstance(p, tuple) else p
        is_attack = gt in ATTACKS
        if p in ABSTAIN:
            abst += 1
            if is_attack: fn += 1          # abstention on an attack = missed
            continue
        if p == SUSPECT and is_attack:   tp += 1
        elif p == SUSPECT:               fp += 1
        elif is_attack:                  fn += 1
        else:                            tn += 1
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec  = tp / (tp + fn) if tp + fn else float("nan")
    f1   = 2*prec*rec/(prec+rec) if prec == prec and rec == rec and prec+rec else float("nan")
    return dict(label=label, tp=tp, fp=fp, fn=fn, tn=tn, abstain=abst,
                precision=prec, recall=rec, f1=f1)


def compare(corpus, keyname="pair+proto", min_history=5, use_server_contrast=True):
    obs = corpus.observations()
    r1 = score(corpus, {o.session_id: d1_per_session(o) for o in obs}, "D1 per-session")
    idx = build_server_index(obs) if use_server_contrast else None
    r2 = score(corpus, d2_cross_session(obs, KEYS[keyname], min_history, idx),
               f"D2 cross-session[{keyname}]")
    return r1, r2


def row(r):
    def f(x): return "  n/a" if x != x else f"{x:5.2f}"
    return (f"  {r['label']:<28} TP={r['tp']:<4} FP={r['fp']:<4} FN={r['fn']:<4} "
            f"TN={r['tn']:<4} abst={r['abstain']:<4} P={f(r['precision'])} R={f(r['recall'])} F1={f(r['f1'])}")


def show(title, corpus, **kw):
    print(f"\n{'='*92}\n{title}\n{'='*92}")
    r1, r2 = compare(corpus, **kw)
    print(row(r1)); print(row(r2))
    d = r1["fp"] - r2["fp"]
    pct = (d / r1["fp"] * 100) if r1["fp"] else 0.0
    print(f"  -> FP change: {r1['fp']} -> {r2['fp']}  ({d:+d}, {pct:+.0f}%)   "
          f"FN change: {r1['fn']} -> {r2['fn']} ({r2['fn']-r1['fn']:+d})")
    return r1, r2


# ============================================================ SCENARIOS
def scen_A(n):   # legitimate decline, one client one server
    c = Corpus(1); c.add(LEGIT_DECLINE, count=n, client="c1", server="s1"); return c

def scen_B(n):   # intentional plaintext configuration
    c = Corpus(2); c.add(LEGIT_PLAINTEXT_CFG, count=n, client="c1", server="s1"); return c

def scen_C(n_ok, n_attack):  # healthy baseline then real stripping
    c = Corpus(3)
    c.add(LEGIT_TLS, count=n_ok, client="c1", server="s1")
    c.add(ATTACK_STRIP_COMMAND, count=n_attack, client="c1", server="s1")
    return c

def scen_D():    # realistic mix on one infrastructure
    c = Corpus(4)
    c.add(LEGIT_TLS, count=40, client="c1", server="s1")
    c.add(LEGIT_DECLINE, count=10, client="c2", server="s1")
    c.add(LEGIT_TLS, count=10, client="c2", server="s1")
    c.add(FAILED_UPGRADE, count=5, client="c1", server="s1")
    c.add(ATTACK_STRIP_COMMAND, count=5, client="c1", server="s1")
    c.add(ATTACK_STRIP_ADVERT, count=5, client="c3", server="s1")
    c.add(LEGIT_TLS, count=10, client="c4", server="s1")
    c.add(INCOMPLETE_CAPTURE, count=5, client="c1", server="s1")
    return c

def scen_E():    # multiple clients, same server, different legitimate behaviour
    c = Corpus(5)
    c.add(LEGIT_TLS, count=20, client="modern", server="s1")
    c.add(LEGIT_DECLINE, count=20, client="legacy", server="s1")
    return c

def scen_F():    # one client, several servers with different postures
    c = Corpus(6)
    c.add(LEGIT_TLS, count=15, client="c1", server="good")
    c.add(LEGIT_PLAINTEXT_CFG, count=15, client="c1", server="old")
    c.add(ATTACK_STRIP_COMMAND, count=5, client="c1", server="good")
    return c


if __name__ == "__main__":
    print("#" * 92)
    print("OQ-25 :: Does cross-session baselining reduce false positives?")
    print("#" * 92)

    for n in (1, 5, 10, 25):
        show(f"SCENARIO A -- legitimate decline, {n} session(s). GT=LEGITIMATE (0 attacks)", scen_A(n))

    show("SCENARIO B -- intentional plaintext config, 25 sessions. GT=LEGITIMATE", scen_B(25))
    show("SCENARIO C -- 25 healthy + 5 stripped, same client/server", scen_C(25, 5))
    show("SCENARIO D -- REALISTIC MIX (the important test)", scen_D())
    show("SCENARIO E -- two clients, same server, different legitimate behaviour", scen_E())
    show("SCENARIO F -- one client, multiple servers", scen_F())
