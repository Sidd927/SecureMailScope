"""OQ-25 part 2: key comparison, ablation, history sweep, adversarial cases."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from corpus import *
from detectors import *
from run import score, scen_D, scen_E, row, ABSTAIN


def run_variant(corpus, keyname, min_history, contrast):
    obs = corpus.observations()
    idx = build_server_index(obs) if contrast else None
    return score(corpus, d2_cross_session(obs, KEYS[keyname], min_history, idx),
                 f"{keyname:<13} h={min_history:<3} contrast={'Y' if contrast else 'N'}")


print("#"*100)
print("PART 5 :: BASELINE KEY COMPARISON  (Scenario D, realistic mix)")
print("#"*100)
c = scen_D()
base = score(c, {o.session_id: d1_per_session(o) for o in c.observations()}, "D1 per-session (baseline)")
print(row(base))
print("-"*100)
for k in KEYS:
    for contrast in (True, False):
        print(row(run_variant(scen_D(), k, 5, contrast)))

print()
print("#"*100)
print("PART 5b :: SAME, on Scenario E (two legitimate client types, same server)")
print("#"*100)
c = scen_E()
base = score(c, {o.session_id: d1_per_session(o) for o in c.observations()}, "D1 per-session (baseline)")
print(row(base))
print("-"*100)
for k in ("pair+proto", "client", "server+proto", "global"):
    for contrast in (True, False):
        print(row(run_variant(scen_E(), k, 5, contrast)))

print()
print("#"*100)
print("PART 10 :: HISTORY DEPENDENCE  (Scenario A: legitimate decline, 0 attacks -> all firing is FP)")
print("#"*100)
from run import scen_A
for n in (1, 2, 3, 5, 10, 25, 50):
    c = scen_A(n)
    d1 = score(c, {o.session_id: d1_per_session(o) for o in c.observations()}, "d1")
    d2 = run_variant(c, "pair+proto", 5, False)
    print(f"  n={n:<4} D1 FP={d1['fp']:<4} | D2 FP={d2['fp']:<4} abstain={d2['abstain']:<4}"
          f"  -> {'ABSTAINS (honest)' if d2['abstain'] else 'baseline usable'}")

print()
print("#"*100)
print("PART 11 :: ADVERSARIAL / FALSIFICATION")
print("#"*100)

def adv(name, corpus, contrast=True, key="pair+proto"):
    d1 = score(corpus, {o.session_id: d1_per_session(o) for o in corpus.observations()}, "D1")
    d2 = run_variant(corpus, key, 5, contrast)
    print(f"\n-- {name}")
    print(f"     D1: TP={d1['tp']} FP={d1['fp']} FN={d1['fn']} TN={d1['tn']} abst={d1['abstain']}")
    print(f"     D2: TP={d2['tp']} FP={d2['fp']} FN={d2['fn']} TN={d2['tn']} abst={d2['abstain']}")
    return d1, d2

# 11J -- attacker strips EVERY session (the killer case)
c = Corpus(11); c.add(ATTACK_STRIP_ADVERT, count=30, client="c1", server="s1")
adv("11J  attacker strips advertisement on 100% of sessions, no control client", c)

# 11J variant -- 100% stripped for this client, but another client is untouched
c = Corpus(12)
c.add(ATTACK_STRIP_ADVERT, count=30, client="victim", server="s1")
c.add(LEGIT_TLS, count=30, client="other", server="s1")
adv("11J' same, but a second client on the same server IS untouched (control exists)", c)

# 11A -- legitimate client changes configuration mid-capture
c = Corpus(13)
c.add(LEGIT_DECLINE, count=20, client="c1", server="s1", day=1)
c.add(LEGIT_TLS, count=20, client="c1", server="s1", day=2)
adv("11A  legitimate client upgrades its config mid-capture", c)

# 11D -- many legitimate client types
c = Corpus(14)
for i, gt in enumerate([LEGIT_TLS, LEGIT_DECLINE, LEGIT_TLS, LEGIT_DECLINE, LEGIT_TLS]):
    c.add(gt, count=10, client=f"c{i}", server="s1")
adv("11D  five legitimate client types, mixed behaviour, NO attack present", c)

# 11H -- NAT: many clients share one IP
c = Corpus(15)
c.add(LEGIT_TLS, count=20, client="nat", server="s1")
c.add(LEGIT_DECLINE, count=20, client="nat", server="s1")   # same apparent client
adv("11H  NAT collapses two client populations into one identity", c)

# 11F/G -- incomplete capture
c = Corpus(16)
c.add(LEGIT_TLS, count=5, client="c1", server="s1")
c.add(INCOMPLETE_CAPTURE, count=20, client="c1", server="s1")
adv("11F  mostly-truncated capture", c)

# 11I -- attacker mimics baseline: strips only as often as the client legitimately declines
c = Corpus(17)
c.add(LEGIT_DECLINE, count=20, client="c1", server="s1")
c.add(ATTACK_STRIP_ADVERT, count=5, client="c1", server="s1")
adv("11I  attacker hides inside an existing plaintext baseline", c)

print()
print("#"*100)
print("PART 13 :: PER-PROTOCOL  (Scenario A pattern, 20 sessions each)")
print("#"*100)
for proto, port in (("smtp", 587), ("imap", 143), ("pop3", 110)):
    c = Corpus(18); c.add(LEGIT_DECLINE, count=20, client="c1", server="s1", protocol=proto, port=port)
    d1 = score(c, {o.session_id: d1_per_session(o) for o in c.observations()}, "d1")
    d2 = run_variant(c, "pair+proto", 5, False)
    print(f"  {proto:<5} D1 FP={d1['fp']:<4} D2 FP={d2['fp']:<4}")
c = Corpus(19)
for proto, port in (("smtp",587),("imap",143),("pop3",110)):
    c.add(LEGIT_TLS, count=15, client="c1", server="s1", protocol=proto, port=port)
    c.add(ATTACK_STRIP_COMMAND, count=3, client="c1", server="s1", protocol=proto, port=port)
d1 = score(c, {o.session_id: d1_per_session(o) for o in c.observations()}, "d1")
print(f"\n  mixed-protocol attack corpus: D1 TP={d1['tp']} FP={d1['fp']}")
for k in ("pair+proto", "pair"):
    print(row(run_variant(c, k, 5, False)))
