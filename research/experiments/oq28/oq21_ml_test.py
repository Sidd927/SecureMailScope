"""
OQ-21 Part 9: does UNSUPERVISED ML add anything beyond the deterministic
cross-session baseline? Tested on the real OQ-28 extracted sessions.

Claim under test: "If unsupervised ML adds nothing beyond deterministic
baselining, reject it." We test both the naive framing AND the inverted one
from 10A (ML finds what the rules missed).
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))
import numpy as np
from sklearn.ensemble import IsolationForest
from extract import extract
from run import d1, d2, d2_contrast, GT, PC, truth_for, ATTACKS

# Gather every session across the whole corpus with observable features only
rows, meta = [], []
for case in sorted(GT):
    for s in extract(os.path.join(PC, GT[case]["pcap"])):
        # passive-observable numeric features
        f = [
            int(s["starttls_advertised"][1] is True),
            int(s["starttls_command"][1] is True),
            int(s["tls_established"][1] is True),
            int(s["plaintext_credentials"][1] is True),
            int(s["capture_complete"][1] is True),
            s["retransmits"], int(s["had_gap"]),
        ]
        rows.append(f)
        gt = truth_for(case, s["stream"])
        meta.append((case, s, gt))

X = np.array(rows, dtype=float)
print(f"corpus: {len(X)} sessions, {X.shape[1]} passive features\n")

# ---- Isolation Forest (unsupervised, no labels) ----
iso = IsolationForest(random_state=42, contamination="auto")
pred = iso.fit_predict(X)          # -1 = outlier
iso_outlier = pred == -1

# ---- deterministic cross-session verdicts, whole corpus ----
# rebuild per-case (baseline is per-capture) then compare set membership
det_suspect = {}
for case in sorted(GT):
    sess = extract(os.path.join(PC, GT[case]["pcap"]))
    v = d2_contrast(sess)
    for s in sess:
        det_suspect[(case, s["stream"])] = v[s["stream"]][0] == "SUSPECT"

print(f"{'':22}{'IsolationForest':>18}{'Determ. D2+contrast':>22}{'ground truth':>16}")
print("-"*80)
iso_flag_attacks = iso_flag_benign = det_flag_attacks = det_flag_benign = 0
iso_only = det_only = 0
for i,(case,s,gt) in enumerate(meta):
    io = iso_outlier[i]; dv = det_suspect[(case,s["stream"])]
    atk = gt in ATTACKS
    if io and atk: iso_flag_attacks += 1
    if io and not atk: iso_flag_benign += 1
    if dv and atk: det_flag_attacks += 1
    if dv and not atk: det_flag_benign += 1
    if io and not dv: iso_only += 1
    if dv and not io: det_only += 1

n_attack = sum(1 for _,_,gt in meta if gt in ATTACKS)
n_benign = len(meta) - n_attack
print(f"{'flags on ATTACKS':22}{iso_flag_attacks:>10}/{n_attack:<7}{det_flag_attacks:>14}/{n_attack:<7}")
print(f"{'flags on BENIGN (FP)':22}{iso_flag_benign:>10}/{n_benign:<7}{det_flag_benign:>14}/{n_benign:<7}")
print()
print(f"IsolationForest flags {iso_only} sessions the deterministic engine did NOT.")
print(f"Deterministic engine flags {det_only} sessions IsolationForest did NOT.")
print()

# ---- the INVERTED test (10A): does ML surface anything among rule-CLEAN sessions? ----
clean_outliers = [(case,s,gt) for i,(case,s,gt) in enumerate(meta)
                  if iso_outlier[i] and not det_suspect[(case,s["stream"])]]
print(f"INVERTED TEST: outliers among deterministically-CLEAN sessions: {len(clean_outliers)}")
for case,s,gt in clean_outliers[:8]:
    print(f"   {case:<20} gt={gt:<22} adv={s['starttls_advertised'][1]} tls={s['tls_established'][1]} gap={s['had_gap']}")
print()
what = set(gt for _,_,gt in clean_outliers)
print("   ground-truth classes among these outliers:", what or "(none)")
