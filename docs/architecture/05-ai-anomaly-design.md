# 05 — AI/ML Anomaly Detection Design

**Status:** Design + experiment plan (model NOT selected). **Date:** 2026-09-16
**Reconciles:** 10B (naive per-session ML rejected on evidence) with Phase-11 §3 (PS explicitly
requires a real AI/ML anomaly component). **Pairs with:** ADR-0006.

---

## 1. The reconciliation (read first)

10B §9 tested naive Isolation Forest on **per-session** features: 2/32 attacks, more false positives
than the deterministic baseline, zero distinctive contribution. Correct result — for that design.

Phase-11 §3 requires a genuine ML component and forbids forcing a bad one. The resolution is **not**
"drop ML" and **not** "ship the failed model." It is a **different, defensible ML design**, selected
empirically:

1. **Unsupervised** — no training on our own rule labels (the competitor circular trap, 01D §6).
2. **Features are cross-session DEVIATION features**, not raw per-session values. 02A/02B showed the
   signal lives in infrastructure-relative space; that is exactly where the model should look.
3. **Model chosen by a bake-off** (§5) on a diversity-controlled corpus, not asserted.
4. **Independent lane** — ML produces a score, never a finding or a fact (§7).
5. **Honest failure path** — if no model beats the deterministic baseline as a *complementary* signal
   (finds things rules miss without flooding FPs), we ship the best one as a *secondary prioritisation
   input only* and document the limitation. A-02 is still satisfied (a real AI/ML anomaly technique is
   present and evaluated); we simply don't overclaim its power.

## 2. What "anomaly" means here

Not "attack." An anomalous TLS session is one whose feature vector is a statistical outlier relative to
the **learned baseline of normal behaviour for its context** — which no deterministic rule enumerates.
This is the one A-requirement genuinely suited to ML (01 §6.5), and it directly answers the PS wording
*"AI-assisted anomaly detection for suspicious TLS sessions."*

## 3. Candidate models (Phase-11 §10)

| Model | Data need | Explainable? | Offline | Synthetic-leak risk | Note |
|---|---|---|---|---|---|
| Isolation Forest | low-med | 🟡 (feature attribution) | ✅ | med | 10B baseline; re-test with deviation features |
| Local Outlier Factor | med | 🟡 | ✅ | med | density-based; good for local anomalies |
| One-Class SVM | med | 🟡 | ✅ | med | boundary model; sensitive to scaling |
| **Robust statistics** (Mahalanobis / MAD / robust z) | low | ✅ **high** | ✅ | **low** | strong default: explainable, few assumptions, no black box |
| Autoencoder | **high** | ❌ | ✅ | high | ❌ likely rejected — too little data for the SIH corpus |
| Temporal anomaly (per-endpoint drift) | med | 🟡 | ✅ | low | complements time-aware baseline (02A §6) |

**Prior expectation (to be tested, not assumed):** robust-statistical scoring over deviation features
is the most defensible starting point — explainable, low data need, low leakage risk — with Isolation
Forest / LOF as challengers. Autoencoder is deprioritised on data grounds.

## 4. Features (from structured evidence, never raw email text — Phase-11 §13)

**Session-intrinsic:** negotiated TLS version, cipher class, key-exchange type, forward-secrecy flag,
handshake completeness, resumption, SNI presence, plaintext-continuation, STARTTLS state tuple,
retransmits, gap, duration, byte counts, directionality.

**Cross-session deviation (the signal):** deviation of this session's TLS-upgrade behaviour from its
server baseline; from its client baseline; from its pair+proto baseline; temporal change vs prior
history; upgrade-rate distance. These are computed by stage [5] and fed to stage [6].

**Excluded by rule:** attacker-controlled email body / header text (Phase-11 §13, 06 threat model).
Including it invites poisoning and prompt-injection-style manipulation of the model.

## 5. Experiment plan (Phase-11 §11 — run before selecting a model)

**Corpus (diversity-controlled to prevent generator-learning, Phase-11 §12):**
- Extend the OQ-28 corpus with **≥2 distinct generators** (our crafter + real Postfix/Dovecot via
  OQ-33r) and **randomised parameters** (banner text, capability ordering, timing, cipher sets).
- **Train/test split by generator and by scenario**, never by random session. A model that only works
  when train and test share a generator is rejected.
- Held-out adversarial scenarios (stripping variants, injection, truncation) unseen in training.

**Protocol:** unsupervised fit on "normal" sessions only; score all; compare bands to ground truth
(held separate). For each candidate report: TP/FP/FN/TN, precision, recall, F1, FPR, **PR-AUC** (not
accuracy — imbalanced), anomaly-score distributions, **seed stability** (≥5 seeds), sensitivity to
history size / protocol / truncation.

**The decisive metric** (not raw accuracy): *does the model flag genuine issues the deterministic
engine missed, without raising more false positives than it removes?* This is the complementary-value
test 10B §9 applied; a model that merely re-derives the rules is rejected as redundant.

**Success / kill criteria:**
- ✅ Select a model if it adds complementary detections at acceptable FPR, stable across seeds, and
  survives generator-held-out evaluation.
- 🟡 If no model adds detections but one is stable and low-FP, ship it as a **secondary prioritisation
  signal** with the limitation documented (A-02 still satisfied by a real technique).
- ❌ If every candidate is worse than the baseline *and* unstable, escalate (Phase-11 §36 stop
  condition) rather than ship a bad model.

## 6. Data leakage & synthetic risk (Phase-11 §12)

The central risk: learning our own traffic generator. Controls: multi-generator corpus, parameter
randomisation, generator/scenario-held-out test split, real-server data (OQ-33r), and reporting
performance **separately** on same-generator vs cross-generator test sets. If cross-generator
performance collapses, we say so.

## 7. AI security boundary (Phase-11 §14, from 10B)

ML **may** output: `anomaly_score`, `anomaly_band`, `feature_contributions`, `model_version`,
`training_context`. ML **may not**: modify packet evidence, protocol state, findings, or capture
completeness; invent certs/packets; convert UNKNOWN/INFERRED→OBSERVED; declare an attack; override the
deterministic engine. The two lanes meet only at prioritisation (07), via an explicit policy.

## 8. Open questions

OQ-36 (which model wins the bake-off — pending the corpus) · OQ-37 (does any model add complementary
value on cross-generator data, or is the honest answer "prioritisation signal only"?) · depends on
OQ-33r (real-server corpus).
