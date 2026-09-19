# 17 — ML Model Evaluation (Phase 6)

**Status:** Complete · **Date:** 2026-09-19 · **Decision:** ADR-0015
**Reproduce:** `python3 research/experiments/oq36/{genb,genc,dataset,bakeoff,probes}.py`
**Raw results:** `research/experiments/oq36/results/{dataset-inventory,bakeoff,probes}.json`

---

## 1. Headline

> **No candidate model produced a single unique true detection on any held-out split.**
> The shipped model adds nothing the deterministic and cross-session lanes do not
> already have, and the feature space is **98.6 % separable by generator**, which means
> the synthetic corpus cannot settle the question at all.

This is **Outcome D** of the Phase-6 brief: *"current corpus cannot justify a reliable
model"*. A real, unsupervised, reproducible, explainable technique exists and is
integrated as a **prioritisation signal**; no detection claim is made for it.

## 2. What was already known, and what Phase 6 adds

`10B §9` rejected Isolation Forest on **7 crude per-session binary features**: 2/32
attacks against the deterministic engine's 8/32, with more false positives. That
experiment could not separate two explanations — bad model, or bad features.

Phase 6 separates them. With a 44-feature, 164-column, evidence-aware, leakage-governed
feature layer including cross-session deviation features, **Isolation Forest again
produced zero true detections** (§5). The 10B result was not an artifact of its features.

## 3. Dataset (§10, §30)

Three generators, each authored independently, each run through the **real** pipeline
(`analyze_capture` → `reconstruct_sessions` → Phase-5 context → features).

| Generator | Dialect | Captures | Sessions | Attacks | Clients | Servers |
|---|---|---:|---:|---:|---:|---:|
| **A** `oq28/craft.py` | Postfix-modelled | 25 | 142 | 32 | 5 | 2 |
| **B** `oq36/genb.py` | Exim / Sendmail | 16 | 576 | 80 | 4 | 2 |
| **C** `oq36/genc.py` | Zimbra / Dovecot | 19 | 666 | 80 | 4 | 2 |
| **Total** | | **60** | **1,384** | **192** | | |

Generators B and C differ structurally, not cosmetically: address plan, port mix,
banner dialect, capability ordering, TLS version mix, `legacy_session_id` handling,
cipher offers, extension ordering, segmentation strategy (B splits messages randomly; C
emits one line per packet with explicit ACKs), timing model, and teardown (FIN / RST /
genuine mid-session truncation).

Protocol coverage: SMTP, IMAP, POP3, and implicit TLS on 465/993/995. TLS versions 1.0
through 1.3. 35 of 1,384 sessions abstain (see §8).

### Labels

`ATTACK_STRIP_ADVERT` and `ATTACK_STRIP_COMMAND` are the only attack labels. Weak TLS,
failed upgrades and server-side refusals are **benign** — they are real security
problems but not manipulation, and conflating "insecure" with "manipulated" would make
the evaluation meaningless.

Labels are used **for evaluation only**. No fitting step receives them, and the
threshold is selected from normal-session scores without reference to any attack.

## 4. Splits and leakage controls (§11, §12)

| Split | Source | Sessions | Attacks (blind) | Role |
|---|---|---:|---:|---|
| `TRAIN` | gen B, train scenarios, **normals only** | 396 | 0 | unsupervised fit |
| `VAL` | gen C, val scenarios, **normals only** | 240 | 0 | threshold |
| `SELECT` | gen B, **held-out scenarios** | 150 | 50 (40) | model selection |
| `TEST_C` | gen C, held-out scenarios | 426 | 80 (40) | cross-generator test |
| `TEST_A` | gen A, all | 142 | 32 (6) | cross-generator test |

**Measured integrity** (`dataset-inventory.json`):
- Feature rows also present in `TRAIN`: **0** in every split.
- Scenario overlap with `TRAIN`: **none**.
- Capture overlap with `TRAIN`: **none**.
- Generators B and C share no client or server IP and no scenario id (asserted by test).

**"Blind" attacks** are scenarios where every client at the endpoint is stripped, so no
unaffected control exists. 02A/02B established these are undetectable from the capture
alone (FN 30/30). Every recall figure is reported **excluding** them (`rec*`) so a
known-impossible case does not silently depress the numbers.

## 5. Bake-off (§14, §15, §17, §18)

Fit on `TRAIN` → threshold from `VAL` at the declared operating point **q = 0.98** →
score the three held-out splits. Thresholds were swept over q ∈ {0.90, 0.95, 0.98, 0.99}
and the full sweep is in `bakeoff.json`; the operating point was declared before any
test split was scored.

**Selection rule**, declared in advance: a **label-free usability gate** (flag rate ≤ 10 %
of held-out traffic — a forensic tool that flags most of a capture has found nothing,
and flag *counts* need no labels), then PR-AUC excluding blind attacks on `SELECT`.
Held-out labels were not consulted for any choice.

| Model | SELECT PR | TEST_C PR | TEST_A PR | flag rate S/C/A | Gate |
|---|---:|---:|---:|---|---|
| lof | **0.515** | 0.246 | 0.217 | 0.00 / 0.04 / **0.87** | ❌ rejected |
| **robust-z-sum** | **0.445** | **0.436** | 0.298 | 0.00 / 0.00 / 0.00 | ✅ **selected** |
| isolation-forest | 0.253 | 0.169 | 0.242 | 0.00 / 0.01 / 0.01 | ✅ |
| mean-distance | 0.240 | 0.368 | 0.217 | 0.00 / 0.00 / 0.13 | ❌ rejected |
| ocsvm | 0.223 | 0.389 | 0.217 | 0.00 / 0.03 / 0.00 | ✅ |
| robust-covariance | 0.206 | 0.367 | **0.479** | 0.00 / **0.18** / 0.04 | ❌ rejected |
| robust-z-k10 | 0.118 | 0.190 | 0.296 | 0.00 / 0.02 / 0.00 | ✅ |
| robust-z-k3 | 0.091 | 0.190 | 0.307 | 0.00 / 0.02 / 0.00 | ✅ |
| robust-z-k5 | 0.091 | 0.190 | 0.296 | 0.00 / 0.02 / 0.00 | ✅ |

### The result that matters most

**LOF, the best model by same-generator selection, flags 86.8 % of the independently
authored generator-A corpus.** Selecting on the training generator's own scenarios does
not transfer. Without the label-free gate, a 0.515 PR-AUC would have shipped a model
that calls almost everything anomalous.

**Seed stability:** the shipped model is deterministic by construction; across seeds
{11, 23, 42, 101, 2026} its recall, FPR and PR-AUC have range **0.000**.

## 6. Independent value (§19) — the decisive experiment

Identical populations, five systems, at the declared operating point.

| Split | A deterministic | B cross-session | C ML only | E cross+ML | **ML-only sighted attacks** |
|---|---|---|---|---|---:|
| SELECT (150) | tp 50, fp 40 | tp 1, fp 0, rec\* 0.100 | tp 0, fp 0 | tp 1, fp 0 | **0** |
| TEST_C (396) | tp 80, fp 89 | tp 15, fp 0, rec\* 0.375 | tp 0, fp 0 | tp 15, fp 0 | **0** |
| TEST_A (137) | tp 32, fp 39 | tp 1, fp 0, rec\* 0.038 | tp 0, fp 0 | tp 1, fp 0 | **0** |

> **The ML column is empty. On every held-out split, adding ML changes nothing.**

### Read `A_deterministic` carefully — it is not what it looks like

`A_deterministic` counts any `OBSERVED_ISSUE`, and in this corpus that is dominated by
`SEC-PLAIN-*` firing on cleartext credentials. Every stripped session carries cleartext
credentials — and so does every *legitimate* cleartext session, which is why its false
positives run 39–89 at FPR 0.28–0.37.

Its apparent recall of 1.000 is **not detection of stripping**. It is detection of
cleartext, which this corpus's attack labels happen to correlate with perfectly. Quoting
it as "the deterministic engine detects 100 % of attacks" would be an artifact of corpus
design, not a capability.

The honest opponent is **`B_cross_session`**, which is what Phase 5 shipped to separate
manipulation from configuration: **precision 1.000, zero false positives, recall\* 0.375
on TEST_C**. That is the bar ML had to clear, and did not.

## 7. Anti-circularity (§20)

| Configuration | Split | ML flagged | Rules flagged | Jaccard | ML-only | ML-only attacks |
|---|---|---:|---:|---:|---:|---:|
| with CONTEXT | TEST_C | 0 | 169 | 0.000 | 0 | 0 |
| with CONTEXT | TEST_A | 0 | 71 | 0.000 | 0 | 0 |
| without CONTEXT | TEST_C | 5 | 169 | 0.030 | 0 | 0 |
| without CONTEXT | TEST_A | 0 | 71 | 0.000 | 0 | 0 |

The model is **not** re-deriving the rules engine — overlap is essentially zero. But the
diagnosis is not favourable either: it is looking somewhere else and finding nothing
useful there. Low overlap plus zero unique true detections is not independence, it is
absence of signal.

## 8. Abstention

35 of 1,384 sessions are never scored: 30 in `TEST_C` (the purpose-built truncated
scenario `C19_truncated`) and 5 in `TEST_A`. Every one abstains because completeness is
not `COMPLETE`.

This is the direct countermeasure to 10B's distinctive failure, where the model's only
distinguishing output was re-flagging truncated captures.

## 9. Feature ablation (§31)

PR-AUC excluding blind attacks, shipped model, re-extracted per configuration.

| Configuration | Columns | SELECT | TEST_C | TEST_A |
|---|---:|---:|---:|---:|
| A protocol only | 67 | 0.348 | 0.603 | 0.349 |
| B TLS only | 39 | 0.333 | 0.370 | 0.456 |
| C **context only** | 30 | **0.133** | **0.113** | **0.162** |
| D **all (shipped)** | 164 | 0.445 | 0.436 | 0.298 |
| E **all minus context** | 134 | **0.496** | **0.643** | 0.340 |
| F all minus structure | 146 | 0.295 | 0.609 | 0.344 |
| G all minus cipher | 152 | 0.445 | 0.436 | 0.298 |

### Two findings, one of them uncomfortable

**The CONTEXT group actively hurts.** Removing it improves PR-AUC on the selection split
(0.445 → 0.496) *and* on both held-out splits (0.436 → 0.643 on TEST_C). Context-only is
the worst configuration by a wide margin.

This **contradicts ADR-0006 and architecture doc 05 §4**, which predicted cross-session
deviation features would be "the signal" and that infrastructure-relative space is
"exactly where the model should look". On this corpus they are noise.

**The shipped configuration was deliberately not changed.** The declared protocol
selected a *model*, not a feature set; re-fitting the feature set after seeing the
ablation would be a second bite at the same data. The gain is in ranking quality of a
signal that detects nothing either way, so there is no practical cost to waiting.
Dropping CONTEXT under a freshly declared protocol is the top Phase-7 recommendation.

**Cipher makes no difference** (G ≡ D), so the MEDIUM-risk `tls_cipher` feature can be
dropped with no loss.

## 10. Generator artifact (§32) — the finding that limits everything else

A RandomForest was trained to predict *which generator produced a session* from the
feature vector alone. This classifier is a **diagnostic** and is never shipped —
generator identity is a forbidden model input.

| Feature space | 5-fold CV accuracy | Majority baseline | Verdict |
|---|---:|---:|---|
| Full (164 columns) | **0.986** | 0.525 | **SEPARABLE** |
| Minus STRUCTURE, `port_class`, `tls_cipher` (86 columns) | **0.747** | 0.525 | **still separable** |

Top separating columns, full space: `duration_s` (0.173), `frame_span` (0.170),
`packet_count_log` (0.158), `port_class=smtp` (0.079), `events_per_packet` (0.068) —
**56 % of importance in the STRUCTURE group alone.** These are precisely the features the
schema had already classified MEDIUM leakage risk, which is the feature-governance
design working as intended.

**Consequence:** on this corpus "cross-generator generalisation" is partly a measurement
of generator recognition. Any positive ML result here would have to be discounted; the
negative result is, if anything, strengthened. **This question cannot be settled on
synthetic data.** OQ-33r (real multi-vendor traffic) is the blocker, and no amount of
additional synthetic generators fixes it.

## 11. Benign variation (§21)

False positives on legitimate-but-unusual traffic — the population a naive "anything
different is anomalous" model destroys itself on.

**Overall: 6 / 332 = 1.8 %.**

| Scenario | Flagged | FP rate |
|---|---|---:|
| C16 implicit POP3S | 6 / 30 | **0.200** |
| B08 / C10 legitimate config change mid-capture | 0 / 72 | 0.000 |
| B09 / C09 heterogeneous legitimate clients | 0 / 80 | 0.000 |
| B16 / C17 obsolete TLS, legitimately negotiated | 0 / 60 | 0.000 |
| C07 server refuses a requested upgrade | 0 / 30 | 0.000 |
| C18 abrupt RST teardown | 0 / 30 | 0.000 |

The model correctly ignores legitimate reconfiguration, client diversity and weak-but-
legitimate TLS — the classic false-positive sources. **It does not handle implicit
POP3S**, flagging 20 % of it, because implicit TLS is thinly represented in training and
its feature profile differs structurally (no upgrade behaviour at all). A real, reported
weakness.

## 12. Performance (§34)

| Stage | Cost |
|---|---|
| Feature extraction incl. Phase-5 context | 0.187 ms/session |
| Fit (396 × 164) | 4.6 ms |
| Scoring | 0.020 ms/session |
| End-to-end (context + score + explain) | 0.185 ms/session |

Not a constraint. No optimisation attempted.

## 13. Threats to validity

1. **The corpus is entirely synthetic**, and 98.6 % generator-separable (§10). This is
   the dominant threat and it bounds every other result.
2. **Generators B and C were authored in the same project.** Structurally different, but
   not independent in the way two real vendors' servers are.
3. **`SELECT` contains only 10 non-blind attacks**, all `ATTACK_STRIP_COMMAND`. Model
   selection rests on a thin labelled set.
4. **`A_deterministic`'s recall is a label-correlation artifact** (§6), not a capability.
5. **Attack labels cover two manipulation families only.** Nothing here speaks to
   certificate abuse, renegotiation or downgrade families the corpus does not contain.
6. **Absence of evidence.** These results show no value *on this corpus*. They do not
   prove no ML approach can add value on real traffic.

## 14. Answers to the ADR-0006 open questions

- **OQ-36 (which model wins?)** — **Closed.** None wins on detection. `robust-z-sum`
  ships as a prioritisation signal on operational and ranking grounds.
- **OQ-37 (complementary value?)** — **Closed, negative.** Zero unique true detections
  on all three held-out splits.
- **New OQ-45** — does real multi-vendor traffic change the answer? Unanswerable on
  synthetic corpora, per §10. Blocked on OQ-33r.
