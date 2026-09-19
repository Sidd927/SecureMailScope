# ADR-0015 — ML ships as a prioritisation signal, not a detector
**Status:** Accepted 2026-09-19 · **Supersedes the open parts of:** ADR-0006 (OQ-36, OQ-37)

**Context** Phase 6 executed the ADR-0006 bake-off: a leakage-controlled feature layer,
three independently authored generators, generator- and scenario-held-out splits, nine
candidate configurations, and the §19 independent-value comparison.

**Problem** Which model ships, in what role, given what the evaluation actually showed?

**Evidence** (all from `docs/architecture/17`, reproducible from
`research/experiments/oq36/`)
- **No candidate produced a single unique true detection on any of the three held-out
  splits.** The shipped model's ML-only column is empty on SELECT, TEST_C and TEST_A
  alike; adding it to the cross-session lane changes tp, fp and recall by zero.
- **The feature space leaks generator identity**: a classifier separates generators B
  and C at **98.6 %** accuracy against a 52.5 % majority baseline; after removing the
  STRUCTURE group, `port_class` and `tls_cipher` it is still **74.7 %** separable.
- **Same-generator selection does not transfer**: LOF, the best candidate by
  selection-split PR-AUC (0.515), flags **86.8 %** of the independently authored
  generator-A corpus.
- **The CONTEXT group actively hurts.** Removing it raises PR-AUC on the selection
  split (0.445 -> 0.496) and on both held-out splits (0.436 -> 0.643 on TEST_C),
  contradicting ADR-0006's expectation that cross-session deviation features would be
  "the signal".
- Isolation Forest, re-tested with a proper feature layer, again produced **zero** true
  detections — confirming 10B §9 was a model-level result, not only a feature-level one.

**Decision** Ship `RobustZScoreModel(aggregate="sum")` as a **secondary prioritisation
signal only**, in a lane that emits a score, a band and a feature attribution, and never
a finding. A-02 is satisfied by a real, evaluated, unsupervised technique; no detection
claim is made for it. The deterministic and cross-session lanes remain the sole source
of security conclusions.

**Rejected**
- *Ship a detector.* No evidence supports the claim; the strongest apparent candidate
  fails catastrophically off its own generator.
- *LOF / robust-covariance / mean-distance.* Rejected by a label-free usability gate
  (flag rate <= 10 % of held-out traffic): 86.8 %, 18.4 % and 13.1 % respectively. LOF
  had the BEST selection-split PR-AUC (0.515), which is exactly why the gate exists.
- *Isolation Forest.* Passes the gate and wins nothing; retained only as an optional
  benchmark.
- *Drop ML entirely.* The PS requires AI/ML (A-02) and a properly evaluated technique
  with an honest limitation is a truthful answer to it; a silent omission is not.
- *Lower the threshold until recall appears.* That is tuning to the test set.

**Consequences** + a real unsupervised component with reproducible artifacts,
explanations and abstention; + the `--no-ai` equivalence property is testable and tested;
+ the negative result is itself defensible evidence for the pitch; + two defects in the
feature layer and two in earlier phases were surfaced by the evaluation. − A-02 remains
**partially** satisfied: capability exists and is evaluated, but demonstrated detection
value does not. − the ML lane currently adds latency (~0.19 ms/session) for a signal that
changes no verdict.

**Risks** Presenting a prioritisation signal as detection would be the exact overclaim
this project exists to avoid → the contract type carries no severity or status field, and
tests assert the emitted text never asserts an attack.

**Open questions** OQ-36 **closed** (no model wins; robust-z ships as a signal).
OQ-37 **closed, negative** (no complementary detection value demonstrated). New: OQ-45 —
does real multi-vendor traffic (OQ-33r) change the answer? The generator-separability
result means this cannot be settled on synthetic corpora at all.
