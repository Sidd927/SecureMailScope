# 16 — ML Anomaly Architecture (Phase 6)

**Status:** Implemented · **Date:** 2026-09-19 · **Decision:** ADR-0015
**Evaluation:** `17-ml-model-evaluation.md` · **Catalog:** `18-ml-model-catalog.md`
**Implements:** the ADR-0006 design, with its open questions now closed by evidence.

---

## 1. The role ML actually plays

> **The ML lane produces an anomaly score and an explanation. It produces no security
> facts, and on the current corpus it changes no verdict.**

That is not a placeholder sentence — it is the measured outcome of §17's evaluation, and
the architecture is built to make it impossible to present the signal as more than it is.

The PS requires AI/ML (A-02: *"AI-assisted anomaly detection for suspicious TLS
sessions"*). Phase 6 delivers a real, unsupervised, reproducible, explainable anomaly
technique — and reports honestly that it did not demonstrate independent detection value
on held-out generators. Both halves of that sentence are load-bearing.

## 2. Pipeline

```
SessionEvidence[]                          (Phase 3)
      │
      ▼
Phase-5 primitives: assess / build_baseline / evaluate_contrast
      │   (measurements — comparability, baselines, contrast; NEVER findings)
      ▼
CrossSessionContext
      │
      ▼
MLFeatureExtractor ──► MLFeatureVector      44 logical features, evidence-aware
      │                (schema v1.0)
      ▼
FeatureEncoder ──────► numeric matrix       164 columns, layout hash 8521f61fe615b9aa
      │
      ▼
AnomalyModel.score()                        higher = more anomalous
      │
      ▼
band + explanation ──► MLAnomalyResult      score · band · top features · basis
```

Module map, all under `src/securemailscope/ml/`:

| Module | Responsibility |
|---|---|
| `features.py` | `FeatureSpec` governance records, `MLFeatureExtractor`, `CrossSessionContext`, `MLFeatureVector` |
| `encoding.py` | `FeatureEncoder` — schema-derived column layout, one-hot, missingness indicators |
| `models.py` | `AnomalyModel` interface, `RobustZScoreModel`, `MeanShiftBaselineModel` (stdlib only) |
| `sklearn_models.py` | Isolation Forest, LOF, One-Class SVM, Elliptic Envelope (optional import) |
| `explain.py` | native attribution, else occlusion |
| `contract.py` | `MLAnomalyResult`, `ModelArtifact`, `dataset_hash` |
| `engine.py` | `AnomalyEngine` — context, abstention, threshold, banding, reporting |

## 3. The leakage boundary (§5)

The extractor's signature is the boundary. It accepts `SessionEvidence` and Phase-5
*derived context*, and nothing else. It has never seen a `SecurityFinding` or a
`CrossSessionFinding`.

Enforced three ways:
1. **Structurally** — `test_ml_package_does_not_import_the_rule_engines` parses every
   module in `ml/` with `ast` and fails on an import of `analysis.*`,
   `crosssession.rules`, `crosssession.model` or `crosssession.engine`.
2. **By naming** — no feature id may contain a rule prefix, a severity, a status or a
   verdict word.
3. **By exclusion list** — `FORBIDDEN_INPUTS` names capture ids, stream keys, IPs,
   ports-as-identity, scenario names, generator ids and labels. None is a feature.

**Why this matters more than it looks:** three of the five competitor codebases audited
in 01D trained a model on their own rules engine's output. One says so in a source
comment. A model fed the rules' answers re-derives the rules and learns nothing.

### The one grey area, named rather than hidden

`contrast_state` is derived by Phase 5 and describes *evidence availability*
(`CONTRAST_SUPPORTED` / `INSUFFICIENT` / `NOT_APPLICABLE` / `AMBIGUOUS`), not a verdict.
It is classified MEDIUM leakage risk and is ablated in §17. The ablation found the whole
CONTEXT group contributes nothing to the shipped model's output, which settles the
concern empirically rather than by argument.

## 4. Evidence-aware features (§7, §9)

Every feature carries a `FeatureSpec` recording source, meaning, leakage risk, missing
policy and — for the single ordinal feature — a written justification for the ordering.

The rule that matters:

> `NOT_OBSERVABLE` ≠ `UNKNOWN` ≠ `AMBIGUOUS` ≠ `false`.

Categorical features carry the evidence state **as its own category**. Numeric features
carry a `<name>__missing` indicator beside a documented neutral fill, so "absent" is
learnable and never confused with "zero".

### A defect this caught during implementation

The first `_tri()` read the value before the state, so Phase 3's
`EvidenceField.ambiguous(False, ...)` — an absent STARTTLS advertisement, the project's
single most important undecided fact — reached the model as a confident `false`. A test
asserting state preservation caught it. `_tri()` now reads the state first: only
`OBSERVED` and `INFERRED` values are reported as decided.

## 5. Encoding (§8)

Column layout is a pure function of `FEATURE_SPECS` and the declared vocabularies, never
of the data, so training and inference agree by construction. The layout is hashed
(`layout_signature`) and recorded in the model artifact.

Categoricals are one-hot — `TLS1.2 = 1, TLS1.3 = 2` never implies magnitude. The single
deliberate ordinal, `tls_version_ordinal`, is justified on the spec: TLS versions are
chronologically ordered and RFC 8996 / NIST SP 800-52r2 deprecate monotonically from the
oldest.

Unknown categorical values route to an explicit `__other__` column. They never create a
column, shift the layout, or raise — an unseen cipher suite in the field must degrade
gracefully.

## 6. Abstention (§9, §28)

The engine returns `NOT_SCORED` — no score at all — when:

- **no mail protocol was identified**: there is no learned normal to compare against;
- **completeness is not COMPLETE**: the session's shape partly reflects where the
  capture begins or ends rather than how the traffic behaved.

The second is aimed directly at the rejected 10B model, whose only distinctive output
was re-flagging truncated captures. A capture artifact is a property of the capture, not
of the traffic. Abstention rates are counted and reported; on generator C, 30 of 426
test sessions abstain.

## 7. Threshold policy (§17)

The threshold is a **false-positive budget**, selected by nearest-rank quantile over
*validation* scores from normal sessions of a generator never used for training. It is
never derived from the data being scored, and `analyse()` cannot move it —
`test_threshold_comes_from_validation_and_scoring_cannot_move_it` asserts this.

Bands are `NORMAL` / `BORDERLINE` / `ANOMALOUS` / `NOT_SCORED`. `BORDERLINE` exists so a
score at 0.999× the threshold is not presented as reassuringly normal.

## 8. Explanation (§23)

Preference order:
1. **Native** — `RobustZScoreModel` reports the per-feature z-scores that produced its
   own score. Exact, not estimated.
2. **Occlusion** — each column differing from the training reference is reset to the
   reference and the row re-scored; the drop is that column's contribution. Capped at 40
   probes.

Every emitted explanation is phrased as **association**, never causation, and every
result's `basis` is asserted by test never to contain "attack", "malicious", "stripped",
"compromise" or "credential theft".

## 9. Two defects in earlier phases that Phase 6 surfaced

Neither is fixed here. Changing deterministic semantics from inside the ML phase is
exactly what §36 forbids, and both need their own change with their own regression run.

### 9.1 `Completeness.TRUNCATED` is unreachable

`session/base.py:_finalise` assigns only `COMPLETE` or `INCOMPLETE`. `TRUNCATED` appears
in the enum and in hand-built test fixtures, but **no real capture can produce it**.

Consequence: the Phase-5 comparability guard at `crosssession/comparability.py:112`
(`if session.completeness is Completeness.TRUNCATED`) is dead code in production, and a
genuinely truncated capture is indistinguishable from one that merely lacks a teardown.
Verified against a purpose-built truncated corpus (`C19_truncated`): every session
reports `INCOMPLETE`.

The ML lane abstains on both values and says why, rather than relying on a rule that
never fires.

### 9.2 Segmented multi-line SMTP replies lose capabilities

When TCP segmentation splits a multi-line `250-` reply, tshark reports two separate
capability responses and Phase 3 evaluates them independently. A `250-STARTTLS` in the
tail can be missed, yielding `AMBIGUOUS` for a server that plainly advertised it.

Observed in 2 of 576 generator-B sessions (`B01_all_upgrade` streams 11 and 38). It is a
genuine robustness gap, not a generator artifact: segmentation of a multi-line SMTP reply
is ordinary on real networks. The affected sessions still reach `TLS_ESTABLISHED`, so no
security verdict flips, which is why it is low-severity rather than none.

## 10. Reproducibility (§24, §25)

`ModelArtifact` records: model id/type/version, library and version, feature schema
version, layout signature, training dataset hash, row and column counts, full config,
seed, threshold and the method that chose it, UTC training timestamp, and evaluation
metadata. `artifact_hash` is a content hash over all of it.

`RobustZScoreModel` is deterministic by construction — its `seed` is accepted and
unused. Across the five bake-off seeds its recall, FPR and PR-AUC have range **0.0**.

## 11. Performance (§34)

| Stage | Cost |
|---|---|
| Feature extraction (incl. Phase-5 context) | **0.18 ms/session** |
| Fit (396 rows × 164 columns) | **4.7 ms** |
| Scoring | **0.021 ms/session** |
| End-to-end analyse (context + score + explain) | **0.19 ms/session** |

No optimisation was needed or attempted.

## 12. Limitations

1. **No demonstrated detection value.** See ADR-0015 and §17.
2. **The corpus is entirely synthetic**, and the generators are 98 % separable by the
   feature vector. Cross-generator results are therefore an upper bound on how much
   generalisation has actually been shown. OQ-33r (real multi-vendor traffic) is the
   blocker.
3. **The CONTEXT group contributes nothing measurable** to the shipped model, contrary
   to the ADR-0006 expectation that cross-session deviation features would be "the
   signal".
4. **Majority poisoning moves the baseline.** Median/MAD resists a single outlier, not a
   corpus that is mostly poisoned. Defence is corpus provenance, not the estimator; the
   limitation is asserted by test so it cannot be forgotten.
5. **Blind stripping stays undetectable** — unchanged from 02A/02B, and no ML changes it.
