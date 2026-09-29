# 18 — ML Model Catalog (Phase 6)

**Status:** Current · **Date:** 2026-09-19 · **Evidence:** `17-ml-model-evaluation.md`
**Decision:** ADR-0015

Every candidate evaluated in the Phase-6 bake-off, retained or rejected, with the reason.
All were fitted on the same 396 training rows, thresholded on the same 240 validation
rows at q = 0.98, and scored on the same held-out splits.

---

## Retained

| Model | Role | Implementation | Result | Decision | Reason |
|---|---|---|---|---|---|
| **`robust-z-sum`** — robust z-scores (median/MAD), total-deviation aggregate | **Secondary prioritisation signal.** Default in `AnomalyEngine`. Never a detector. | `ml/models.py`, stdlib only | SELECT PR-AUC **0.445** (best among gated), TEST_C **0.436**, TEST_A 0.298. **0 unique true detections on every split.** Benign-variation FP 1.8 %. Seed range 0.000. | ✅ **Ship, labelled as a signal** | Best gated ranking; only candidate that is stdlib-only, natively explainable per feature, and deterministic. Satisfies A-02 with a real technique without claiming detection. |
| `isolation-forest` | Optional benchmark | `ml/sklearn_models.py` | SELECT 0.253, TEST_C 0.169. **0 true detections**, 4 FPs total. | 🟡 **Retain, not default** | Passes the gate but wins nothing. Kept so the 10B comparison stays runnable. Requires scikit-learn. |
| `ocsvm` | Optional benchmark | `ml/sklearn_models.py` | SELECT 0.223, TEST_C **0.389**. Flag rate ≤ 0.03. | 🟡 **Retain, not default** | Strong TEST_C ranking but weak on the selection split; no native explanation; needs scikit-learn. |
| `robust-z-k3/k5/k10` | Ablation reference | `ml/models.py` | SELECT 0.091–0.118, TEST_C 0.190 | 🟡 **Retain for comparison** | Superseded by the `sum` aggregate. See the saturation defect below. |
| `mean-distance` | Deliberate weak control | `ml/models.py` | TEST_C PR-AUC 0.368 — **higher than Isolation Forest's 0.169** | 🟡 **Retain as a control** | Its job is to show when a sophisticated model is not earning its complexity. It did. |

## Rejected

| Model | Result | Decision | Reason |
|---|---|---|---|
| **`lof`** | Best SELECT PR-AUC (**0.515**) — and flags **86.8 %** of generator A | ❌ **Rejected by the usability gate** | The most instructive failure in the phase: same-generator selection did not transfer at all. A tool that flags 6 sessions in 7 has found nothing. |
| **`robust-covariance`** (EllipticEnvelope) | TEST_A PR-AUC 0.479 (highest), but flag rate 0.184 on TEST_C | ❌ **Rejected by the usability gate** | Also emits singular-covariance warnings: 164 columns on 396 rows violates its elliptical assumption outright. Its apparent strength is numerically untrustworthy. |
| **Autoencoder** | Not implemented | ❌ **Not evaluated** | 396 training rows. Architecture doc 05 §3 deprioritised it on data grounds and §30 confirms nothing changed. Building it for appearance would be exactly what the brief forbids. |
| **Supervised attack classifier** | Not implemented | ❌ **Rejected by design** | Would train on labels our own rules produce — the circular trap three of five audited competitors fell into (01D §6). |
| **Temporal drift model** | Not implemented | ❌ **Deferred** | Needs longitudinal captures the corpus does not contain. Revisit with OQ-33r. |

## Feature-set variants (not models)

| Variant | SELECT | TEST_C | TEST_A | Status |
|---|---:|---:|---:|---|
| All features (shipped) | 0.445 | 0.436 | 0.298 | ✅ current |
| **All minus CONTEXT** | **0.496** | **0.643** | 0.340 | 🔜 **Phase-7 recommendation** |
| All minus `tls_cipher` | 0.445 | 0.436 | 0.298 | Identical — feature can be dropped free |
| Context only | 0.133 | 0.113 | 0.162 | Worst configuration measured |

Dropping CONTEXT wins on the selection split as well as both test splits, so the
recommendation does not rest on held-out data. It was **not applied in Phase 6** because
the declared protocol selected a model, not a feature set, and re-fitting after seeing
the ablation would be a second pass over the same evidence. Since the configuration
changes no verdict either way, waiting costs nothing.

---

## Defects found and fixed during Phase 6

### 1. `_tri()` let a value override its evidence state — **fixed**

Phase 3 records an absent STARTTLS advertisement as `EvidenceField.ambiguous(False, …)`:
value `False`, state `AMBIGUOUS`, because stripping and genuine non-support are
byte-identical. The first `_tri()` read the value first and handed the model a confident
`false` for the project's single most important undecided fact.

Caught by `test_evidence_states_survive_as_their_own_categories`. `_tri()` now reads the
state first; only `OBSERVED` and `INFERRED` values are reported as decided. All
experiments were re-run after the fix.

### 2. `topk_mean` saturation — **fixed by adding the `sum` aggregate**

On a wide one-hot matrix most columns are constant in training, and every constant-column
deviation is charged exactly `_CONSTANT_NOVELTY = 3.0`. Any session deviating on ≥ `top_k`
constant columns therefore scores **exactly 3.0** — identical to every other such session.
Ranking resolution collapsed precisely where it was needed.

Caught by `test_a_clearly_different_session_scores_above_its_own_population`, where an
obviously anomalous session tied with an ordinary one at 3.0. The `sum` aggregate keeps
counting past the k-th column; it raised SELECT PR-AUC from 0.091 to 0.445 and was then
selected by the declared protocol. `SATURATION_NOTE` records the reasoning in the class.

## Defects found in earlier phases — **reported, not fixed here**

Changing deterministic semantics from inside the ML phase is what §36 forbids. Both need
their own change with their own regression run. Full detail in `16-ml-anomaly-architecture.md` §9.

| # | Defect | Impact | Severity |
|---|---|---|---|
| 1 | `Completeness.TRUNCATED` is never assigned by `session/base.py:_finalise` | The Phase-5 comparability guard at `crosssession/comparability.py:112` is dead code in production; a truncated capture is indistinguishable from one merely lacking a teardown | Medium |
| 2 | A TCP-segmented multi-line `250-` reply can lose `STARTTLS` | Yields `AMBIGUOUS` for a server that plainly advertised. Observed in 2 of 576 generator-B sessions; no security verdict flipped because the sessions still reached `TLS_ESTABLISHED` | Low |

## Governance

Every retained model, when fitted, produces a `ModelArtifact` recording model id, type
and version, library and version, feature schema version, layout signature, training
dataset hash, row/column counts, full config, seed, threshold and the method that chose
it, and UTC training time. `artifact_hash` is a content hash over all of it, and every
`MLAnomalyResult` carries it.
