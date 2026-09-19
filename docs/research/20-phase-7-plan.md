# 20 — Phase 7 Plan: Evidence Fusion + Security Posture Engine

**Date:** 2026-09-20 · **Branch:** `phase/07-evidence-fusion-posture` from `2db283c`
**Status:** Plan, written before implementation.

---

## 1. Architecture inventory (what already exists)

Established by targeted inspection of the Phase 2–6 source, not from memory.

### A. `SecurityFinding` (Phase 4, `analysis/model.py`)

`finding_id · rule_id · title · status · severity · conclusion · explanation · standards ·
capture_id · tcp_stream_id · protocol · stream_key · first_frame · last_frame ·
timestamp_epoch · evidence_refs · remediation · limitations · rules_version ·
engine_version`

Invariants enforced at construction:
- a non-assertive status (`AMBIGUOUS`, `INSUFFICIENT_EVIDENCE`, `NOT_OBSERVABLE`,
  `COMPLIANT`, `INFORMATIONAL`) may not carry severity above `INFO`;
- `OBSERVED_ISSUE` must cite a standards basis;
- every finding must reference evidence.

### B. `CrossSessionFinding` (Phase 5, `crosssession/model.py`)

Reuses Phase-4 `Severity`, `FindingStatus` and `EvidenceRef` — it does **not** duplicate
them. Adds `deviation` (`NONE` / `DEVIATION` / `SUSPICIOUS_DEVIATION` / `NOT_ASSESSED`)
and the comparison provenance: `comparability`, `baseline`, `contrast`, plus
`subject_stream_key`.

### C. `MLAnomalyResult` (Phase 6, `ml/contract.py`)

`session_key · capture_id · model_id · model_version · feature_schema_version ·
anomaly_score · threshold · band · top_features · basis · model_artifact_hash ·
layout_signature`. Carries **no** severity, status or standards field, by design.

### D. Evidence states

`OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE`
(`evidence/states.py`). All six reachable; all six semantically distinct.

### E. Provenance already available

`EvidenceRef.frames` · finding `first_frame`/`last_frame` · `Baseline.members`
(`SessionRef` with stream key, frame, timestamp, membership reason) ·
`ContrastResult.control_sessions` · capture SHA-256 on `Capture` ·
`ModelArtifact.artifact_hash` + `layout_signature`.

### F. Standards currently in use — **five, all Phase-4 verified**

| Constant | Text |
|---|---|
| `RFC8996` | RFC 8996 (BCP 195) §4–5: TLS 1.0 and TLS 1.1 MUST NOT be used |
| `NIST_52R2` (tls) | NIST SP 800-52r2 §3.1: shall use TLS 1.2, should use 1.3, … |
| `NIST_52R2` (plaintext) | NIST SP 800-52r2 §3.1 (TLS required to protect transmitted data) |
| `RFC3207` | RFC 3207 §6 (SMTP STARTTLS security considerations) |
| `RFC2595` | RFC 2595 (STARTTLS for IMAP and POP3) |
| `RFC8314` | RFC 8314 §3 / implicit TLS for submission and access |

⚠️ **Defect noted:** `NIST_52R2` is defined **twice** with different text
(`tls_rules.py:28`, `plaintext_rules.py:21`). Standards are free-text strings with no
structure. Phase 7 will add a *read-only registry* that maps these exact strings to
structured `(standard, section, reason)` records. **No new standard is introduced and no
existing string is edited** — the rules keep emitting exactly what they emit today.

### G. Severity vocabulary

`INFO · LOW · MEDIUM · HIGH · CRITICAL`. `LOW` is currently emitted by no rule.
Phase 7 **reuses this vocabulary unchanged**.

### H. Rule inventory (11 rules) and their asserting severities

| Rule | Issue severity when `OBSERVED_ISSUE` |
|---|---|
| `SEC-TLS-001` | SSL2.0/SSL3.0 → CRITICAL; TLS1.0/TLS1.1 → HIGH |
| `SEC-TLS-002` | never asserts (COMPLIANT / AMBIGUOUS / INSUFFICIENT) |
| `SEC-TLS-003` | never asserts (`NOT_OBSERVABLE` — certificate boundary) |
| `SEC-STLS-001` | MEDIUM (upgrade requested but not achieved) |
| `SEC-STLS-002` | never asserts (INFORMATIONAL / AMBIGUOUS / INSUFFICIENT) |
| `SEC-STLS-003` | never asserts (INFORMATIONAL — implicit TLS) |
| `SEC-PLAIN-001` | HIGH (authentication without TLS) |
| `SEC-PLAIN-002` | MEDIUM (session carried no TLS) |
| `CS-STARTTLS-001` | MEDIUM (suspicious deviation, contrast-supported) |
| `CS-STARTTLS-002` | never asserts (AMBIGUOUS deviation) |
| `CS-TLS-001` | MEDIUM (version deviation from baseline) |

### I. What may contribute to a posture penalty

**Only `FindingStatus.OBSERVED_ISSUE`**, from either the deterministic or the
cross-session lane. Nothing else.

### J. What must remain non-scoring

`COMPLIANT` (positive evidence — contributes to coverage, never to score),
`INFORMATIONAL`, `AMBIGUOUS`, `INSUFFICIENT_EVIDENCE`, `NOT_OBSERVABLE`, and every
`AnomalyBand`. These become **abstentions** and **coverage**, never penalties and never
credits.

### K. Trust boundaries

```
raw evidence → deterministic rules → findings
                                       ↓
                     cross-session comparison (baselines, contrast)
                                       ↓
                       optional ML signal (score only)
                                       ↓
                                   FUSION  ← Phase 7 adds this
                                       ↓
                                  POSTURE
```
The arrow never reverses. Phase 7 adds nothing upstream of fusion.

### L. Concepts to reuse, not re-create

`Severity`, `FindingStatus`, `EvidenceRef` (already shared by Phases 4 and 5);
`crosssession.baseline._order` for total deterministic ordering; `PopulationIndex` for
population grouping. Phase 7 introduces **no second finding model** — `FusedFinding`
*references* existing findings, it does not replace them.

---

## 2. Design decisions to be made in this phase

### 2.1 Fusion identity — the deduplication key

Finding ids are unique per instance, so they cannot be the dedup key. Fusion keys on a
**content-derived issue identity**:

```
IssueKey = (issue_class, scope_key)
```

where `issue_class` is a stable mapping from `rule_id` and `scope_key` is the session
`stream_key` (session scope) or the endpoint (population scope). Three findings
describing the same underlying fact therefore collapse into **one** `FusedFinding` whose
`sources` list holds all three, preserving every provenance record.

### 2.2 Three fact kinds that must not collapse into each other

| Kind | Source | Meaning |
|---|---|---|
| `BASE_SECURITY_ISSUE` | deterministic `OBSERVED_ISSUE` | a standards-bound weakness |
| `BEHAVIOURAL_DEVIATION` | cross-session finding | behaviour differs from a baseline |
| `ANOMALY_SIGNAL` | ML result | statistically unlike learned normal |

A deviation *enriches* a base issue; it never becomes one, and it never becomes an
attack. Relations: `SUPPORTS`, `ENRICHES`, `DUPLICATES`, `CONTEXTUALIZES`,
`PRIORITIZES`, `CONTRADICTS`, `ABSTAINS`.

### 2.3 Three orthogonal dimensions (must not be collapsed)

| Dimension | Values | Source |
|---|---|---|
| **Severity** | INFO…CRITICAL | the rule |
| **Evidence certainty** | CONFIRMED / PROBABLE / UNCERTAIN / UNDETERMINED | evidence states of the refs |
| **Observability** | OBSERVABLE / PARTIALLY_OBSERVABLE / NOT_OBSERVABLE | the capture |

Severity is **never** reduced because certainty is low. A missing certificate is
`NOT_OBSERVABLE`, not `LOW` risk.

### 2.4 Scoring — three candidates, to be evaluated empirically

To be run over the OQ-25, OQ-28 and Phase-6 corpora **before** one is chosen:

- **F1 instance penalty** — `100 − Σ weight(severity)` per issue instance.
- **F2 group penalty with damped recurrence** — group by issue class;
  `penalty = weight(severity) × (1 + log₂(affected_sessions))`, capped.
- **F3 worst-dominant** — `100 − worst_penalty − damped_sum(remaining)`.

Evaluated on: monotonicity, duplicate resistance, severe-finding sensitivity, behaviour
under incomplete evidence, benign-variation stability, explainability. Simplest
defensible formulation wins; if none is defensible, ship bands over a transparent
penalty measure and say so. Recorded in ADR-0016.

**Hard constraint:** the score must never reward missing evidence. A capture with no
observable TLS must not score the same as one with observed TLS 1.3.

### 2.5 ML boundary

`robust-z-sum` is a **secondary prioritisation signal only** (ADR-0015, Outcome D: zero
unique true detections on every held-out split). In Phase 7 it may influence **ordering
within a severity tier** and nothing else. It cannot create, remove, or re-severity a
finding; `--no-ai` must produce byte-identical findings, risk and score.

---

## 3. Pre-existing defects — decision

Both were found in Phase 6 and are recorded in `docs/architecture/16` §9.

| # | Defect | Affects posture correctness? | Decision |
|---|---|---|---|
| 1 | `Completeness.TRUNCATED` never assigned by `session/base.py:_finalise`, so the Phase-5 comparability guard is dead code | **No, but it is visible.** Truncated sessions report `INCOMPLETE` and so still enter baselines. The posture layer surfaces completeness in evidence coverage, making the effect observable rather than hidden. | **DEFER.** Changing it alters Phase-3/5 deterministic semantics and needs its own regression run. Tracked as OQ-46. |
| 2 | TCP-segmented multi-line SMTP `250-` replies can lose `STARTTLS` | **No.** The failure direction is fail-safe: it yields `AMBIGUOUS`, which the posture engine treats as an abstention, never as a compliant or a secure state. | **DEFER.** Tracked as OQ-47. |

Neither is fixed in this phase. Burying a Phase-3 change inside the posture engine is
exactly what the brief forbids, and neither defect can cause the posture engine to
report a weakness as secure.

---

## 4. Module plan

```
src/securemailscope/posture/
├── model.py         canonical contracts: IssueClass, FactKind, Relation,
│                    EvidenceCertainty, Observability, SourceRef, FusedFinding,
│                    IssueGroup, Abstention, RemediationGuidance, EvidenceCoverage,
│                    ProtocolPosture, PostureBand, PostureAssessment
├── standards.py     read-only registry mapping existing standard strings to
│                    structured (standard, section, reason). Adds nothing new.
├── fusion.py        FusionEngine: findings + cross-session + ML -> FusedFinding[]
├── risk.py          RiskClassifier (A-01 elevation): dimensions + certainty
├── scoring.py       candidate formulas + the selected one, decomposable
├── prioritise.py    PriorityRanker (A-04)
├── remediation.py   rule-bound remediation templates (A-05)
└── engine.py        PostureEngine -> PostureAssessment
```

Tests: `tests/test_posture_model.py`, `test_posture_fusion.py`, `test_posture_scoring.py`,
`test_posture_engine.py`, `test_posture_adversarial.py`, `test_posture_corpora.py`.

Experiment: `research/experiments/oq48/score_review.py` — the scoring bake-off.

## 5. Commit plan

1. `docs: add phase 7 plan` (this file)
2. `feat: add posture contracts and evidence fusion`
3. `feat: add risk classification and posture scoring`
4. `feat: add prioritisation and remediation`
5. `test: add posture adversarial and corpus coverage`
6. `docs: document posture architecture and scoring ADR`

## 6. Explicit non-goals

No LLM · no frontend · no PDF/HTML reporting · no SPF/DKIM/DMARC/DNS · no certificate
conclusions beyond observability · no Phase-3 refactor · no change to any Phase 2–6
deterministic output.
