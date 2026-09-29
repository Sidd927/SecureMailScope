# ADR-0016 — Content-keyed fusion and a group-damped posture score
**Status:** Accepted 2026-09-20 · **Detail:** `docs/architecture/19` ·
**Evidence:** `research/experiments/oq48/results/score-review.json`

**Context** Phases 4–6 produce three independent output streams. Phase 7 must combine
them into one canonical assessment that the backend, dashboard and reports consume
without recomputing anything, while preserving the evidence discipline the project is
built on.

**Problem** Four decisions: how to deduplicate overlapping findings without over-merging
them; how to score posture defensibly; what "unknown" does to a score; and how much
influence the ML lane gets.

---

## Decision 1 — Fusion keys on content, not on finding ids

`IssueKey = (issue_class, fact_kind, scope_key)`.

**Rejected:** keying on `finding_id` — ids are unique per instance, so deduplication
would be a no-op that looks like it works. **Rejected:** keying on `rule_id` — two rules
describing one condition would never converge, and renaming a rule would silently change
identity. `issue_class` is therefore an explicit map, not parsed from the id.

**Consequence** Three reports of one condition produce one finding and an unchanged
score (measured delta 0.0), while all three sources — including those marked
`DUPLICATES` — keep their ids, frames and evidence refs. Deduplication compresses the
count, never the evidence.

## Decision 2 — Base issues, deviations and anomalies are three fact kinds

`FactKind` is part of the fusion key, so they cannot merge.

**Rejected:** collapsing a cross-session deviation into the base issue it relates to.
That would silently promote "this differs from last time" into "this is a vulnerability"
— the exact overclaim the whole project exists to avoid. A deviation `ENRICHES`; it never
becomes a weakness. An anomaly `PRIORITIZES`; a class invariant makes it structurally
incapable of penalising the score.

## Decision 3 — Scoring: F2-group-damped

```
score = 100 − Σ over penalising groups of  weight(severity) × min(2, 1 + log₂(n)/4)
```

Three candidates were implemented and measured over **60 real captures** plus property
probes before one was chosen.

| Formula | Mean | At 0 | Distinct values | 8 MEDIUM issues | Verdict |
|---|---:|---:|---:|---:|---|
| F1-instance | 36.7 | 37/60 | **5** | 4.0 | ❌ |
| **F2-group-damped** | 53.2 | 1/60 | 16 | 4.0 | ✅ |
| F3-worst-dominant | 61.3 | 0/60 | 16 | **76.1** | ❌ |

**Rejected F1 (linear per-session penalty).** It saturates: 37 of 60 captures pin to
zero and only 5 distinct values exist across the whole corpus. It measures capture
length, not posture — the same server scores differently depending on how much traffic
was recorded.

**Rejected F3 (geometric rank discount).** Eight simultaneous MEDIUM issue classes still
score 76.1 = ADEQUATE. A service with eight distinct moderate problems is not adequate,
and a score that cannot say so is decorative.

**Selected F2.** Passes every property probe — monotonic on a new HIGH issue, monotonic
on recurrence, duplicate-resistant with delta 0.0, registers one CRITICAL among 59 benign
sessions at 45.0, and keeps 10 → 100 sessions cheaper than one additional MEDIUM issue.
It is also the simplest of the three to explain to an analyst: one penalty per problem,
damped by how widely it recurs.

**Rejected: bands only, no number.** The brief permits this if no formulation is
defensible. F2 is defensible and measurably discriminating (16 distinct values), so a
number is reported — accompanied by its full decomposition, which is what makes it
auditable rather than mysterious.

## Decision 4 — Unknown is never compliant, and never rewards the score

**Rejected:** lowering the score when evidence is incomplete. That punishes the capture
rather than the configuration, and would make a good analyst's thorough capture score
worse than a careless one.

**Rejected:** treating "no issue found" as a clean bill of health regardless of coverage.
The score review exposed exactly this hazard: with no coverage supplied, an empty finding
set scored 100/STRONG, making blindness indistinguishable from security.

**Selected:** the arithmetic is untouched, and certification is withheld instead.
`sessions_assessed == 0` yields `INSUFFICIENT_EVIDENCE`; `assessed_fraction < 0.5` keeps
the numeric score but withholds the band. Coverage is reported beside the score, never
folded into it. Scoring is structurally forbidden from reading certainty, observability
or any ML value — enforced by an AST test, not by convention.

## Decision 5 — ML is bounded by arithmetic, not by policy

`MAX_ML_ADJUSTMENT = 4.0`; the narrowest severity gap in the priority model is 30. An
anomaly score can therefore reorder findings within a tier and **cannot** cross one. The
inequality is asserted directly against the tier gaps.

**Rejected:** letting the ML signal modify severity or contribute to the score.
ADR-0015 measured zero unique true detections on every held-out split; a signal with no
demonstrated detection value has no business changing a security fact.

**Rejected:** omitting ML from the posture layer entirely. It is a genuine prioritisation
input, and hiding it would make the `--no-ai` guarantee untestable.

`--no-ai` drops ML results at the top of `assess()`, before fusion, so they cannot reach
scoring or ranking by any path. Verified on fixtures and end to end on a real capture:
score, band, penalising groups, standards and remediation are byte-identical.

## Decision 6 — Contradictions fail closed

When sources sharing a key disagree, the disagreement is recorded, `OBSERVED_ISSUE` is
retained if any source asserts one, certainty drops from `CONFIRMED` to `UNCERTAIN`, and
the reassuring reading is never selected. This is the Phase-4 fail-closed philosophy
applied at the fusion boundary rather than re-derived.

---

**Consequences** + one canonical object for every later phase; + every conclusion traces
to frames, a rule and a standard; + the score is decomposable and reproducible;
+ duplicate and contradictory evidence are handled explicitly. − severity weights and
band thresholds are calibrated policy rather than measurement; − recurrence counts
sessions, so NAT-collapsed populations under-count affected systems (OQ-29).

**Risks** A dashboard rendering `overall_posture` without `coverage` beside it would
reproduce exactly the misleading claim §4 guards against → the band is already withheld
below the coverage floor, and coverage is a required field on the contract.

**Open questions** OQ-49: should severity weights be recalibrated once real multi-vendor
traffic exists (blocked on OQ-33r)? OQ-50: should recurrence count distinct endpoints
rather than sessions, once NAT identity (OQ-29) is resolved?
