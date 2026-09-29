# ADR-0018 — A backend job lifecycle distinct from run status, and a pass-through API
**Status:** Accepted 2026-09-21 · **Detail:** `docs/architecture/21` ·
**Builds on:** ADR-0011 (modular monolith, FastAPI), ADR-0016 (canonical assessment)

**Context** Phase 8 turns the Phase-7 engine into a backend: accept a capture, run the
existing pipeline, persist the canonical assessment, expose it over HTTP, and survive
failure and restart. ADR-0011 already fixed the shape — modular monolith, Python,
FastAPI, in-process background work, no brokers. This ADR records the four decisions
ADR-0011 left open.

**Problem** What is a job's lifecycle, given that a `RunStatus` already exists? What does
the API return? What happens on restart, and on a duplicate submission?

---

## Decision 1 — `JobState` is new; `RunStatus` is not extended

Phase 2 already defines `RunStatus` — `CREATED · VALIDATING · DISSECTING · NORMALIZING ·
COMPLETED · EMPTY · PARTIAL · FAILED` (`evidence/run.py`).

**Rejected: adding `QUEUED`, `CANCELLED` and a recovery state to `RunStatus`.** Its
module docstring is explicit that it describes *the analysis, not the security of the
traffic*, and that `PARTIAL` means "the capture was truncated". Those values describe
**evidence quality**. Queueing, cancellation and crash recovery describe **job
scheduling**. One enum holding both would force a caller to answer "is `PARTIAL` a
finished job or a degraded one?" and would make `EMPTY` — a perfectly successful
analysis of a capture with no packets — look like a scheduling outcome. It would also
be a change to a frozen Phase-7 input contract.

**Selected** a separate `JobState` owned by the backend. `RunStatus` is stored beside it
as the ingest outcome, untouched. The two answer different questions: `JobState` says
whether the backend finished; `RunStatus` says what the capture contained.

**Also decided** `AnalysisRun.advance()` accepts any transition without validation —
`COMPLETED → DISSECTING` silently succeeds today. Phase 8 does not change that (frozen),
but its own machine validates every transition against an explicit table and raises
`InvalidTransition` otherwise. Fail closed, per the Phase-4 philosophy.

## Decision 2 — `COMPLETED` requires a durably committed assessment

The transition to `COMPLETED` and the insertion of the assessment row occur in **one
SQLite transaction**. There is no code path that marks a job complete and then writes
the result.

**Rejected: marking `COMPLETED` on pipeline return, persisting afterwards.** A crash in
the gap produces a job that claims success with nothing behind it — the single most
damaging failure a forensic tool can have, because it is indistinguishable from a real
result until someone asks for the evidence.

On startup, any job found in a non-terminal state (`CREATED`, `VALIDATING`, `QUEUED`,
`RUNNING`, `FINALIZING`) was interrupted by definition: nothing else could have left it
there. It is swept to `RECOVERY_REQUIRED` and then `FAILED`, with the reason recorded.

**Rejected: resuming interrupted work on startup.** Resumption needs durable
intermediate state, which would mean persisting partial evidence — a second
representation of analysis in progress, and a much larger blast radius than re-running a
deterministic pipeline. The capture is content-addressed and the pipeline is
deterministic, so re-submission is cheap and correct.

**Rejected: `RECOVERY_REQUIRED` as a resting state.** A state that requires a human but
names no action is a worse `FAILED`. It exists only as an audited intermediate so the
`run_events` trail distinguishes "crashed" from "failed during analysis".

## Decision 3 — The API is a transport for the canonical object, not a second contract

`GET /api/v1/analyses/{run_id}/assessment` returns `PostureAssessment.to_dict()` with no
field removed, renamed, flattened or recomputed.

**Rejected: a hand-written "summary" response shaped for a future dashboard.** That is
how `INSUFFICIENT_EVIDENCE` becomes `UNKNOWN`, then `OK`, then a green tick. ADR-0016
already withholds the band below the coverage floor precisely so this cannot happen; an
API that re-projected the object would reopen the hole from the other side.

The response envelope therefore carries the document verbatim. `coverage`, `limitations`
and `model_summary` are **required** fields on the assessment response — a client cannot
receive a band without the evidence coverage that qualifies it. The six evidence states
and the `NOT_OBSERVABLE` / `AMBIGUOUS` / `INSUFFICIENT_EVIDENCE` distinctions are never
collapsed into a boolean.

Pydantic models are used for **requests, errors and list items** — inputs and backend-
owned metadata, which the backend genuinely owns — and deliberately **not** as a
re-declaration of the assessment schema, which the posture layer owns.

## Decision 4 — Duplicate submission returns the existing assessment by default

Same `capture_id` + same configuration (`ai_enabled`, formula) → the existing completed
run is returned, marked as a replay. `?force=true` creates an independent run against the
same capture.

**Rejected: always creating a new run.** The pipeline is deterministic, so a second run
produces the same `assessment_id` and the same document: the work is wasted and the
catalog accumulates rows that differ only by uuid and timestamp.

**Rejected: rejecting duplicates with `409`.** Re-submitting a capture is a normal
analyst action, and an error for a request the system can trivially answer is hostile.

**Rejected: deduplicating on filename.** Filenames are attacker-controlled and carry no
forensic identity. Deduplication keys on `capture_id`, which is the SHA-256 of the
content.

`force=true` exists because "run it again and show me it agrees" is a legitimate check,
and because a changed engine version should be re-runnable against stored history.

---

**Consequences** + a job can never claim a result it does not have; + evidence quality
and job state stay legible as separate facts; + the API cannot dilute a posture claim;
+ repeat submissions are cheap. − no resumption of interrupted analyses; − one active
writer, so throughput is bounded (documented invariant, ADR-0017); − clients wanting a
compact summary must compute it themselves from the canonical document, on purpose.

**Risks** A Phase-9 dashboard renders `overall_posture` without `coverage` → the band is
already withheld below the floor and `coverage` is non-optional in the response schema,
but this is a UI discipline this ADR cannot enforce and Phase 9 must carry.

**Open questions** OQ-52: does synchronous in-request analysis remain acceptable for
large captures, or does the background-job path in ADR-0011 need to be exercised before
the demo? OQ-53: should `force=true` retain both assessments when engine versions
differ, rather than conflicting on `assessment_id` (ADR-0017 Decision 4)?
