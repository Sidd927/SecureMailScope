"""
Backend job lifecycle (doc 21 §6, ADR-0018 Decision 1).

`JobState` is deliberately **not** an extension of Phase-2 `RunStatus`. `RunStatus`
describes evidence quality — its own docstring states that `PARTIAL` means "the capture
was truncated" and that no security verdict may be derived from it. Queueing,
cancellation and crash recovery describe scheduling. One enum holding both would force a
caller to decide whether `EMPTY` — a perfectly successful analysis of a capture with no
packets — is a scheduling outcome. `RunStatus` is stored beside this as `ingest_status`,
unmodified.

Transitions are an explicit table. Anything not in it raises `InvalidTransition`:
`COMPLETED -> RUNNING` is rejected rather than silently accepted, which is the behaviour
Phase-2's `AnalysisRun.advance()` has (it validates nothing) and which Phase 8 does not
inherit.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet

from securemailscope.backend.errors import InvalidTransition


class JobState(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    FINALIZING = "FINALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    #: Audited intermediate only. A run observed here was interrupted; it is swept to
    #: FAILED immediately. It is not a resting state, because a state that demands a
    #: human but names no action is merely a worse FAILED (ADR-0018 Decision 2).
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


TERMINAL: FrozenSet[JobState] = frozenset(
    {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED})

#: States that only an interrupted process can leave behind. Swept at startup.
INTERRUPTIBLE: FrozenSet[JobState] = frozenset(
    {JobState.CREATED, JobState.VALIDATING, JobState.QUEUED,
     JobState.RUNNING, JobState.FINALIZING})

#: The whole transition table. Every allowed edge is here and nowhere else.
TRANSITIONS: Dict[JobState, FrozenSet[JobState]] = {
    JobState.CREATED: frozenset(
        {JobState.VALIDATING, JobState.FAILED, JobState.CANCELLED,
         JobState.RECOVERY_REQUIRED}),
    JobState.VALIDATING: frozenset(
        {JobState.QUEUED, JobState.FAILED, JobState.CANCELLED,
         JobState.RECOVERY_REQUIRED}),
    JobState.QUEUED: frozenset(
        {JobState.RUNNING, JobState.FAILED, JobState.CANCELLED,
         JobState.RECOVERY_REQUIRED}),
    JobState.RUNNING: frozenset(
        {JobState.FINALIZING, JobState.FAILED, JobState.CANCELLED,
         JobState.RECOVERY_REQUIRED}),
    # FINALIZING -> COMPLETED is the only edge into COMPLETED, and the service performs
    # it in the same transaction that inserts the assessment.
    JobState.FINALIZING: frozenset(
        {JobState.COMPLETED, JobState.FAILED, JobState.RECOVERY_REQUIRED}),
    JobState.RECOVERY_REQUIRED: frozenset({JobState.FAILED}),
    JobState.COMPLETED: frozenset(),
    JobState.FAILED: frozenset(),
    JobState.CANCELLED: frozenset(),
}


def is_terminal(state: JobState) -> bool:
    return state in TERMINAL


def can_transition(source: JobState, target: JobState) -> bool:
    return target in TRANSITIONS.get(source, frozenset())


def check_transition(source: JobState, target: JobState,
                     run_id: str = "") -> None:
    """Raise unless the edge is in the table. Fails closed."""
    if not can_transition(source, target):
        raise InvalidTransition(
            "transition {0} -> {1} is not permitted".format(
                source.value, target.value),
            detail={"from": source.value, "to": target.value,
                    "allowed": sorted(s.value for s in TRANSITIONS.get(
                        source, frozenset()))},
            run_id=run_id or None)


def parse(value: str) -> JobState:
    """Parse a stored state string. Unknown values fail rather than defaulting."""
    try:
        return JobState(value)
    except ValueError:
        raise InvalidTransition("unknown job state in storage",
                                detail={"value": value})
