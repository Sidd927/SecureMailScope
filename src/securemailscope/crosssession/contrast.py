"""
Control-endpoint contrast (Phase-5 §9), implementing the ADR-0005 state machine.

The research result this encodes (02A §9 #2, 02B §4.2): when an endpoint shows a
security-relevant deviation *and* a comparable control endpoint on the same server is
unaffected, the contrast reveals something single-session analysis cannot see
(FN 30->0 in OQ-25; FN 6->0 at packet level). When no such control exists, the same
attack is indistinguishable from legitimate configuration (FN 30/30, FN 6/6) and the
engine must abstain.

Crucially this is NOT a boolean flag. It is an evidence-driven decision that records
*why* a contrast was or was not performed, because a manufactured control relationship
would produce exactly the false confidence the whole project is built to avoid.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence, Tuple

from securemailscope.crosssession.baseline import (
    DEFAULT_MAX_HISTORY, PopulationIndex, SessionRef, _order,
)
from securemailscope.crosssession.comparability import key_for, assess
from securemailscope.session.model import SessionEvidence, TlsState


class ContrastState(str, Enum):
    """Vocabulary fixed by ADR-0005."""
    CONTRAST_SUPPORTED = "CONTRAST_SUPPORTED"
    CONTRAST_INSUFFICIENT = "CONTRAST_INSUFFICIENT"
    CONTRAST_NOT_APPLICABLE = "CONTRAST_NOT_APPLICABLE"
    CONTRAST_AMBIGUOUS = "CONTRAST_AMBIGUOUS"


@dataclass(frozen=True)
class ContrastResult:
    state: ContrastState
    reason: str
    control_sessions: Tuple[SessionRef, ...] = ()
    control_upgrade_rate: Optional[float] = None
    subject_upgraded: Optional[bool] = None

    @property
    def supported(self) -> bool:
        return self.state is ContrastState.CONTRAST_SUPPORTED

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "reason": self.reason,
            "control_sessions": [c.to_dict() for c in self.control_sessions],
            "control_upgrade_rate": self.control_upgrade_rate,
            "subject_upgraded": self.subject_upgraded,
        }


def _established(session: SessionEvidence) -> bool:
    return session.tls_state is TlsState.ESTABLISHED


def find_controls(subject: SessionEvidence,
                  population: Sequence[SessionEvidence],
                  min_controls: int = 1,
                  index: Optional[PopulationIndex] = None,
                  max_controls: Optional[int] = DEFAULT_MAX_HISTORY
                  ) -> List[SessionEvidence]:
    """Sessions to the SAME server/protocol/TLS mode from a DIFFERENT client.

    A control must differ in client identity — that is the whole point. Comparing the
    subject against its own earlier sessions is baseline work, not contrast.
    """
    index = index if index is not None else PopulationIndex(population)
    endpoint = key_for(subject).endpoint
    group = index.by_endpoint.get(endpoint, [])
    subject_client = subject.client_ip
    if subject_client is None:
        return []
    # Cheap exit: if this endpoint only ever saw one client, no control can exist and
    # scanning the group would be wasted linear work per subject.
    clients = index.clients_by_endpoint.get(endpoint, set())
    if len(clients - {subject_client}) == 0:
        return []
    controls: List[SessionEvidence] = []
    # Walk most-recent-first and stop once we have enough evidence: controls are an
    # evidence sample, not a census, and an unbounded scan makes analysis quadratic.
    for s in reversed(group):
        if len(controls) >= (max_controls or len(group)):
            break
        if (s is not subject and s.client_ip is not None
                and s.client_ip != subject_client):
            controls.append(s)
    controls.reverse()
    return controls


def evaluate_contrast(subject: SessionEvidence,
                      population: Sequence[SessionEvidence],
                      min_controls: int = 1,
                      index: Optional[PopulationIndex] = None,
                      max_controls: Optional[int] = DEFAULT_MAX_HISTORY) -> ContrastResult:
    """Run the ADR-0005 decision path."""
    if not assess(subject).ok:
        return ContrastResult(
            ContrastState.CONTRAST_NOT_APPLICABLE,
            "subject session is not comparable; no contrast is meaningful")

    if subject.implicit_tls:
        return ContrastResult(
            ContrastState.CONTRAST_NOT_APPLICABLE,
            "implicit TLS carries no upgrade behaviour to contrast")

    controls = find_controls(subject, population, min_controls, index, max_controls)
    if not controls:
        # THE case from 02A §9 #1 / 02B: without an unaffected comparable endpoint the
        # deviation is fundamentally indistinguishable from legitimate configuration.
        return ContrastResult(
            ContrastState.CONTRAST_NOT_APPLICABLE,
            "no comparable session from a different client at this endpoint; "
            "without an unaffected control the behaviour cannot be contrasted")

    if len(controls) < min_controls:
        return ContrastResult(
            ContrastState.CONTRAST_INSUFFICIENT,
            f"only {len(controls)} control session(s); {min_controls} required",
            control_sessions=_refs(controls))

    upgraded = [c for c in controls if _established(c)]
    rate = len(upgraded) / len(controls)
    subject_upgraded = _established(subject)

    # Controls disagree among themselves: the population is heterogeneous, which is
    # exactly the legitimate-diversity false-positive mode found in OQ-25 (cases E,
    # 11D, where the contrast rule took FP from 0 to 20). Do not pick a side.
    if 0.0 < rate < 1.0:
        return ContrastResult(
            ContrastState.CONTRAST_AMBIGUOUS,
            f"control endpoints disagree ({len(upgraded)}/{len(controls)} upgraded); "
            "the comparable population is not homogeneous enough to contrast against",
            control_sessions=_refs(controls), control_upgrade_rate=rate,
            subject_upgraded=subject_upgraded)

    return ContrastResult(
        ContrastState.CONTRAST_SUPPORTED,
        (f"{len(controls)} comparable control session(s) from other clients, "
         f"all {'upgrading' if rate == 1.0 else 'not upgrading'}"),
        control_sessions=_refs(controls), control_upgrade_rate=rate,
        subject_upgraded=subject_upgraded)


def _refs(sessions: Sequence[SessionEvidence]) -> Tuple[SessionRef, ...]:
    return tuple(
        SessionRef(s.stream_key, s.tcp_stream_id, s.first_frame, s.start_epoch,
                   "comparable session from a different client at the same endpoint")
        for s in sessions)
