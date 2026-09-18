"""
Baseline construction (Phase-5 §6, §7, §8).

A baseline summarises the behaviour of *prior comparable* sessions. Three constraints
come straight from the experiments and are not negotiable:

1. **Prior-history, not capture-wide pooling.** OQ-25 (02A §6) showed capture-wide
   pooling produces false positives when a server legitimately changes configuration
   mid-capture (FP 20 -> 0 when switched to prior-history). A session is therefore
   compared only against sessions that precede it.

2. **No invented time window.** The experiment established *ordering* matters, not any
   particular duration. We deliberately do not invent "last N minutes"; the temporal
   policy is strict precedence by (timestamp, frame, stream), which is what was tested.

3. **Abstain below the history threshold.** Default 5, from 02A §5 where behaviour is a
   step function at that point. That document explicitly records 5 as *a chosen
   parameter, not a derived one*, so it is configuration, not a constant.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

from securemailscope.crosssession.comparability import (
    Comparability, ComparabilityKey, assess, key_for,
)
from securemailscope.session.model import SessionEvidence, TlsState

#: Empirical default (docs/research/02A §5). Configurable, not hard-coded at call sites.
DEFAULT_MIN_HISTORY = 5

#: Most-recent-N prior sessions used for a baseline. This follows the same principle as
#: prior-history ordering (Finding 3): recent behaviour is the relevant comparison, and
#: pooling unboundedly far back both dilutes a legitimate reconfiguration and makes the
#: analysis quadratic. The value is a bound, not an empirical claim -- the experiments
#: measured the *minimum* usable history (5), never an optimal maximum.
DEFAULT_MAX_HISTORY = 50


class BaselineStatus(str, Enum):
    ESTABLISHED = "ESTABLISHED"
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    NOT_APPLICABLE = "NOT_APPLICABLE"   # subject not comparable at all


@dataclass(frozen=True)
class SessionRef:
    """Concrete pointer to a baseline member. Never cite 'a baseline' abstractly."""
    stream_key: Optional[str]
    tcp_stream_id: Optional[int]
    first_frame: Optional[int]
    timestamp_epoch: Optional[float]
    membership_reason: str

    def to_dict(self) -> dict:
        return {"stream_key": self.stream_key, "tcp_stream_id": self.tcp_stream_id,
                "first_frame": self.first_frame, "timestamp_epoch": self.timestamp_epoch,
                "membership_reason": self.membership_reason}


@dataclass(frozen=True)
class FeatureSummary:
    """Distribution of one security-relevant feature across the baseline population."""
    name: str
    counts: Dict[str, int]
    total: int

    def rate(self, value: str) -> float:
        return (self.counts.get(value, 0) / self.total) if self.total else 0.0

    @property
    def is_consistent(self) -> bool:
        """True when every observation agreed."""
        return self.total > 0 and len(self.counts) == 1

    @property
    def dominant(self) -> Optional[str]:
        if not self.counts:
            return None
        # Deterministic tie-break on the value name.
        return sorted(self.counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

    def to_dict(self) -> dict:
        return {"name": self.name, "counts": dict(sorted(self.counts.items())),
                "total": self.total, "consistent": self.is_consistent,
                "dominant": self.dominant}


#: Security-relevant features only (Phase-5 §6): we do not baseline every field.
def _feature_values(session: SessionEvidence) -> Dict[str, str]:
    def state_of(field_) -> str:
        if field_.value is True:
            return "true"
        if field_.value is False:
            return "false"
        return field_.state.value  # UNKNOWN / AMBIGUOUS / NOT_OBSERVABLE

    return {
        "starttls_advertised": state_of(session.starttls_advertised),
        "starttls_requested": state_of(session.starttls_requested),
        "tls_established": "true" if session.tls_state is TlsState.ESTABLISHED else (
            session.tls_state.value),
        "tls_version": (str(session.tls_negotiated_version.value)
                        if session.tls_negotiated_version.value is not None
                        else session.tls_negotiated_version.state.value),
        "auth_activity": state_of(session.auth_activity),
    }


@dataclass
class Baseline:
    """Behaviour of prior comparable sessions for one endpoint/protocol population."""
    key: Optional[ComparabilityKey]
    status: BaselineStatus
    sample_count: int = 0
    min_history: int = DEFAULT_MIN_HISTORY
    features: Dict[str, FeatureSummary] = field(default_factory=dict)
    members: Tuple[SessionRef, ...] = ()
    window_start_epoch: Optional[float] = None
    window_end_epoch: Optional[float] = None
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.status is BaselineStatus.ESTABLISHED

    def feature(self, name: str) -> Optional[FeatureSummary]:
        return self.features.get(name)

    def to_dict(self) -> dict:
        return {
            "key": self.key.to_dict() if self.key else None,
            "status": self.status.value,
            "sample_count": self.sample_count,
            "min_history": self.min_history,
            "window": {"start_epoch": self.window_start_epoch,
                       "end_epoch": self.window_end_epoch},
            "features": {k: v.to_dict() for k, v in sorted(self.features.items())},
            "members": [m.to_dict() for m in self.members],
            "reason": self.reason,
        }


def _order(session: SessionEvidence) -> Tuple:
    """Total, deterministic ordering. Never relies on dict/filesystem iteration order.
    Sessions without a timestamp sort by frame then stream so the order is still total."""
    return (
        session.start_epoch if session.start_epoch is not None else float("-inf"),
        session.first_frame if session.first_frame is not None else -1,
        session.tcp_stream_id if session.tcp_stream_id is not None else -1,
    )


class PopulationIndex:
    """One-pass grouping of a population by comparability key and by server endpoint.

    Without this, every subject rescans the whole population, making analysis O(n^2)
    (measured: 1.3 ms/session at n=250 rising to 10.8 ms/session at n=2000). Building
    the index once makes each lookup proportional to the size of the relevant group.
    """

    __slots__ = ("by_key", "by_endpoint", "clients_by_endpoint")

    def __init__(self, population: Sequence[SessionEvidence]):
        self.by_key: Dict[Tuple, List[SessionEvidence]] = {}
        self.by_endpoint: Dict[Tuple, List[SessionEvidence]] = {}
        #: Distinct client identities per endpoint. Lets contrast exit immediately when
        #: only one client exists, instead of scanning the whole group to find nothing.
        self.clients_by_endpoint: Dict[Tuple, set] = {}
        for session in population:
            if not assess(session).ok:
                continue
            key = key_for(session)
            self.by_key.setdefault(key.as_tuple(), []).append(session)
            self.by_endpoint.setdefault(key.endpoint, []).append(session)
            self.clients_by_endpoint.setdefault(key.endpoint, set()).add(session.client_ip)
        for group in self.by_key.values():
            group.sort(key=_order)
        for group in self.by_endpoint.values():
            group.sort(key=_order)


def prior_comparable(subject: SessionEvidence,
                     population: Sequence[SessionEvidence],
                     index: Optional["PopulationIndex"] = None,
                     max_history: Optional[int] = DEFAULT_MAX_HISTORY
                     ) -> List[SessionEvidence]:
    """Comparable sessions that strictly precede the subject (§7 prior-history policy).

    The group is pre-sorted, so priors are a contiguous prefix located by bisect;
    only the most recent `max_history` of them are returned.
    """
    if not assess(subject).ok:
        return []
    index = index if index is not None else PopulationIndex(population)
    group = index.by_key.get(key_for(subject).as_tuple(), [])
    if not group:
        return []
    cut = _bisect_orders(group, _order(subject))
    # Window FIRST, then filter: materialising the whole prefix made this O(n) per
    # subject and therefore O(n^2) overall. +2 slack covers self/duplicate removal.
    start = max(0, cut - (max_history + 2)) if max_history is not None else 0
    subject_id = (subject.capture_id, subject.tcp_stream_id)
    prior = [s for s in group[start:cut]
             if s is not subject and (s.capture_id, s.tcp_stream_id) != subject_id]
    if max_history is not None and len(prior) > max_history:
        prior = prior[-max_history:]
    return prior


def _bisect_orders(group: List[SessionEvidence], target: Tuple) -> int:
    """Binary search for the first index whose order is >= target."""
    lo, hi = 0, len(group)
    while lo < hi:
        mid = (lo + hi) // 2
        if _order(group[mid]) < target:
            lo = mid + 1
        else:
            hi = mid
    return lo


def build_baseline(subject: SessionEvidence,
                   population: Sequence[SessionEvidence],
                   min_history: int = DEFAULT_MIN_HISTORY,
                   index: Optional["PopulationIndex"] = None,
                   max_history: Optional[int] = DEFAULT_MAX_HISTORY) -> Baseline:
    """Build the prior-history baseline for one subject session."""
    subject_assessment = assess(subject)
    key = subject_assessment.key

    if subject_assessment.result is Comparability.NOT_COMPARABLE:
        return Baseline(key, BaselineStatus.NOT_APPLICABLE, min_history=min_history,
                        reason=f"subject not comparable: {subject_assessment.reason}")
    if subject_assessment.result is Comparability.INSUFFICIENT_EVIDENCE:
        return Baseline(key, BaselineStatus.INSUFFICIENT_HISTORY, min_history=min_history,
                        reason=f"subject evidence insufficient: {subject_assessment.reason}")

    prior = prior_comparable(subject, population, index, max_history)
    if len(prior) < min_history:
        return Baseline(
            key, BaselineStatus.INSUFFICIENT_HISTORY, sample_count=len(prior),
            min_history=min_history,
            reason=(f"only {len(prior)} prior comparable session(s); "
                    f"{min_history} required before a baseline is used"))

    counts: Dict[str, Dict[str, int]] = {}
    for s in prior:
        for name, value in _feature_values(s).items():
            counts.setdefault(name, {})
            counts[name][value] = counts[name].get(value, 0) + 1

    features = {name: FeatureSummary(name, dict(v), len(prior))
                for name, v in counts.items()}
    members = tuple(
        SessionRef(s.stream_key, s.tcp_stream_id, s.first_frame, s.start_epoch,
                   "prior comparable session at the same endpoint, protocol and TLS mode")
        for s in prior)

    stamps = [s.start_epoch for s in prior if s.start_epoch is not None]
    return Baseline(
        key, BaselineStatus.ESTABLISHED, sample_count=len(prior), min_history=min_history,
        features=features, members=members,
        window_start_epoch=min(stamps) if stamps else None,
        window_end_epoch=max(stamps) if stamps else None,
        reason=f"{len(prior)} prior comparable sessions at {key.server_ip}:{key.server_port}")
