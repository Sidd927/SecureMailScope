"""
Session comparability (Phase-5 §5).

A baseline may only be built from sessions that are *actually* comparable. Comparing a
session against unrelated traffic is how cross-session reasoning manufactures false
conclusions, so comparability is an explicit, inspectable decision — not an implicit
group-by.

Dimensions were chosen from the OQ-25 experiment (docs/research/02A §4), which found
that the useful axis is "same service endpoint, same protocol" and that the *rule set*
mattered far more than the key. We deliberately do NOT key on every available field:
over-specific keys fragment history below the usable threshold and cause abstention,
under-specific keys pool unrelated behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from securemailscope.session.model import Completeness, SessionEvidence


class Comparability(str, Enum):
    COMPARABLE = "COMPARABLE"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True)
class ComparabilityKey:
    """Identity of a comparable population.

    Scoped to one CLIENT talking to one service endpoint over one protocol and TLS mode.
    Client identity is part of the key because OQ-25 (02A §4) found the workable split is
    a client-scoped baseline plus an explicit cross-client contrast: pooling every client
    of a server into one baseline mixes heterogeneous-but-legitimate client populations
    and destroys the contrast signal that makes control endpoints useful.

    Implicit and explicit TLS are never pooled -- they are different protocol behaviours
    (Phase-3 §17), so mixing them would compare unlike with unlike.
    """

    client_ip: Optional[str]
    server_ip: Optional[str]
    server_port: Optional[int]
    protocol: Optional[str]
    implicit_tls: bool

    @property
    def endpoint(self) -> Tuple:
        """Server-scoped identity, used to locate control sessions from other clients."""
        return (self.server_ip, self.server_port, self.protocol, self.implicit_tls)

    @property
    def is_resolvable(self) -> bool:
        return (self.server_ip is not None and self.server_port is not None
                and self.protocol is not None and self.client_ip is not None)

    def as_tuple(self) -> Tuple:
        return (self.client_ip, self.server_ip, self.server_port, self.protocol,
                self.implicit_tls)

    def to_dict(self) -> dict:
        return {"client_ip": self.client_ip, "server_ip": self.server_ip,
                "server_port": self.server_port, "protocol": self.protocol,
                "implicit_tls": self.implicit_tls}


@dataclass(frozen=True)
class ComparabilityAssessment:
    result: Comparability
    reason: str
    key: Optional[ComparabilityKey] = None

    @property
    def ok(self) -> bool:
        return self.result is Comparability.COMPARABLE

    def to_dict(self) -> dict:
        return {"result": self.result.value, "reason": self.reason,
                "key": self.key.to_dict() if self.key else None}


def key_for(session: SessionEvidence) -> ComparabilityKey:
    return ComparabilityKey(
        client_ip=session.client_ip,
        server_ip=session.server_ip,
        server_port=session.server_port,
        protocol=session.protocol,
        implicit_tls=session.implicit_tls,
    )


def assess(session: SessionEvidence) -> ComparabilityAssessment:
    """Can this session participate in cross-session reasoning at all?"""
    key = key_for(session)

    if session.protocol is None:
        return ComparabilityAssessment(
            Comparability.NOT_COMPARABLE,
            "no mail protocol identified for this stream", key)

    if not key.is_resolvable:
        # Without a resolved server identity we cannot know what population this
        # session belongs to. NAT/identity collapse is a known limitation (02A §9 #5).
        return ComparabilityAssessment(
            Comparability.INSUFFICIENT_EVIDENCE,
            "client or server endpoint identity could not be resolved", key)

    if session.completeness is Completeness.TRUNCATED:
        return ComparabilityAssessment(
            Comparability.INSUFFICIENT_EVIDENCE,
            "session is truncated; its behaviour may be an artefact of the capture", key)

    return ComparabilityAssessment(
        Comparability.COMPARABLE,
        f"client {key.client_ip} to {key.server_ip}:{key.server_port}, "
        f"protocol {key.protocol}, "
        f"{'implicit' if key.implicit_tls else 'explicit'} TLS mode", key)


def comparable_pair(a: SessionEvidence, b: SessionEvidence) -> ComparabilityAssessment:
    """Are two specific sessions comparable to each other?"""
    aa, ab = assess(a), assess(b)
    if not aa.ok:
        return ComparabilityAssessment(aa.result, f"subject: {aa.reason}", aa.key)
    if not ab.ok:
        return ComparabilityAssessment(ab.result, f"candidate: {ab.reason}", ab.key)
    if aa.key != ab.key:
        return ComparabilityAssessment(
            Comparability.NOT_COMPARABLE,
            "different client, service endpoint, protocol or TLS mode", aa.key)
    return ComparabilityAssessment(Comparability.COMPARABLE, aa.reason, aa.key)
