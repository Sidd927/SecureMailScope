"""
Evidence states and the EvidenceField contract.

This module is the correctness backbone of the whole system (docs/architecture/04).
Every non-structural fact is an EvidenceField carrying not just a value but *how well
the capture supports it*. The design makes the forbidden silent conversions
(UNKNOWN->FALSE, NOT_OBSERVABLE->FALSE, INFERRED->OBSERVED, ...) structurally hard:

  - EvidenceField is frozen (immutable): a field's state cannot be mutated in place,
    so a "conversion" always requires explicitly constructing a new field.
  - Fields are built through intent-revealing factory constructors that validate
    their own invariants (e.g. OBSERVED must carry a value; UNKNOWN must not).
  - There is deliberately NO setter and NO `.with_state(...)` shortcut.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional, Tuple


class EvidenceState(str, Enum):
    """How strongly the capture supports a fact (docs/architecture/04 §1)."""

    OBSERVED = "OBSERVED"              # directly present in captured bytes
    INFERRED = "INFERRED"             # deduced from observed facts (basis required)
    UNKNOWN = "UNKNOWN"               # insufficient evidence to decide
    AMBIGUOUS = "AMBIGUOUS"           # evidence supports more than one reading
    INCOMPLETE = "INCOMPLETE"         # capture truncated at the relevant point
    NOT_OBSERVABLE = "NOT_OBSERVABLE"  # structurally impossible to observe passively


# States that must NOT carry a concrete value: their whole point is the absence of one.
_VALUELESS = {
    EvidenceState.UNKNOWN,
    EvidenceState.INCOMPLETE,
    EvidenceState.NOT_OBSERVABLE,
}


class Provenance(str, Enum):
    """Origin of a certificate-class fact (docs/architecture/04 §3)."""

    OBSERVED = "observed"        # seen in this session's captured bytes
    INHERITED = "inherited"      # linked from an earlier full handshake (TLS <=1.2 session id)
    HISTORICAL = "historical"    # seen earlier for this server in our own corpus
    RETRIEVED = "retrieved"      # actively fetched (out of core scope; optional mode)
    DECRYPTED = "decrypted"      # recovered with key material (optional mode)
    NONE = "none"               # not applicable


@dataclass(frozen=True)
class EvidenceField:
    """An immutable value-with-provenance. Build via the factory constructors below."""

    value: Any
    state: EvidenceState
    basis: str
    provenance: Provenance = Provenance.NONE
    frames: Tuple[int, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        # Invariants that make invalid evidence unrepresentable.
        if self.state == EvidenceState.OBSERVED and self.value is None:
            raise ValueError("OBSERVED evidence must carry a value")
        if self.state == EvidenceState.INFERRED and not self.basis:
            raise ValueError("INFERRED evidence must record its basis")
        if self.state in _VALUELESS and self.value is not None:
            raise ValueError(f"{self.state.value} evidence must not carry a value (got {self.value!r})")
        if not isinstance(self.frames, tuple):
            raise TypeError("frames must be a tuple (frozen)")

    # ---- intent-revealing constructors -------------------------------------
    @classmethod
    def observed(cls, value: Any, basis: str, *, frames: Optional[List[int]] = None,
                 provenance: Provenance = Provenance.OBSERVED) -> "EvidenceField":
        return cls(value, EvidenceState.OBSERVED, basis, provenance, tuple(frames or ()))

    @classmethod
    def inferred(cls, value: Any, basis: str, *, frames: Optional[List[int]] = None,
                 provenance: Provenance = Provenance.NONE) -> "EvidenceField":
        return cls(value, EvidenceState.INFERRED, basis, provenance, tuple(frames or ()))

    @classmethod
    def ambiguous(cls, value: Any, basis: str, *, frames: Optional[List[int]] = None) -> "EvidenceField":
        return cls(value, EvidenceState.AMBIGUOUS, basis, Provenance.NONE, tuple(frames or ()))

    @classmethod
    def unknown(cls, basis: str) -> "EvidenceField":
        return cls(None, EvidenceState.UNKNOWN, basis, Provenance.NONE, ())

    @classmethod
    def incomplete(cls, basis: str) -> "EvidenceField":
        return cls(None, EvidenceState.INCOMPLETE, basis, Provenance.NONE, ())

    @classmethod
    def not_observable(cls, basis: str) -> "EvidenceField":
        return cls(None, EvidenceState.NOT_OBSERVABLE, basis, Provenance.NONE, ())

    # ---- safe accessors -----------------------------------------------------
    @property
    def is_conclusive(self) -> bool:
        """True only when the fact is firmly established (OBSERVED or INFERRED)."""
        return self.state in (EvidenceState.OBSERVED, EvidenceState.INFERRED)

    def value_or(self, default: Any) -> Any:
        """Read the value ONLY when conclusive; otherwise the caller's default.

        This is the safe read path: it refuses to hand back a value for
        UNKNOWN/AMBIGUOUS/INCOMPLETE/NOT_OBSERVABLE, preventing the forbidden
        'treat missing evidence as the value' conversion.
        """
        return self.value if self.is_conclusive else default

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "state": self.state.value,
            "basis": self.basis,
            "provenance": self.provenance.value,
            "frames": list(self.frames),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceField":
        return cls(
            value=d["value"],
            state=EvidenceState(d["state"]),
            basis=d["basis"],
            provenance=Provenance(d.get("provenance", "none")),
            frames=tuple(d.get("frames", [])),
        )
