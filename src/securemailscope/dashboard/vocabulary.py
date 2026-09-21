"""
Canonical enum -> presentation label (doc 23 §4b, §10, §11).

Two rules, both load-bearing:

1. **A label changes punctuation, never meaning.** `INSUFFICIENT_EVIDENCE` becomes
   `INSUFFICIENT EVIDENCE`. It never becomes `Unknown`, `Not assessed`, or anything a
   reader could mistake for reassurance.

2. **An unknown value is rendered, not replaced.** A severity this build has never heard
   of is humanised and shown as itself. It is never mapped to a default, never dropped,
   and never raises — a future enum value must degrade into "displayed verbatim", which
   is the only honest handling. `is_known()` lets the UI mark it as unrecognised rather
   than silently presenting it as understood.

The vocabulary mirrors `reporting/styles.py` so the dashboard and the report speak the
same words about the same assessment. It is deliberately a copy rather than an import:
`dashboard/` must not depend on `reporting/` (doc 23 §8), and a shared mutable constant
between two presentation layers would couple them in the one place they should agree by
test instead.
"""
from __future__ import annotations

from typing import Dict, Optional

#: Sentinel for findings whose `session.protocol` is null. Verified on a real capture:
#: the ANOMALY entry carries `protocol: None` while the base issue carries "smtp"
#: (doc 23 §7). A filter that omitted these would silently hide findings.
PROTOCOL_UNATTRIBUTED = "__unattributed__"
PROTOCOL_UNATTRIBUTED_LABEL = "Not attributed to a protocol"

POSTURE: Dict[str, str] = {
    "STRONG": "STRONG",
    "ADEQUATE": "ADEQUATE",
    "WEAK": "WEAK",
    "CRITICAL": "CRITICAL",
    "INSUFFICIENT_EVIDENCE": "INSUFFICIENT EVIDENCE",
}

#: Display ordering only. Never used to rank a finding: the assessment already decided
#: the order and the dashboard renders it (doc 23 §5).
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

SEVERITY: Dict[str, str] = {s: s for s in SEVERITY_ORDER}

#: ASCII so severity survives greyscale printing and screen readers, matching the report.
SEVERITY_MARKER: Dict[str, str] = {
    "CRITICAL": "[!!!]", "HIGH": "[!! ]", "MEDIUM": "[!  ]",
    "LOW": "[.  ]", "INFO": "[i  ]",
}

STATUS: Dict[str, str] = {
    "OBSERVED_ISSUE": "OBSERVED ISSUE",
    "COMPLIANT": "COMPLIANT",
    "AMBIGUOUS": "AMBIGUOUS",
    "INSUFFICIENT_EVIDENCE": "INSUFFICIENT EVIDENCE",
    "NOT_OBSERVABLE": "NOT OBSERVABLE",
}

CERTAINTY: Dict[str, str] = {
    "CONFIRMED": "CONFIRMED", "PROBABLE": "PROBABLE",
    "UNCERTAIN": "UNCERTAIN", "UNDETERMINED": "UNDETERMINED",
}

OBSERVABILITY: Dict[str, str] = {
    "OBSERVABLE": "OBSERVABLE",
    "PARTIALLY_OBSERVABLE": "PARTIALLY OBSERVABLE",
    "NOT_OBSERVABLE": "NOT OBSERVABLE",
}

FACT_KIND: Dict[str, str] = {
    "BASE_SECURITY_ISSUE": "Security issue",
    "BEHAVIOURAL_DEVIATION": "Behavioural deviation",
    "ANOMALY_SIGNAL": "Anomaly signal",
    "POSITIVE_EVIDENCE": "Positive evidence",
    "ABSTENTION": "Abstention",
}

ABSTENTION_REASON: Dict[str, str] = {
    "INSUFFICIENT_HISTORY": "Insufficient history",
    "AMBIGUOUS_EVIDENCE": "Ambiguous evidence",
    "NOT_OBSERVABLE": "Not observable",
    "INSUFFICIENT_CAPTURE": "Insufficient capture",
    "CONTRADICTORY_EVIDENCE": "Contradictory evidence",
    "UNSUPPORTED_PROTOCOL_VARIANT": "Unsupported protocol variant",
    "NOT_COMPARABLE": "Not comparable",
}

DIMENSION: Dict[str, str] = {
    "PROTOCOL_VERSION": "Protocol version",
    "PLAINTEXT_EXPOSURE": "Plaintext exposure",
    "UPGRADE_INTEGRITY": "Upgrade integrity",
    "CRYPTO_CONFIGURATION": "Crypto configuration",
    "CERTIFICATE_TRUST": "Certificate trust",
    "BEHAVIOURAL_CONSISTENCY": "Behavioural consistency",
}

#: Backend job lifecycle (Phase 8). Shown on the history screen.
JOB_STATE: Dict[str, str] = {
    "CREATED": "Created", "VALIDATING": "Validating", "QUEUED": "Queued",
    "RUNNING": "Running", "FINALIZING": "Finalizing", "COMPLETED": "Completed",
    "FAILED": "Failed", "CANCELLED": "Cancelled",
    "RECOVERY_REQUIRED": "Interrupted",
}

#: Job states that are finished. Used only to decide whether the UI keeps polling.
TERMINAL_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})

_VOCABULARIES = {
    "posture": POSTURE, "severity": SEVERITY, "status": STATUS,
    "certainty": CERTAINTY, "observability": OBSERVABILITY, "fact_kind": FACT_KIND,
    "abstention_reason": ABSTENTION_REASON, "dimension": DIMENSION,
    "job_state": JOB_STATE,
}


def humanise(value: Optional[str]) -> str:
    """`SOME_ENUM_VALUE` -> `Some enum value`.

    Applied only to identifiers the project itself defines. Text that came from a
    capture is never reshaped — it is displayed as captured.
    """
    if not value:
        return ""
    return str(value).replace("_", " ").capitalize()


def label(vocabulary: str, value: Optional[str], *, empty: str = "") -> str:
    """Display label for a canonical value. Never raises, never substitutes."""
    if value is None or value == "":
        return empty
    table = _VOCABULARIES.get(vocabulary, {})
    known = table.get(str(value))
    if known is not None:
        return known
    # Unknown to this build: show it, do not reinterpret it.
    return humanise(value)


def is_known(vocabulary: str, value: Optional[str]) -> bool:
    """Whether this build recognises the value. Lets the UI flag it as unrecognised."""
    if value is None or value == "":
        return False
    return str(value) in _VOCABULARIES.get(vocabulary, {})


def severity_marker(value: Optional[str]) -> str:
    """Text marker so severity is readable without colour (doc 23 §10, §12)."""
    if not value:
        return ""
    return SEVERITY_MARKER.get(str(value), "[?  ]")


def severity_index(value: Optional[str]) -> int:
    """Display-ordering index. NOT a severity judgement and not a score.

    Unknown severities sort after known ones rather than being treated as INFO.
    """
    try:
        return SEVERITY_ORDER.index(str(value))
    except ValueError:
        return len(SEVERITY_ORDER)


def tone(value: Optional[str]) -> str:
    """CSS class suffix for a severity. Drawn from the known vocabulary only, so no
    assessment text can ever reach a class attribute (doc 23 §11)."""
    v = str(value) if value else ""
    return v.lower() if v in SEVERITY else "unknown"


def posture_tone(value: Optional[str]) -> str:
    """`INSUFFICIENT_EVIDENCE` gets its own tone rather than a severity colour:
    withholding a verdict is not a severity, and colouring it like one implies a
    judgement the engine declined to make."""
    v = str(value) if value else ""
    return v.lower() if v in POSTURE else "unknown"
