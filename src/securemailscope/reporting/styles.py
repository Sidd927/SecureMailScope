"""
Report design vocabulary (doc 22 §6, §8, ADR-0019 Decision 3).

Two rules govern everything here:

1. **Text first, colour second.** Every severity, posture, certainty and observability
   value renders as a word. Colour reinforces; it never carries the meaning. A report
   printed in greyscale, or read by someone with a colour vision deficiency, must convey
   exactly the same severities as one read on screen.

2. **Labels change punctuation, never meaning.** `INSUFFICIENT_EVIDENCE` becomes
   `INSUFFICIENT EVIDENCE`. It never becomes `Unknown`, `Not assessed` or anything a
   reader could mistake for reassurance.
"""
from __future__ import annotations

from typing import Dict

# --------------------------------------------------------------------- labels
#: Canonical value -> display label. Underscores to spaces; nothing is softened.
POSTURE_LABEL: Dict[str, str] = {
    "STRONG": "STRONG",
    "ADEQUATE": "ADEQUATE",
    "WEAK": "WEAK",
    "CRITICAL": "CRITICAL",
    "INSUFFICIENT_EVIDENCE": "INSUFFICIENT EVIDENCE",
}

#: Ordered strongest-signal-first. Used for display ordering only, never for ranking a
#: finding: the assessment already decided the order (doc 22 §5).
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: A text marker so severity survives greyscale printing and screen readers. These are
#: ASCII rather than emoji so PDF font coverage is not a variable.
SEVERITY_MARKER: Dict[str, str] = {
    "CRITICAL": "[!!!]",
    "HIGH": "[!! ]",
    "MEDIUM": "[!  ]",
    "LOW": "[.  ]",
    "INFO": "[i  ]",
}

STATUS_LABEL: Dict[str, str] = {
    "OBSERVED_ISSUE": "OBSERVED ISSUE",
    "COMPLIANT": "COMPLIANT",
    "AMBIGUOUS": "AMBIGUOUS",
    "INSUFFICIENT_EVIDENCE": "INSUFFICIENT EVIDENCE",
    "NOT_OBSERVABLE": "NOT OBSERVABLE",
}

CERTAINTY_LABEL: Dict[str, str] = {
    "CONFIRMED": "CONFIRMED",
    "PROBABLE": "PROBABLE",
    "UNCERTAIN": "UNCERTAIN",
    "UNDETERMINED": "UNDETERMINED",
}

OBSERVABILITY_LABEL: Dict[str, str] = {
    "OBSERVABLE": "OBSERVABLE",
    "PARTIALLY_OBSERVABLE": "PARTIALLY OBSERVABLE",
    "NOT_OBSERVABLE": "NOT OBSERVABLE",
}

ABSTENTION_LABEL: Dict[str, str] = {
    "INSUFFICIENT_HISTORY": "Insufficient history",
    "AMBIGUOUS_EVIDENCE": "Ambiguous evidence",
    "NOT_OBSERVABLE": "Not observable",
    "INSUFFICIENT_CAPTURE": "Insufficient capture",
    "CONTRADICTORY_EVIDENCE": "Contradictory evidence",
    "UNSUPPORTED_PROTOCOL_VARIANT": "Unsupported protocol variant",
    "NOT_COMPARABLE": "Not comparable",
}


def humanise(value: str) -> str:
    """`SOME_ENUM_VALUE` -> `Some enum value`. Used for issue classes and dimensions.

    Applied only to enum identifiers the project itself defines — never to text that
    came from a capture.
    """
    if not value:
        return ""
    return value.replace("_", " ").capitalize()


def posture_label(value: str) -> str:
    return POSTURE_LABEL.get(value, value.replace("_", " ") if value else "")


def severity_marker(value: str) -> str:
    return SEVERITY_MARKER.get(value, "[?  ]")


def severity_rank(value: str) -> int:
    """Display-ordering index only. Not a severity judgement and not a score."""
    try:
        return SEVERITY_ORDER.index(value)
    except ValueError:
        return len(SEVERITY_ORDER)


# ---------------------------------------------------------------------- colour
#: Restrained DFIR palette. Every one of these is redundant with a text label.
COLOR = {
    "ink": "#15191e",
    "muted": "#5c6672",
    "rule": "#d4d9de",
    "panel": "#f6f7f9",
    "accent": "#1f3a5f",
    "critical": "#8d1f1f",
    "high": "#a8480f",
    "medium": "#8a6510",
    "low": "#3d5a2b",
    "info": "#41526b",
    "withheld": "#4a3a6b",
}

SEVERITY_COLOR = {
    "CRITICAL": COLOR["critical"], "HIGH": COLOR["high"], "MEDIUM": COLOR["medium"],
    "LOW": COLOR["low"], "INFO": COLOR["info"],
}

#: INSUFFICIENT_EVIDENCE gets its own hue rather than a severity colour: withholding a
#: verdict is not a severity, and colouring it like one would imply a judgement.
POSTURE_COLOR = {
    "STRONG": COLOR["low"], "ADEQUATE": COLOR["info"], "WEAK": COLOR["medium"],
    "CRITICAL": COLOR["critical"], "INSUFFICIENT_EVIDENCE": COLOR["withheld"],
}


def severity_color(value: str) -> str:
    return SEVERITY_COLOR.get(value, COLOR["muted"])


def posture_color(value: str) -> str:
    return POSTURE_COLOR.get(value, COLOR["muted"])


# ------------------------------------------------------------------- typography
#: Core-14 PDF fonts: present in every PDF reader, so no font is embedded and no font
#: file is a dependency. The HTML uses a system stack for the same reason — doc 22 §9
#: requires no external font.
PDF_FONT = "Helvetica"
PDF_FONT_BOLD = "Helvetica-Bold"
PDF_FONT_MONO = "Courier"

HTML_FONT_STACK = (
    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", '
    "Arial, sans-serif")
HTML_MONO_STACK = ('ui-monospace, SFMono-Regular, Menlo, Consolas, '
                   '"Liberation Mono", monospace')
