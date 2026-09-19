"""
Standards registry (Phase 7).

Phase 4 emits standards as free-text strings. That is fine for a human reading one
finding and useless for a report that needs to group, cite or link them. This module
adds **structure around the existing strings** and nothing else:

* it introduces **no new standard** — every entry here corresponds to a string a Phase-4
  or Phase-5 rule already emits, verified in docs/research/SOURCES.md;
* it **never rewrites** a rule's string — the verbatim text is carried through as
  `StandardCitation.text`, so what an analyst sees is what the rule said;
* an unrecognised string is **not dropped**. It becomes an `UNMAPPED` citation with its
  text intact, because silently losing a citation is worse than an ugly one.

`NIST SP 800-52r2` is deliberately matched twice: `tls_rules.py` and
`plaintext_rules.py` define it with different wording for the same section, and the
registry resolves both rather than pretending one of them does not exist.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

from securemailscope.posture.model import StandardCitation

#: (substring marker, standard, section, applicability reason).
#: Matching is by marker rather than by exact equality so that the two differently
#: worded NIST strings both resolve, and so a whitespace change in a rule cannot
#: silently orphan a citation.
_REGISTRY: Tuple[Tuple[str, str, str, str], ...] = (
    ("RFC 8996", "RFC 8996 (BCP 195)", "SS4-5",
     "prohibits negotiating TLS 1.0 and TLS 1.1"),
    ("NIST SP 800-52r2", "NIST SP 800-52r2", "SS3.1",
     "defines the TLS versions a server shall and shall not be configured to use, and "
     "requires TLS to protect transmitted data"),
    ("RFC 3207", "RFC 3207", "SS6",
     "documents that a man-in-the-middle can strip the SMTP STARTTLS capability"),
    ("RFC 2595", "RFC 2595", "",
     "defines STARTTLS for IMAP and STLS for POP3"),
    ("RFC 8314", "RFC 8314", "SS3",
     "declares cleartext email submission and access obsolete and specifies implicit "
     "TLS on the dedicated ports"),
)

UNMAPPED_STANDARD = "UNMAPPED"


def resolve(text: str) -> StandardCitation:
    """Structure one standards string, preserving it verbatim."""
    stripped = text.strip()
    for marker, standard, section, reason in _REGISTRY:
        if marker in stripped:
            return StandardCitation(standard=standard, section=section,
                                    reason=reason, text=stripped)
    # Not recognised: keep it, flag it, never discard it.
    return StandardCitation(
        standard=UNMAPPED_STANDARD, section="",
        reason="cited by a rule but not present in the Phase-7 standards registry; "
               "carried through verbatim rather than dropped",
        text=stripped)


def resolve_all(texts: Iterable[str]) -> Tuple[StandardCitation, ...]:
    """Structure a rule's standards tuple, de-duplicated and deterministically ordered."""
    seen: Dict[Tuple[str, str], StandardCitation] = {}
    for text in texts:
        if not text or not text.strip():
            continue
        citation = resolve(text)
        seen.setdefault((citation.standard, citation.text), citation)
    return tuple(sorted(seen.values(), key=lambda c: (c.standard, c.section, c.text)))


def summarise(citations: Sequence[StandardCitation]) -> Dict[str, object]:
    """Standards summary for the assessment: which standards the findings rest on."""
    by_standard: Dict[str, List[str]] = {}
    for citation in citations:
        by_standard.setdefault(citation.standard, [])
        if citation.section and citation.section not in by_standard[citation.standard]:
            by_standard[citation.standard].append(citation.section)
    unmapped = sorted({c.text for c in citations if c.standard == UNMAPPED_STANDARD})
    return {
        "standards": {k: sorted(v) for k, v in sorted(by_standard.items())
                      if k != UNMAPPED_STANDARD},
        "distinct_standards": len([k for k in by_standard if k != UNMAPPED_STANDARD]),
        "unmapped_citations": unmapped,
        "note": ("every citation originates from a Phase-4/5 rule; the Phase-7 registry "
                 "adds structure and introduces no new standard"),
    }
