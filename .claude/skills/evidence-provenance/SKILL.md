---
name: evidence-provenance
description: Evidence-state and traceability discipline. Trigger whenever a fact, finding, or field is produced, stored, displayed, or sent to the AI layer.
---
# evidence-provenance

Every fact carries a state: **OBSERVED** (present in captured bytes), **INFERRED** (deduced from
observed facts, basis recorded), **UNKNOWN** (insufficient evidence), **AMBIGUOUS** (>1 valid reading),
**INCOMPLETE** (capture truncated at this point), **NOT_OBSERVABLE** (structurally impossible passively,
e.g. TLS 1.3 cert).

Forbidden silent conversions: UNKNOWN→FALSE, UNKNOWN→SECURE, INFERRED→OBSERVED, AMBIGUOUS→ATTACK,
INCOMPLETE→NORMAL, NOT_OBSERVABLE→FALSE.

Certificate/finding provenance tag: `observed | inherited | historical | retrieved | decrypted`.
Every finding links to frames + stream IDs. Evidence confidence ≠ model confidence — keep separate fields.
The system must be comfortable outputting "not enough evidence to determine this."
