# ADR-0002 — Canonical evidence schema with per-field evidence states
**Status:** Accepted 2026-09-16
**Context** Forensic tool must never claim more than the capture supports (01A/02B).
**Problem** How to represent facts so silent over-claiming is impossible?
**Options** (a) bare values; (b) values + a separate confidence column; (c) EvidenceField<T> wrapper
carrying value+state+basis+provenance+frames.
**Evidence** 04; competitors reduce STARTTLS to one boolean and conflate absence with negative (01B/01D).
**Decision** Option (c). Every non-structural field is an EvidenceField (03 §2).
**Rejected** (a) enables the forbidden conversions; (b) lets consumers ignore state.
**Consequences** + structural prevention of UNKNOWN→FALSE etc.; auditable. − more verbose objects/serialisation.
**Risks** developer bypasses `.state` → mitigate via code-review skill + unit tests on access patterns.
**Open questions** none blocking.
