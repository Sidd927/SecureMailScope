# ADR-0012 — Per-protocol state machines behind one session contract
**Status:** Accepted 2026-09-16

**Context** Phase 3 must reconstruct SMTP, IMAP and POP3 dialogue. The three grammars are
genuinely different: numeric response codes vs tagged responses with untagged `*` data lines vs
`+OK`/`-ERR` indicators.

**Problem** One generic parser, or three separate ones?

**Options** (a) single regex/keyword matcher over payload; (b) three unrelated implementations;
(c) three protocol state machines behind a common `ProtocolSessionReconstructor` producing one
`SessionEvidence`.

**Evidence** Phase-3 §10 forbids `if "STARTTLS" in payload`. Empirically, naive matching fails
three ways: tshark truncates SMTP commands to 4 chars, the SMTP capability reply is multi-valued,
and the POP3 CAPA body is exposed as empty strings.

**Decision** (c). Shared pipeline (grouping, dedupe, TLS classification, completeness, transition
recording) in `base.py`; per-protocol event extraction and advertisement semantics in
`protocols.py`. Transitions are a declarative `event × from-state → to-state` table.

**Rejected** (a) demonstrably wrong on real tshark output and unable to express state; (b)
triplicates the shared logic and would drift.

**Consequences** + one contract for Phase 4/5; per-protocol correctness; transitions individually
testable. − three parsers to maintain.

**Risks** grammar gaps on unusual servers → adversarial corpus + notes for ignored events.

**Open questions** OQ-42: multi-vendor banner diversity (rolled into OQ-33r).
