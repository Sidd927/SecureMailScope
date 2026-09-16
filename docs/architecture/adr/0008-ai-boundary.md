# ADR-0008 — AI analyst layer: optional, read-only, grounded
**Status:** Accepted 2026-09-16 · **DEFERRED from initial prototype on approval 2026-09-16** — not built in v1; interface boundary kept documented so it can be added later without touching the security engine. Rationale: not PS-required, adds attack surface + validation + deployment cost; the ML anomaly lane already satisfies the architectural AI requirement more directly.
**Context** 10B: LLM adds analyst ergonomics, not security; every competitor's AI is empty; email text
is attacker-controlled.
**Problem** If/how to include an LLM.
**Decision** Optional analyst-facing layer: NL query over evidence (primary) + grounded explanation
(optional). Receives the structured grounding contract (10B §5 / Finding object), never raw PCAP text.
Cannot write/alter findings or convert evidence states. Offline local 7–8B; cloud rejected as a
requirement. `--no-ai` yields identical security findings.
**Rejected** LLM in security path (10B); cloud dependency (I-01, breaks offline); LLM-decided severity (ADR-0004).
**Consequences** + safe ergonomic layer, differentiator (no competitor has NL query). − model packaging (OQ-26).
**Risks** prompt injection → contained (10B §12, 06 §4); hallucination → citation post-validator + refusal path.
**Open questions** OQ-26 local model size/licensing.
