# ADR-0013 — Deterministic rule registry with three-axis findings
**Status:** Accepted 2026-09-18

**Context** Phase 4 must turn reconstructed sessions into security findings that survive
review by a sceptical security engineer. The research repeatedly showed the failure mode
to avoid: turning absence of evidence into evidence of attack.

**Problem** How should security conclusions be structured, and how do we stop the engine
over-claiming?

**Options**
(a) one module of `if` checks returning strings;
(b) findings with a single "risk" scalar;
(c) a rule registry producing findings with **severity, evidence state and analytic
status as three orthogonal fields**, with invariants enforced at construction.

**Evidence** 02B §3.1 proved `B_strip_advert` (attack) and `I_no_support` (legitimate)
are byte-identical at the application layer. Any design that forces PASS/FAIL, or that
lets confidence and impact share one number, must fabricate a distinction there.

**Decision** (c). `SecurityFinding` carries `severity` (impact if true), the Phase-3
`EvidenceState` on each `EvidenceRef` (how well supported), and `FindingStatus` (the
outcome, including AMBIGUOUS / INSUFFICIENT_EVIDENCE / NOT_OBSERVABLE). Two invariants
are enforced in `__post_init__`: only OBSERVED_ISSUE may exceed INFO severity, and an
OBSERVED_ISSUE must cite a standards basis. Rules are small, pure, independently
testable units in a registry with stable ordering and content-derived finding ids.

**Rejected** (a) untestable and invites ad-hoc severity; (b) collapses confidence into
impact, which is precisely the dishonesty the research warns against.

**Consequences** + over-claiming becomes a construction-time error rather than a review
comment; findings are diffable and reproducible. − more structure than a simple checker;
rule authors must choose a status deliberately.

**Risks** rule-set gaps look like "no issue" → mitigated by COMPLIANT/INFORMATIONAL
findings making silence explicit, and by documenting non-implemented conditions.

**Open questions** OQ-43: how Phase 5 should upgrade an AMBIGUOUS advertisement finding
when cross-session evidence resolves it, without mutating the Phase-4 finding.
