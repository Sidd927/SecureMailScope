# ADR-0014 — Client-scoped prior-history baselines with cross-client contrast
**Status:** Accepted 2026-09-18

**Context** Phase 5 must add historical and control evidence without manufacturing
certainty. OQ-25/OQ-28 established what works and what backfires.

**Problem** How should a comparable population be scoped, and how should history and
control evidence combine?

**Options** (a) one capture-wide baseline per server; (b) server-scoped baseline; (c)
client-scoped baseline plus an explicit cross-client contrast.

**Evidence** 02A §6: capture-wide pooling produced false positives on legitimate
mid-capture reconfiguration (FP 20 → 0 with prior-history). 02A §4: the useful axis is
whether the comparison spans multiple clients of one server; `pair+proto` with an explicit
contrast and `server+proto` alone were equivalent. Implementing (b) first produced a mixed
victim/control baseline that suppressed the very contrast the research showed is decisive.

**Decision** (c). `ComparabilityKey` includes client identity, so a client's own prior
sessions form its baseline, while controls are sessions to the same server from *other*
clients. Baselines use strict prior-history ordering with a bounded recent window and an
explicit `min_history` abstention. Contrast follows the ADR-0005 four-state machine.

**Rejected** (a) demonstrably false-positive-prone; (b) destroys contrast by pooling
affected and unaffected clients into one population.

**Consequences** + reproduces both OQ-25 results (control present → supported deviation;
control absent → abstention); + legitimate client diversity yields `CONTRAST_AMBIGUOUS`
rather than a finding. − client-scoped keys fragment history, so abstention is common on
small captures, which is the intended conservative behaviour.

**Risks** NAT/shared client identity collapses distinct clients into one key (known
limitation, 02A §9 #5) → recorded as a limitation, not silently absorbed.

**Open questions** OQ-44: whether a per-endpoint server-scoped baseline should supplement
the client-scoped one where client identity is unreliable.
