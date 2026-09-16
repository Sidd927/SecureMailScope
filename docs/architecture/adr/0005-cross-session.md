# ADR-0005 — Cross-session / temporal reasoning as a first-class layer
**Status:** Accepted 2026-09-16
**Context** Per-session detection is inverted (fires on benign decline, blind to stripping) — proven
02A/02B. Cross-session reasoning is our only verified differentiator (01D §4).
**Problem** How to distinguish configuration from deviation without over-claiming?
**Evidence** 02A (−71% FP), 02B (−72% FP on real packets), control-endpoint FN 6→0. Time-aware beats
capture-wide pooling (02A §6). Two failure modes: 100%-strip-no-control, NAT identity.
**Decision** Dedicated `crosssession` component: baselines (server/client/pair/pair+proto/temporal),
prior-history (time-aware), control-endpoint contrast via an **evidence-driven policy** (below), not a binary on/off flag, explicit `INSUFFICIENT_HISTORY` abstention below ~5 sessions.
**Rejected** capture-wide pooling (02A §6 worse); forcing a verdict (produces the inversion).
**Consequences** + the differentiator; honest abstention. − needs multi-session captures to add value.
**Risks** NAT identity collapse (OQ-29); universal stripping undetectable (accepted, 06 §8).
**Open questions** OQ-29 identity model, OQ-30 contrast-rule default.


---
## Contrast policy (modified on approval, 2026-09-16)
Replaces the binary "control exists → ON" gate with an evidence-driven state machine that records
*why* a contrast was or was not performed:
```
comparable sessions?  ── NO ──> CONTRAST_NOT_APPLICABLE
        │ YES
sufficient evidence?  ── NO ──> CONTRAST_INSUFFICIENT
        │ YES
conflicting readings? ── YES ─> CONTRAST_AMBIGUOUS
        │ NO
        └──> CONTRAST_SUPPORTED → perform contrast
```
Never manufacture a control relationship. The chosen state is recorded on the finding's
`baseline_context` so the analyst sees the reasoning. Supersedes OQ-30 (no longer a default flag).
