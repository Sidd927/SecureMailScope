# 14 — Cross-Session Reasoning (Phase 5)

**Status:** Implemented. **Date:** 2026-09-18 · **ADR:** 0014 · **Code:** `src/securemailscope/crosssession/`

    SessionEvidence[] → comparability → baseline → contrast → CrossSessionFinding[]

Supplements Phase 4, never replaces it. Deterministic, no ML, no network, no wall-clock
dependence (temporal reasoning uses capture timestamps only).

| Phase | Question |
|---|---|
| 3 | What was observed? |
| 4 | What does one session mean on its own? |
| **5** | **How does this session compare with other evidence?** |

## Comparability (§5)
A baseline may only be built from sessions that are *actually* comparable.
`ComparabilityKey` = **client + server + port + protocol + TLS mode**. Client identity is
in the key because 02A §4 found the workable split is a **client-scoped baseline plus an
explicit cross-client contrast**; pooling all clients of a server mixes
heterogeneous-but-legitimate populations and destroys the contrast signal. Implicit and
explicit TLS are never pooled — different protocol behaviours (Phase-3 §17).

Outcomes: `COMPARABLE` · `NOT_COMPARABLE` · `INSUFFICIENT_EVIDENCE` · `AMBIGUOUS`.
Truncated sessions are excluded: their behaviour may be a capture artefact.

## Baseline (§6–§8)
- **Prior-history only.** A session is compared against sessions that *precede* it. 02A §6
  showed capture-wide pooling causes false positives on legitimate mid-capture
  reconfiguration (FP 20 → 0 when switched to prior-history).
- **No invented time window.** The experiment established that *ordering* matters, not any
  duration. The temporal policy is strict precedence by `(timestamp, frame, stream)` —
  exactly what was tested. We deliberately do not invent "last N minutes".
- **Bounded recent window** (`max_history`, default 50): the same principle as
  prior-history — recent behaviour is the relevant comparison, and unbounded pooling both
  dilutes a legitimate reconfiguration and makes analysis quadratic. This is a *bound*,
  not an empirical claim; the experiments measured only the minimum usable history.
- **Abstain below threshold** (`min_history`, default **5**, from 02A §5, which records 5
  as a chosen parameter, not a derived one). Below it: `INSUFFICIENT_HISTORY`.
- Only a **consistent** baseline establishes an expectation. Mixed history ⇒ no claim.

## Contrast (§9, ADR-0005 vocabulary)
`CONTRAST_SUPPORTED` · `CONTRAST_INSUFFICIENT` · `CONTRAST_NOT_APPLICABLE` ·
`CONTRAST_AMBIGUOUS`. A control is a session to the **same server** from a **different
client**. Controls that disagree among themselves yield `CONTRAST_AMBIGUOUS` — that is the
legitimate-client-diversity false-positive mode from 02A (where the contrast rule took FP
from 0 to 20). Never a boolean flag; the state and reason are recorded on the finding.

## Deviation vocabulary (§15)
`NONE` · `DEVIATION` (differs from a consistent baseline) · `SUSPICIOUS_DEVIATION`
(differs **and** contrast corroborates) · `NOT_ASSESSED`. Severity stays INFO unless the
status is `OBSERVED_ISSUE`; a difference is not an attack.

## Provenance (§13)
Every finding carries the comparability decision, the baseline (status, sample count,
window, feature distributions, **concrete member session refs with membership reason**),
and the contrast result (state, reason, control session refs, upgrade rate). A finding
never cites "a baseline exists".

## The limitation we preserve (§24)
> Passive PCAP evidence alone cannot distinguish a consistently legitimate plaintext
> configuration from a consistently stripped STARTTLS configuration when no unaffected
> comparable control endpoint or other differentiating evidence exists.

This string is attached verbatim to every finding touching the stripping question. It is
not hidden; it is the scientific boundary of the method.

## Performance
Profiling showed the naive implementation was quadratic (6.2 ms/session at n=16000). A
one-pass `PopulationIndex` (by key, by endpoint, plus per-endpoint client diversity),
window-before-filter slicing, and an early exit when an endpoint has only one client made
it linear: **~0.115 ms/session, flat from n=2000 to n=16000** (99.2s → 1.9s at n=16000).
A scaling regression test guards against reintroducing it.
