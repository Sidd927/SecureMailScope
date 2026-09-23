# 10 — The AI story

The PS title is *"AI-Assisted Cryptographic Security Posture Assessment"*. The deck **must**
address AI. It must also not lie. This document resolves that tension.

---

## The empirical reality (non-negotiable)

- A real unsupervised anomaly model ships: `robust-z-sum`, fitted on 44 governed features.
- Leakage controls are structural: `FORBIDDEN_INPUTS` excludes `rule_id`, `severity`,
  `finding_status`, `ground_truth`, `label`, `generator`, `scenario` — the model **cannot** be
  trained on the deterministic engine's own answers.
- It was evaluated properly: generator-held-out splits, a label-free usability gate, nine candidate
  configurations.
- **Result: zero unique true detections on every held-out split** (ADR-0015), unchanged after
  Phase-11 features were added and re-measured (ADR-0024).
- Therefore it ships **bounded**: max adjustment **4.0** against a **30-point** severity-tier gap —
  it can re-order findings within a tier and can never create, promote, or demote one.
- `--no-ai` equivalence is **proven end-to-end**, not asserted.

## How much AI belongs in the deck?

**Roughly three lines on Slide 3, one risk row on Slide 4. Nothing on Slide 2.**

Rationale: the hook must be the deterministic + cross-session engine (`07-core-narrative.md`). If
AI leads, a technical judge will immediately probe detection performance — and the honest answer
is "zero unique true detections," which is a bad thing to discover *after* we've led with AI. Lead
with what's strong; present AI where its bounded role is a *design virtue*.

## The strongest honest AI narrative

> **AI is used where it is defensible — and deliberately bounded where it is not.**
> An unsupervised anomaly model scores every session and can re-prioritise findings *within* a
> severity tier. It cannot create a security finding, and it cannot move one across a tier —
> capped at 4.0 against a 30-point gap. We evaluated it on generator-held-out data and it showed
> no independent detection value, so we ship it as a prioritisation signal with that result stated
> rather than hidden. **Every security conclusion is produced by deterministic, standards-cited
> rules and is provably identical with the AI lane switched off.**

This is a *stronger* position than an unsupported detection claim, and it is defensible against
the hardest question a judge can ask.

## Why this satisfies "AI-Assisted"

The PS (doc 19 §3) requires *"Application of AI/ML techniques"* for risk classification, anomaly
detection, posture scoring, prioritisation and mitigation — it **does not prescribe a trained
detector, an accuracy target, or an architecture**. We ship a real, evaluated ML technique
performing prioritisation, plus deterministic engines for the rest. That is an honest reading of
the requirement, and A-02 is reported PARTIAL precisely because we refuse to overstate it.

## The visual for the AI lane

A **two-lane diagram**, inside the Slide 3 pipeline:

```
   deterministic lane  →  rules → findings → posture      ← ALL security facts
   ML lane             →  anomaly score → ranking only    ← capped 4.0 / 30-pt tier gap
                                    ↑ never writes a finding
```

One arrow crossing into ranking only, visually blocked from findings. If a judge reads nothing
else on the slide, that blocked arrow communicates the entire AI boundary.

## Wording that must NEVER appear

"AI detects attacks" · "ML identifies malicious traffic" · "AI-powered threat detection" ·
"intelligent threat identification" · any accuracy/precision/recall figure · "AI validates
certificates" · "AI determines security posture".

## Wording that is safe

"bounded secondary prioritisation signal" · "cannot cross a severity tier" · "evaluated on
generator-held-out data" · "deterministic rules remain the single source of security truth" ·
"provably identical with AI disabled".
