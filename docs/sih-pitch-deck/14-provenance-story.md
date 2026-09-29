# 14 — The provenance story

Powerful, real, and **competing for space**. This document decides how much of it survives.

---

## What we actually have

```
PCAP file
  └─ SHA-256 ──────────────► capture_id
                                └─ frame number + TCP stream + timestamp
                                     └─ evidence state + provenance label
                                          └─ finding (rule id + cited standard)
                                               └─ posture assessment  ─► assessment_id (content-addressed)
                                                    └─ report ─────────► report_sha256
```

Every link is real and verified: traced live across 13 capture executions during finalization with
zero mismatches; artifacts are **re-hashed on access**, not trusted from write time; `assessment_id`
is content-addressed, so re-running the same evidence yields the same identity.

## The honest verdict on slide space: **a strip, not a diagram**

A full provenance diagram is genuinely impressive — and it would compete directly with the
**pipeline diagram** on Slide 3, which is mandatory (the template asks for flow charts) and
carries more argumentative weight.

**Decision: one horizontal strip, one line, at the foot of Slide 3.**

```
PCAP SHA-256 → frame → TCP stream → evidence state → finding → cited standard → signed report
```

Eight tokens, one line. A judge who cares reads it; a judge who doesn't loses nothing.

## The one supporting sentence

> **Every conclusion traces back to specific frames, and every artifact is content-addressed and
> re-verified on access.**

## Why not more

Provenance answers *"can I trust the output?"* — a **second-order** question. The deck must first
win *"is this different?"* (Slide 2) and *"is it real?"* (Slides 3–4). Provenance is the answer to
a question the judge only asks if the first two land. It is therefore **Q&A-first, slide-second**.

## Q&A escalation path

If a judge asks "how do I know a finding isn't fabricated?", the answer escalates in three steps:
1. every finding carries frame numbers and a rule id;
2. every artifact is content-addressed and re-hashed when read;
3. re-running the identical capture produces the identical `assessment_id` — determinism is
   verifiable, not asserted.

## The one thing to avoid

Do **not** call this "chain of custody." It is traceability *within the tool's analysis*, not a
certified legal evidentiary process — and a forensics-literate judge will catch the difference.
