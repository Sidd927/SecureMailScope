# 13 — The evidence / forensic-honesty story

Our second-strongest differentiator, and the cheapest to make visual.

---

## The core idea, one sentence

> **The system never turns missing evidence into a security conclusion — in either direction.**

Not "no findings = secure". Not "can't see it = broken". Both are lies a forensic tool must refuse
to tell.

## The six states

```
OBSERVED         directly present in the captured bytes
INFERRED         follows from observed facts + a cited standard
AMBIGUOUS        the evidence supports more than one reading
INCOMPLETE       the capture is truncated at the relevant point
UNKNOWN          insufficient evidence to decide
NOT_OBSERVABLE   structurally impossible to see passively
```

Six labels, six short glosses. This renders as a clean vertical strip and needs no prose.

## Why it matters — the four places it earns its keep

| Situation | Naive tool | SecureMailScope |
|---|---|---|
| TLS 1.3 session | "no certificate found" → reads as a defect | `NOT_OBSERVABLE` — *"the negotiated version encrypts the Certificate message (RFC 8446 §2)"* |
| Truncated capture | silently partial results | `INCOMPLETE` — truncation named as the cause, distinct from absence |
| STARTTLS never advertised | flags an attack, or ignores it | `AMBIGUOUS` — stripping and genuine non-support are byte-identical here |
| Certificate trust | "valid ✓" from a bundled root store | `NOT_OBSERVABLE` — no trust anchor exists in a PCAP (RFC 5280 §6) |
| Too few sessions to baseline | invents a verdict | abstains — *"no anomaly is inferred from the absence of history"* |

## The structural guarantee (the part a technical judge will appreciate)

This is not a convention — it is **enforced in code**. (Note: the statuses named in this
paragraph are `FindingStatus` values — the *analytic outcome* of a rule — which is a different
vocabulary from the six `EvidenceState` values above. See `DO-NOT-CLAIM.md` §A.) A finding whose status is
`AMBIGUOUS`/`INSUFFICIENT_EVIDENCE`/`NOT_OBSERVABLE`/`COMPLIANT`/`INFORMATIONAL` **cannot carry a
severity above INFO**; the constructor raises. And the posture score is **coverage-gated**: the
band is withheld below 50% assessed coverage, so a capture that shows too little gets
`INSUFFICIENT_EVIDENCE`, never a good grade.

> **Missing evidence can never improve a score.**

That sentence is the single best one-line summary of this differentiator.

## Where it goes

- **Slide 3:** the six-state strip as the secondary visual, with the one-line guarantee beneath it.
- **Slide 4:** its consequences appear as the risks/mitigations rows (TLS 1.3, trust, ML).

## The strongest supporting quote (Q&A, not slide)

From a real finding: *"absence of certificate evidence is not evidence of an absent, invalid or
untrusted certificate."*

## Do not

- Do not compress six states into three — the granularity *is* the contribution.
- Do not present this as a UI feature. It is an architectural invariant, enforced by tests.
- Do not claim competitors lack it entirely — one audited competitor has a partial equivalent
  (`08-differentiation-analysis.md`).
