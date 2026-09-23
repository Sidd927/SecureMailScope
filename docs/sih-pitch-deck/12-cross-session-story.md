# 12 — The cross-session story

Our headline differentiator. Built from **real engine output**, not an illustration
(`docs/finalization/06-cross-session-demo.md`).

---

## The problem, in one sentence a judge immediately feels

> A server that never offered STARTTLS and an attacker who stripped it produce **byte-identical**
> captures. Looking at one session, you cannot tell them apart — you can only guess, or stay silent.

## The mechanism

Compare the session against **comparable prior sessions at the same endpoint, protocol and TLS
mode**, within the same capture. A baseline requires **≥5 prior comparable sessions**
(`DEFAULT_MIN_HISTORY = 5`); below that the engine abstains rather than infers.

## The real result — positive case

`G_control_endpoint.pcap`, 12 SMTP sessions to one server:

| | |
|---|---|
| **SESSIONS A–E** | one client, 5 sessions, never upgrades — *self-consistent, unremarkable alone* |
| **CONTROL ENDPOINT** | 6 sessions from **other clients**, same server, **all upgrade successfully** |
| **SESSION F** (same client) | still no upgrade |
| **BASELINE** | this client: consistently no upgrade. Other clients: consistently upgrade. |
| **DEVIATION** | the difference is between *clients*, not within one client's history |
| **ENGINE OUTPUT** (verbatim) | *"This endpoint consistently lacks the upgrade capability while comparable endpoints at the same server consistently have it."* — `CS-STARTTLS-001`, **OBSERVED_ISSUE, MEDIUM** |
| **CONCLUSION** | a capability/configuration difference worth an analyst's attention |
| **LIMITATION** (engine's own words) | *"Per-client server policy and interference are indistinguishable here."* |

**Note the phrasing.** The finding says *deviation*, never *attack*. That restraint is the point.

## The real result — negative case (equally important)

`H_no_control.pcap`, 6 sessions, **one client only, no control endpoint**:

| | |
|---|---|
| **ENGINE OUTPUT** (verbatim) | *"Advertisement behaviour matches the established baseline… No comparable control endpoint was available to corroborate this from a second angle."* — **COMPLIANT** |
| **STATED LIMITATION** | *"Passive PCAP evidence alone cannot distinguish a consistently legitimate plaintext configuration from a consistently stripped STARTTLS configuration when no unaffected comparable control endpoint or other differentiating evidence exists."* |

**This is a feature.** Consistent stripping across every session is passively indistinguishable
from a server that simply never offers STARTTLS. The engine says so, unprompted, in the same
finding as its verdict — rather than reporting false reassurance.

## The slide visual

```
   Same server, same capture
   ┌─────────────────────────────────────────────┐
   │  Client A:  ✗ ✗ ✗ ✗ ✗   (never upgrades)    │
   │  Others:    ✓ ✓ ✓ ✓ ✓ ✓ (always upgrade)    │  ← CONTROL ENDPOINT
   └─────────────────────────────────────────────┘
                      ↓
        Control endpoint present?
         ┌────────────┴────────────┐
       YES                         NO
         ↓                          ↓
   Deviation reported          Abstain + state
   (MEDIUM, evidenced)         the limitation
         ↓                          ↓
   "deviates from comparable   "passively indistinguishable
    endpoints"                  from legitimate config"
```

Both branches shown. The right-hand branch is what makes the left-hand branch credible.

## Where it goes

- **Slide 2:** the *claim* — cross-session reasoning, with the byte-identical framing.
- **Slide 3:** the *diagram* above, inside or beside the pipeline.
- Real quoted output is **Q&A ammunition**, not slide text — it is too long for a slide but
  devastating when produced under questioning.

## Honest caveat to carry

The real 10-capture OQ-33r corpus has **too few same-server sessions** to trigger a live baseline;
this demonstration uses the golden corpus, which is generated (though realistic) traffic. If asked,
say exactly that. It does not weaken the mechanism — it bounds the claim.
