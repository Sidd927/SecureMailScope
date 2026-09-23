# 07 — Core narrative (the hook)

Not a slogan exercise. The candidate framings were tested against the actual implementation, the
PS text, differentiation evidence, and overclaim risk.

---

## Candidates evaluated

| # | Framing | Verdict |
|---|---|---|
| A | *"AI detects malicious encrypted email traffic."* | ❌ **Rejected — false.** The ML lane has zero demonstrated detection value (ADR-0024). This framing is the single most dangerous thing we could say. |
| B | *"Analyze encrypted email traffic without decrypting it."* | 🔸 True and appealing, but **describes every passive TLS analyzer**, including all five audited competitors and tshark itself. Zero differentiation. |
| C | *"Turn passive email PCAPs into cryptographic security posture."* | 🔸 Accurate and clear — but again describes the whole competitive field. It states the *category*, not our contribution. |
| D | *"Reason across encrypted email sessions rather than analyzing packets in isolation."* | ✅ **Strongest differentiator.** Audit-backed (0 of 5 competitors implement it), directly solves a real inference problem, and is comprehensible in one sentence. |
| E | *"Evidence-backed cryptographic assessment with uncertainty preservation."* | ✅ Strong and genuinely differentiating, but **abstract** — "uncertainty preservation" needs a paragraph before a judge feels it. Better as support than as the hook. |
| F | Discovered alternative: *"It tells you what it can't tell you."* | 🔸 Memorable and true, but leads with a limitation — risky as an opening frame for a competitive evaluation. |

## Selected narrative

> **SecureMailScope reads a passive email packet capture and produces a standards-cited
> cryptographic security posture — by reasoning across comparable prior sessions at the same
> endpoint rather than judging each connection alone, which is what makes it possible to tell a
> stripped STARTTLS from a client that simply declined.**

**Why this wins:** it is **D anchored in C**. C establishes what the system *is* in terms a judge
already understands (PCAP in, security posture out). D supplies the *why it's different*, and it is
the one differentiator we can defend with a source-code audit. E becomes the supporting theme on
Slides 3–4 rather than the headline.

## The one-sentence version (Slide 2 headline)

> **Reasoning across sessions, not just parsing packets.**

## The compressed logic chain

1. Email transport security fails silently; after an incident the PCAP is the evidence.
2. But that evidence is **encrypted, ambiguous, and incomplete** — TLS 1.3 hides the certificate;
   a stripped STARTTLS looks byte-identical to a declined one.
3. Judging each session alone, you must either **guess** or **stay silent**.
4. Comparing a session against comparable prior sessions at the same endpoint **resolves** what
   one session cannot.
5. And where even that isn't enough, the system **says so explicitly** instead of guessing.
6. Result: a posture assessment an analyst can put in a report and defend under review.

## Tone rules

- Lead with the **inference problem**, not the technology stack.
- Never let "AI" carry the hook — the PS title supplies the AI framing; our credibility comes from
  the deterministic engine and the honest AI boundary.
- Limitations are presented as **engineering rigour**, never as apology.
- Say "our source audit found none of five competing implementations do this" — never "we are the
  first."
