# 04 — Judge cognitive journey

Mapped onto the **actual official slide structure**, not an idealized narrative. The judge is
reading a PDF, probably quickly, possibly alongside dozens of others.

---

## Slide 1 — TITLE PAGE

| | |
|---|---|
| **JUDGE QUESTION** | "Which problem statement is this, and is it filled in correctly?" |
| **OUR ANSWER** | SIH26159 · NTRO · Software · Blockchain & Cybersecurity · team metadata |
| **EVIDENCE** | the PS record itself |
| **VISUAL** | official template title layout, unmodified |
| **TAKEAWAY** | "Correctly submitted, right problem statement." |

**Design note:** this slide wins nothing and can lose something (wrong ID, missing team name).
Treat it as a compliance checkbox. Do not try to make it clever.

## Slide 2 — IDEA TITLE / Proposed Solution

| | |
|---|---|
| **JUDGE QUESTION** | "What is it, why is it needed, and what's actually new here?" |
| **OUR ANSWER** | A passive forensic engine that turns an email PCAP into a cited cryptographic security posture — and that reasons **across sessions**, which is what lets it tell a stripped STARTTLS from a client that simply declined. |
| **EVIDENCE** | competitor source audit (0 of 5 implement cross-session); the byte-identical-ambiguity argument |
| **VISUAL** | small before/after: two byte-identical-looking sessions → cross-session evidence separates them |
| **TAKEAWAY** | "They're not just parsing TLS — they solved an inference problem the obvious approach can't." |

**This is the most important slide in the deck.** If the judge takes only one thing, it is this.

## Slide 3 — TECHNICAL APPROACH

| | |
|---|---|
| **JUDGE QUESTION** | "Is there a real system here, or a concept? What's it built from?" |
| **OUR ANSWER** | Python + tshark, zero third-party runtime dependencies in the core; a 9-stage pipeline; 16 standards-bound rules + 3 cross-session rules; six evidence states; bounded ML. |
| **EVIDENCE** | the pipeline diagram; 11 standards; the dashboard screenshot |
| **VISUAL** | **pipeline flow diagram** (primary) + evidence-state strip (secondary) |
| **TAKEAWAY** | "This is engineered, not sketched." |

## Slide 4 — FEASIBILITY AND VIABILITY

| | |
|---|---|
| **JUDGE QUESTION** | "Does it actually work? What breaks it? Are they aware of their own limits?" |
| **OUR ANSWER** | 1219 tests; validated on 10 real Postfix/Dovecot captures; 20/20 reproducible demo runs; 115–320 ms per capture; offline. **And**: TLS 1.3 hides certificates, trust can't be validated passively, AI showed no detection value — each named with its mitigation. |
| **EVIDENCE** | test counts, real-corpus results, the two PARTIAL requirements |
| **VISUAL** | compact results strip + a short risks/mitigations table |
| **TAKEAWAY** | "They know exactly what their system can and cannot prove — which makes me trust the parts that work." |

**Strategic insight:** the official pointer *asks* for "potential challenges and risks." Most
teams invent soft risks ("scalability", "adoption"). We have **real, technical, measured** ones.
Stating D-11 and A-02 here is not a confession — it is the strongest available evidence of rigour,
placed exactly where the template asks for it.

## Slide 5 — IMPACT AND BENEFITS

| | |
|---|---|
| **JUDGE QUESTION** | "Who uses this, and what does it change for them?" |
| **OUR ANSWER** | SOC / DFIR / incident-response / mail administrators get a defensible, citable posture assessment from evidence they already collect, with no server access, no keys, and no internet. |
| **EVIDENCE** | PS-named user groups; offline + passive architecture; 3 export formats |
| **VISUAL** | before/after analyst workflow, or a 3-column benefit strip |
| **TAKEAWAY** | "This fits a real workflow and produces something an analyst can put in a report." |

**Danger zone:** this is where decks fabricate market sizes and ROI. We have none. Impact must be
**operational and qualitative**, and it can be — the passive/offline/citable properties are
genuinely valuable and fully defensible.

## Slide 6 — RESEARCH AND REFERENCES

| | |
|---|---|
| **JUDGE QUESTION** | "Is this grounded in anything real, or self-invented?" |
| **OUR ANSWER** | 11 published standards, the authoritative PS record, and an in-repo research corpus including a source-code audit of competing implementations. |
| **EVIDENCE** | the citation list itself |
| **VISUAL** | clean two-column reference list |
| **TAKEAWAY** | "Standards-grounded, not hand-waved." |

---

## The one-line arc

> **2:** here's the inference problem nobody else solves → **3:** here's the engineered system that
> solves it → **4:** here's proof it works *and* proof we know its limits → **5:** here's who
> benefits → **6:** here's the ground truth we built on.
