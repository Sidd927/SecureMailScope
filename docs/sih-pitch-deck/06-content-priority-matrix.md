# 06 — Content priority matrix

Internal prioritisation. Scores are **not** exposed in the deck; only the resulting class is used.
Dimensions weighed: problem relevance · SIH requirement relevance · technical differentiation ·
judge comprehension · evidence strength · visual value · demo value · impact · space efficiency ·
overclaim risk.

---

## MUST HAVE (earns slide space unconditionally)

| Item | Slide | Why it survives |
|---|---|---|
| Cross-session reasoning as the core idea | 2 | highest differentiation + strongest evidence + directly satisfies the mandatory "innovation and uniqueness" pointer |
| The STARTTLS byte-identical-ambiguity framing | 2 | makes the problem *and* the solution legible in one visual; nothing else explains "why is this hard?" so cheaply |
| Pipeline / architecture diagram | 3 | the template explicitly asks for flow charts; proves a real system |
| Technologies list (Python, tshark, zero deps) | 3 | mandatory pointer ("technologies to be used") |
| 16 rules + 3 cross-session rules | 3 | concrete, verifiable, compact |
| Six evidence states | 3 | second-strongest differentiator, and highly visual |
| AI bounded (4.0 vs 30-point tier gap) | 3 | title says "AI-Assisted" — must be addressed, and this is the honest framing |
| 1219 tests, 0 failures | 4 | single strongest "this is real" signal |
| 10 real Postfix/Dovecot captures | 4 | real-world validation, not toy data |
| TLS 1.3 certificate limitation | 4 | mandatory "risks" pointer; pre-empts the most likely judge challenge |
| D-11 + A-02 stated honestly | 4 | converts the deck's biggest vulnerability into its strongest credibility signal |
| PS-named user groups | 5 | mandatory "target audience" pointer, PS-sourced |
| Passive + offline + no keys | 5 | genuine operational benefit, architecturally guaranteed |
| 11 published standards | 6 | slide 6 exists for exactly this |

## SHOULD HAVE (include if the layout breathes)

| Item | Slide | Note |
|---|---|---|
| Dashboard screenshot | 3 or 5 | best proof-of-realness image available; needs to be captured (none exists yet) |
| 115–320 ms performance | 4 | one number only; supports feasibility |
| 20/20 reproducible runs | 4 | strong, but can be folded into the test number if space is tight |
| JSON/HTML/PDF export | 5 | concrete deliverable |
| Weak-certificate result (RSA-1024 + SHA-1 → CRITICAL) | 4 | vivid, but **must** be labelled a generated fixture |
| Provenance chain strip | 3 | powerful but competes with the pipeline diagram |

## NICE TO HAVE (only if a slide is visibly empty)

- Coverage-gated scoring ("the band is withheld below 50% coverage")
- 25-capture golden corpus count
- Zero-npm dashboard
- Content-addressed artifact integrity
- Next step: operator-supplied trust anchors

## DO NOT USE

| Item | Reason |
|---|---|
| Any false-positive reduction percentage | **never measured** — OQ-25 was never closed quantitatively |
| Market size, ROI, user counts, economic impact figures | no verified data exists anywhere in the repository |
| Scalability / throughput claims | untested; no capture beyond a few hundred KB has been run |
| "Real-time" | never demonstrated; the system is batch-over-PCAP |
| ML accuracy / precision / recall figures | the honest measured result is *zero unique true detections* — quoting any favourable metric would be fabrication |
| "First", "only", "unique", "no existing tool can do this" | unsupportable; contradicts our own novelty audit |
| ADR numbers, formula names, class names, code snippets | internal vocabulary; consumes space, communicates nothing to a judge |
| Phase history / 12-phase engineering narrative | interesting to us, irrelevant to the decision |
| The tool's own hostile-input security matrix | excellent engineering, invisible in 6 slides — keep for Q&A |
