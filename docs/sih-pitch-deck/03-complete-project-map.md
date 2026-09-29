# 03 — Complete project map: what belongs in six slides

Every category of thing this project has, judged against one question: **does it earn space in a
five-content-slide deck?** Slide numbers refer to the official structure (`00-official-sih-format-research.md`).

**Reminder of the real constraint:** Slide 1 is administrative metadata. We have **five** slides
of argument, under **fixed headings**, with **prescribed sub-pointers**.

---

| Category | In deck? | Which slide | Why / why not |
|---|---|---|---|
| **PROBLEM** (encrypted, ambiguous, partly-absent evidence) | ✅ YES, compressed | 2 | The template has **no problem slide**. Must be 2–3 lines under "How it addresses the problem." |
| **USERS** (SOC, DFIR, IR, mail admins) | ✅ YES, one line | 5 | PS-sourced; belongs in "Potential impact on the target audience." |
| **CURRENT PAIN / why existing tools fall short** | ✅ YES, one line | 2 | Folds into "Innovation and uniqueness." No separate slide exists for it. |
| **INPUT** (PCAP, 3 protocols) | ✅ YES | 2 + 3 | One line on 2, shown in the pipeline diagram on 3. |
| **PIPELINE / ARCHITECTURE** | ✅ YES — primary visual | 3 | This *is* "Methodology and process for implementation (Flow Charts)". |
| **SECURITY RULES (16 + 3)** | ✅ YES, as a number | 3 | "16 standards-bound rules + 3 cross-session" is compact and concrete. |
| **TLS version / cipher** | ✅ YES, inside the crypto strip | 3 | One row of a compact capability strip, not its own block. |
| **STARTTLS / STLS** | ✅ YES | 2 or 3 | Carries the headline ambiguity story; cheap to state. |
| **X.509 / certificates** | ✅ YES, but bounded | 3 + 4 | Capability on 3; the TLS 1.3 limitation on 4 (it is a *risk/challenge*, which is exactly slide 4's pointer). |
| **KEY EXCHANGE** | 🔸 MINIMAL | 3 | One word in the crypto strip. Not worth a line of its own. |
| **FORWARD SECRECY** | 🔸 MINIMAL | 3 | Same — one word in the strip. |
| **CROSS-SESSION REASONING** | ✅ **YES — headline differentiator** | 2 (claim) + 3 (diagram) | Our single strongest defensible differentiator. Earns real space. |
| **CONTROL ENDPOINT reasoning** | ✅ YES | 3 | It is the mechanism that makes cross-session credible; shown in the diagram. |
| **EVIDENCE STATES (6)** | ✅ YES — second visual | 3 or 4 | Strong, compact, visual. Directly supports "uniqueness" and "risks". |
| **PROVENANCE chain** | 🔸 CONDITIONAL | 3 (as a thin strip) | Powerful but competes with the pipeline diagram. Include only as a one-line strip, not a full diagram. |
| **POSTURE SCORING** (F2-group-damped, coverage gate) | 🔸 MINIMAL | 3 | Mention "coverage-gated score"; the formula name is internal detail. |
| **ML / AI** | ✅ YES, precisely worded | 3 | Mandatory (title says "AI-Assisted") — must be honest and compact. |
| **REPORTING (JSON/HTML/PDF)** | ✅ YES, one line | 3 or 5 | Concrete deliverable; cheap. |
| **DASHBOARD** | ✅ YES — screenshot | 3 or 5 | Best single proof-of-realness visual available. |
| **PERFORMANCE (115–320 ms)** | 🔸 CONDITIONAL | 4 | Supports feasibility. One number only. |
| **SECURITY of the tool itself** (hostile PCAP handling) | ❌ NO | — | Important engineering, invisible to a judge in 6 slides. Keep for Q&A. |
| **REAL PCAPS (10, Postfix+Dovecot)** | ✅ YES | 4 | Core feasibility proof: "validated on real vendor traffic." |
| **GENERATED FIXTURES (3)** | ✅ YES, labelled | 4 | Must be labelled generated. Honesty is the point. |
| **GOLDEN CORPUS (25)** | 🔸 MINIMAL | 4 | Fold into a single corpus number. |
| **STANDARDS (11)** | ✅ YES | 3 or 6 | "11 published standards" on 3; the list itself on 6 (References). |
| **RESEARCH DOCS / ADRs** | ✅ YES | 6 | Slide 6 is literally "Research and References". |
| **DIFFERENTIATION / competitor audit** | ✅ YES | 2 (claim) + 6 (source) | Official pointer requires "innovation and uniqueness". |
| **LIMITATIONS (D-11, A-02)** | ✅ YES — deliberately | 4 | Slide 4 asks for "potential challenges and risks". Stating them there converts a weakness into evidence of rigour. |
| **FUTURE WORK** | 🔸 MINIMAL | 4 or 5 | One line max ("operator-supplied trust anchors" as the named next step). |
| **DEMO / scenes** | ✅ YES, as evidence | 4 | "20/20 reproducible runs" is a feasibility fact. |
| **RESULTS (tests, regression, timings)** | ✅ YES, curated | 4 | See `09-results-selection.md` — only 4–5 numbers survive. |
| **DEPLOYMENT (offline, zero deps)** | ✅ YES | 4 + 5 | Feasibility on 4; benefit on 5. |
| **SCALABILITY** | ❌ **NO** | — | **Untested.** Claiming it would be fabrication. If asked, answer honestly in Q&A. |
| **IMPACT (quantified market/ROI)** | ❌ **NO** | — | No verified data exists. Slide 5 must use *qualitative, defensible* impact only. |
| **1234 tests** | ✅ YES | 4 | Single strongest "this is real, not slideware" number. |
| **Zero runtime dependencies** | ✅ YES | 4 | Deployment feasibility, one line. |
| **tshark dependency** | ✅ YES, honestly | 4 | Named as a dependency/risk — it is one. |

## What gets cut, and why that is correct

The temptation is to show everything: 24 ADRs, 12 phases, a 16,000-line codebase, a hostile-input
security matrix, byte-deterministic reporting, artifact tamper detection. **All of it is real and
none of it survives the six-slide cut**, because a judge cannot absorb it and none of it changes
the core decision: *is this a credible, differentiated, working solution to SIH26159?*

The deck answers that with: **one architecture diagram, one differentiator, five numbers, one
screenshot, and two honestly-stated limitations.** Everything else is Q&A ammunition, already
prepared in `docs/finalization/10-final-judge-cheatsheet.md`.
