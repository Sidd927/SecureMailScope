# 00 — Research Index

**Project:** SecureMailScope — SIH 2026, PS **SIH26159** (NTRO, Blockchain & Cybersecurity, Software)
**Mode:** Research only. No product implementation. No technology selection is final.
**Last updated:** 2026-09-16

---

## Evidence tiering convention (used in every document)

Every non-trivial statement in this repository carries one of four labels. This convention is
binding: an unlabelled claim is a defect.

| Label | Meaning | Rule |
|---|---|---|
| **FACT** | Directly supported by a primary source, quoted or citable. | Must have a `SOURCES.md` reference. |
| **INFERENCE** | Logically derived from one or more FACTs. | Must name the FACTs it derives from. |
| **ASSUMPTION** | Working belief adopted to make progress. Not yet supported. | Must be listed in `RESEARCH_STATUS.md` and be falsifiable. |
| **OPEN QUESTION** | Known unknown. Blocks or shapes a decision. | Must have an owner: *research*, *team*, or *SPOC/NTRO*. |

An ASSUMPTION never silently becomes a FACT. Promotion requires a source added to `SOURCES.md`
and an explicit changelog line in `RESEARCH_STATUS.md`.

**Source hierarchy** (prefer higher): IETF RFC / NIST / official standards → CISA, ENISA, CERT-In,
government advisories → peer-reviewed academic work → official vendor documentation →
independent technical analysis → community writeups. Community GitHub repositories implementing
this PS are treated as *interpretations by other competitors*, never as statements of requirement.

---

## Document map

| # | Document | Phase(s) | Status |
|---|---|---|---|
| 00 | [Research Index](00-research-index.md) | — | 🟢 Live |
| 01 | [Problem Statement Analysis](01-problem-statement-analysis.md) | 1, 2 | 🟢 Complete (v1, §6.1 **amended**) |
| 01A | [TLS Visibility Validation](01A-tls-visibility-validation.md) | critical pass | 🟢 Complete (v1) |
| 01B | [STARTTLS Prior-Art & Capability Audit](01B-starttls-prior-art.md) | OQ-14 | 🟢 Complete (v1) |
| 01C | [Tool-Stack Reconstruction & Competitor Audit](01C-existing-tool-stack-reconstruction.md) | OQ-18/19 | 🟢 Complete (v1) |
| 01D | [SIH Competitor Source Audit](01D-sih-competitor-source-audit.md) | OQ-23/24 | 🟢 Complete (v1) |
| 02 | Stakeholders | 3 | ⚪ Not started |
| 02A | [Cross-Session Baseline Experiment](02A-cross-session-baseline-experiment.md) | OQ-25 | 🟢 Executed (RESULT B) |
| 02B | [Packet-Level Validation](02B-packet-level-validation.md) | OQ-28, OQ-33 | 🟢 Executed (confirmed) |
| 03 | Domain Deep Dive | 4 | ⚪ Not started |
| 04 | Email Security Standards | 4 | ⚪ Not started |
| 05 | Existing Solutions | 5 | ⚪ Not started |
| 06 | Competitive Landscape | 6 | ⚪ Not started |
| 07 | User Workflows | 7 | ⚪ Not started |
| 08 | Threat Model | 8 | ⚪ Not started |
| 09 | Data & Evidence | 9 | ⚪ Not started |
| 10 | AI Opportunity | 10 | ⚪ Not started |
| 10A | [AI Opportunity Validation](10A-ai-opportunity-validation.md) | OQ-21 | 🟢 Complete (v1) |
| 10B | [AI Architecture Decision](10B-ai-architecture-decision.md) | OQ-21 | 🟢 Decided |
| 11 | Innovation Space | 11, 12 | ⚪ Not started |
| 12 | Prior Art | 13 | ⚪ Not started |
| 13 | Solution Architectures | 14 | ⚪ Not started |
| 14 | Feasibility | 15 | ⚪ Not started |
| 15 | SIH Evaluation Lens | 16 | ⚪ Not started |
| 16 | Demo Strategy | 17 | ⚪ Not started |
| 17 | Research Gaps | 18 | ⚪ Not started |
| 18 | Master Synthesis | 19, 20 | ⚪ Not started |
| 19 | [Authoritative PS Verification](19-authoritative-ps-verification.md) | gate | 🟢 Passed |
| — | [SOURCES](SOURCES.md) | all | 🟢 Live |
| — | [RESEARCH_STATUS](RESEARCH_STATUS.md) | all | 🟢 Live |

### Evidence artifacts

| Path | What it is |
|---|---|
| `evidence/SIH26159-official-ps.json` | Verbatim official PS record + provenance block. **The canonical requirement source.** |
| `evidence/sih2026-all-ps-20260822.json` | Full 226-PS SIH 2026 dataset (mirror of `sih.gov.in/sih2026PS`, scraped 2026-08-22). Used for cross-PS context. |
| `evidence/sih2026-portal-SIH26159-20260916.html` | **Authoritative** official-portal capture of SIH26159, 2026-09-16. Confirms A-01; source of the 30 Sept deadline. |

---

## Headline findings so far

Detail and sourcing live in [01-problem-statement-analysis.md](01-problem-statement-analysis.md).

1. **The PS is a passive PCAP network-forensics problem, not a DNS/domain-posture problem.**
   The official text scopes the work to offline analysis of captured SMTP/IMAP/POP3 traffic.
   SPF, DKIM, DMARC, MTA-STS, DANE, BIMI and DNSSEC **do not appear anywhere in the PS**.
   This contradicts a widely-assumed reading of the title and must be corrected before any
   further work. See §8, *Scope correction*.

2. **Certificate evidence is conditionally unavailable — but this was initially overweighted.**
   TLS 1.3 encrypts the `Certificate` message (RFC 8446 §2), *and* every resumed session omits it at
   any TLS version (§2.2). However, only **5 of 22** PS deliverables are certificate-dependent, and
   version, cipher suite, key-exchange group, SNI and resumption remain visible under TLS 1.3.
   Handling this is a **correctness requirement, not a differentiator** — evidence tiering is prior
   art (Delgado 2026; Casey 2002). See [01A](01A-tls-visibility-validation.md) §2, §6.

3. **The STARTTLS negotiation layer is the reweighted opportunity — OQ-14 resolved, it survives.**
   Cleartext at every TLS version, with a published attack taxonomy (Poddebniak, USENIX Sec '21;
   Durumeric, IMC '15; RFC 3207 §6). Source inspection confirms **no shipped Zeek script, Suricata
   event or ET rule detects STARTTLS stripping**; Zeek's whole SMTP output is one boolean; **Zeek
   has no `imap.log` and no `pop3.log`, and Suricata has no POP3 parser.** See
   [01B](01B-starttls-prior-art.md).

4. **Conceded openly: the extraction layer is already solved.** PCAP parsing, TCP reassembly, TLS
   dissection and X.509 validation are mature in Zeek/Suricata. Reimplementing them would be
   rebuilding infrastructure worse ([01B](01B-starttls-prior-art.md) §8).

5. 🔴 **The differentiation hypothesis was falsified — by competitors, not by tooling.** OQ-18/19
   closed in our favour (Snort: 0 STARTTLS rules of 4,017; **all 285 zkg packages**: zero relevant;
   Arkime *silently normalises* the downgrade condition). **But ~10 competing SIH26159 repos exist,
   and CipherPost already ships `rule_starttls_strip` cited to RFC 3207 with SMTP *and IMAP* test
   fixtures.** H1 and H2 are dead. What survives is **execution-grade, not capability-grade**:
   evidence-observability discipline, POP3/STLS coverage, resumption-aware certificate reasoning,
   and multi-session posture — reasons to be more *correct*, not more *capable*.
   See [01C](01C-existing-tool-stack-reconstruction.md).

6. 🔴 **Three of four surviving differentiators were lost to competitor source code.** saravana
   implements `NOT_OBSERVABLE` + `score_confidence`; gouravsehlangia implements POP3/STLS + implicit
   TLS across all three protocols; Prahari implements resumption reasoning citing RFC 7627.
   **Only cross-session reasoning survives** — verified absent from all five codebases. H0–H3
   rejected; **H7 survives**. See [01D](01D-sih-competitor-source-audit.md).

7. 🎯 **OQ-21 resolved — nobody's AI does anything deterministic rules cannot.** gourav's LLM is a
   report rewriter with severity hardcoded into the prompt; saravana's RandomForest trains on 2,500
   self-generated archetypes; CipherPost's ML learns its own rules engine and says so in a comment.
   **The inversion:** use unsupervised outlier detection to find what the rules *missed*, not to
   reproduce what they found. Analyst-facing only, with a `--no-ai` equivalence test.
   See [10A](10A-ai-opportunity-validation.md).

8. 🟡 **OQ-25 executed — RESULT B, partially verified.** Cross-session reasoning cuts false
   positives **−71%** (120→35) with no recall loss, *or* halves false negatives, **but not both** —
   two mechanisms that trade off. 🔴 **The per-session detector is inverted:** CRITICAL on 25/25
   benign sessions, blind to 30/30 real attacks. Two unresolved failures: 100% stripping with no
   control endpoint, and NAT identity collapse. Thesis revised to match the numbers.
   See [02A](02A-cross-session-baseline-experiment.md).

9. 🟡 **OQ-28 executed — packet-level replication confirms it.** 17 real PCAPs validated by
   tshark's own dissectors. **FP −72%** on real packets vs −71% in the session model; all six
   success criteria met, no parameter tuned. The D1 inversion replicated in **SMTP, IMAP and POP3**.
   Byte-identity of attack vs legitimate config now **proven**, not asserted. Truncation, packet
   loss, reordering and retransmission all handled correctly. **H7: PARTIALLY VERIFIED.**
   See [02B](02B-packet-level-validation.md).

   **OQ-33 closed (02B §15):** the reference attack tool `striptls` was **executed** — its real
   SMTP mangler produces output *byte-identical* to our corpus, POP3/IMAP confirmed. The "striptls
   not run" caveat is removed; the attack model is validated against the reference tool's own output.

10. **Timeline is the binding constraint, not technical difficulty.** The PS record carries an idea
   submission deadline of **20 September 2026**; independent sources describe a national
   nomination deadline of **30 September 2026**. Sources conflict. See §9 / OQ-01.

---

## How to work in this repository

- Do not edit `evidence/` — it is an immutable record of what sources said when we read them.
- Every claim added to a numbered document gets a label and, if FACT, a `SOURCES.md` entry.
- At the end of each phase, update `RESEARCH_STATUS.md` (phases, findings, assumptions, next actions).
- Requirement IDs (`R-xx`, `O-xx`, `D-xx`) are defined in document 01 and are stable. Later
  documents must trace design proposals back to these IDs rather than inventing scope.
