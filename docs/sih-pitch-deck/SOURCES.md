# SOURCES

Every externally-derived claim used in the pitch-deck content package.

---

## Official SIH sources (Tier 1 — authoritative)

| SOURCE | URL | CLAIM SUPPORTED | DATE ACCESSED |
|---|---|---|---|
| **Official SIH 2026 Idea Presentation Format (.pptx)** | `https://sih.gov.in/letters/2026/SIH2026-IDEA-Presentation-Format.pptx` | The entire six-slide structure: fixed headings (`TITLE PAGE`, `IDEA TITLE`, `TECHNICAL APPROACH`, `FEASIBILITY AND VIABILITY`, `IMPACT AND BENEFITS`, `RESEARCH AND REFERENCES`), the prescribed sub-pointers, the 6-slide cap including the title slide, the "avoid paragraphs / use points, diagrams, infographics" instruction, the "do not change the idea details pointers" rule, and PDF-only submission. **Extracted programmatically from the file's slide XML, not paraphrased.** | 2026-09-23 |
| Smart India Hackathon portal | `https://sih.gov.in/` | Location of the official Idea PPT template under Guidelines | 2026-09-23 |
| SIH FAQs | `https://www.sih.gov.in/faqs` | General submission process context | 2026-09-23 |
| Guidelines for College SPOC (PDF) | `https://www.sih.gov.in/letters/Guidelines-College-SPOC.pdf` | Internal-hackathon and nomination process context | 2026-09-23 |
| SIH Process Flow (PDF) | `https://www.sih.gov.in/letters/SIH-Process-flow-chart-final.pdf` | Idea screening is the online first stage; finale is offline | 2026-09-23 |

**NOT FOUND and therefore not used:** an official published jury scoring rubric. A weighting
breakdown (problem understanding 20% / technical approach 25% / prototype 25% / impact 20% /
presentation 10%) circulates on *institutional* portals but is **not** an official AICTE/SIH
publication. It is recorded here as **unverified** and was **not** used to drive any design
decision in this package.

## Standards cited by the implementation (Tier 1 — normative)

These are not decorative references: each was verified to be cited by an actual rule in the
registry (enumerated programmatically from `ALL_RULES`).

| Standard | Used for |
|---|---|
| RFC 8446 — TLS 1.3 | certificate-encryption boundary (§2); key exchange via `key_share` (§4.2.8); forward secrecy (§1.2, App. D.5) |
| RFC 8996 (BCP 195) — Deprecating TLS 1.0/1.1 | deprecated-version findings |
| RFC 3207 — SMTP Service Extension for Secure SMTP over TLS | STARTTLS rules |
| RFC 2595 — Using TLS with IMAP, POP3 and ACAP | STLS rules |
| RFC 8314 — Cleartext Considered Obsolete: Use of TLS for Email | implicit-TLS and plaintext-exposure rules |
| RFC 5280 — Internet X.509 PKI Certificate and CRL Profile | certificate structure; §6 path validation boundary; §4.2.1.1 Authority Key Identifier |
| RFC 6960 — Online Certificate Status Protocol (OCSP) | revocation-observability boundary |
| RFC 9155 — Deprecating MD5 and SHA-1 signature algorithms | weak-signature findings |
| NIST SP 800-52r2 — Guidelines for TLS Implementations | TLS server configuration posture |
| NIST SP 800-57 Part 1 Rev. 5 — Key Management | RSA minimum key length (2048) |
| NIST SP 800-131A Rev. 2 — Transitioning Cryptographic Algorithms | SHA-1 transition |

## In-repository research (project-internal evidence)

| Document | Claim supported |
|---|---|
| `docs/research/19-authoritative-ps-verification.md` | The authoritative PS text, retrieved from the official portal and hash-preserved; named user groups (SOC/DFIR/IR/admins); confirmation that AI/ML is explicitly required but method-open |
| `docs/research/01D-sih-competitor-source-audit.md` | Source-code audit of five competing SIH26159 implementations; cross-session reasoning verified absent from all five; competitor ML epistemics |
| `docs/research/01A-tls-visibility-validation.md` | What a passive capture can and cannot expose at each TLS version |
| `docs/research/01B-starttls-prior-art.md` | STARTTLS stripping prior art; the byte-identical ambiguity |
| `docs/architecture/adr/0015-ml-model-selection.md` | ML bake-off; zero unique true detections; 98.6% generator separability |
| `docs/architecture/adr/0024-a02-remains-partial.md` | Re-evaluation after Phase-11 features; A-02 remains PARTIAL |
| `docs/architecture/adr/0023-certificate-and-key-exchange-analysis.md` | Why D-11 is PARTIAL; why a bundled root store was rejected |
| `docs/finalization/04-real-pcap-evidence-pack.md` | 10 real captures; 0 of 10 expose a certificate; corpus inventory |
| `docs/finalization/06-cross-session-demo.md` | Real cross-session engine output, positive and negative cases |
| `docs/finalization/14-final-release-gate.md` | 1219 tests, 0 failures, 3 independent runs; zero production drift |
| `docs/phase12/12-novelty-audit.md` | The scoping discipline for every novelty claim |

## Slide mapping

| Source | Slide(s) used |
|---|---|
| Official SIH template | structure of all 6 slides |
| RFC 8446 | 2, 4, 6 |
| RFC 8996 / 3207 / 2595 / 8314 | 3, 6 |
| RFC 5280 / 6960 / 9155 | 4, 6 |
| NIST SP 800-52r2 / 800-57 / 800-131A | 3, 6 |
| `docs/research/19` (PS record) | 1, 5 |
| `docs/research/01D` (competitor audit) | 2, 6 |
| `docs/finalization/06` (cross-session) | 2, 6 |
| `docs/finalization/04` (real-PCAP pack) | 4 |
| `docs/finalization/14` (release gate) | 4 |
| ADR-0015 / ADR-0024 | 3, 4, 6 |
| ADR-0023 | 4 |

## Evidence-category clarification (important)

The cross-session demonstration evidence (`G_control_endpoint.pcap`, `H_no_control.pcap`) is
**executed, validated evidence from the generated scenario corpus** — real engine output, produced
by running the released system. It is **not** real-world production traffic, and must never be
described as such. The 10 Postfix/Dovecot captures are the real-vendor evidence; the 3 TLS 1.2
certificate captures are **generated fixtures**. See `DO-NOT-CLAIM.md` §B.

## Method note

Claims in this package are traceable to one of three tiers: **(1)** the official SIH template file
itself, **(2)** a normative standard, or **(3)** a verified in-repository artifact (source, test,
or executed experiment). No claim rests on a blog post, a coaching site, a vendor page, or an
unattributed statistic — and no quantitative figure appears anywhere in the deck that was not
produced by an actual measurement in this repository.
