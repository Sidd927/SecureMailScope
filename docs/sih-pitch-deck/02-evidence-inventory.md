# 02 — Evidence inventory

Every claim that could plausibly appear on a slide, classified by how it is verified. **Nothing
reaches `FINAL-SLIDE-CONTENT.md` unless it appears here with category A–F.** Category G claims may
appear only with explicit hedging; category H claims may not appear at all.

**Categories:** A = source code · B = automated test · C = real-PCAP experiment · D = generated
fixture · E = external standard/RFC · F = research literature · G = inference/interpretation ·
H = not verified

---

| # | CLAIM | CAT | SOURCE / EXPERIMENT | QUANTITATIVE RESULT | SAFE WORDING | OVERCLAIM RISK |
|---|---|---|---|---|---|---|
| 1 | Analyses SMTP, IMAP, POP3 incl. implicit TLS | A+C | `session/protocols.py`; 10 real captures across all 3 | 3 protocols, 4 TLS modes | "SMTP, IMAP and POP3, including implicit-TLS SMTPS/IMAPS/POP3S" | none |
| 2 | 16 deterministic single-session rules | A | enumerated from `ALL_RULES` | 16 | "16 standards-bound rules" | don't say "16 detection rules" — several are compliance/abstention rules |
| 3 | 3 cross-session rules | A | `crosssession/rules.py` | 3 | "3 cross-session rules" | none |
| 4 | Every finding cites a published standard | A | rule `standards` tuples | 11 distinct standards | "every finding cites an RFC or NIST publication" | don't claim "compliance certification" |
| 5 | Standards used | A+E | RFC 2595/3207/5280/6960/8314/8446/8996/9155; NIST SP 800-52r2/800-57/800-131A | 8 RFCs + 3 NIST SPs | list them | don't imply endorsement by those bodies |
| 6 | Six evidence states, never collapsed | A+B | `evidence/states.py`; `_NON_ASSERTIVE` invariant enforced in `SecurityFinding.__post_init__` | 6 | "six evidence states" | none |
| 7 | Missing evidence never becomes a verdict | A+B | status/severity invariant; `test_scene_b_no_findings_is_not_rendered_as_secure` | — | "absence of evidence is never reported as either secure or insecure" | none |
| 8 | TLS 1.3 hides the certificate | C+E | measured across all 10 real captures; RFC 8446 §2 | **0 of 10** real captures expose a certificate | "TLS 1.3 encrypts the certificate by design — 0 of our 10 real captures expose one" | never say "TLS 1.3 is insecure" or imply a defect |
| 9 | Certificate analysis works where observable | D | `smtps_tls12_*` fixtures | 38 distinct X.509 fields extracted from a TLS 1.2 handshake | "where a cleartext handshake exposes it" | **must label fixtures as generated** |
| 10 | Weak certificate correctly flagged | D | `smtps_tls12_weak_sha1_rsa1024.pcap` | RSA-1024 + SHA-1 → 2× HIGH → posture CRITICAL, score 44.0 | "RSA-1024 and SHA-1 both flagged, posture CRITICAL" | generated fixture, must be labelled |
| 11 | Self-signed detected structurally | D | `smtps_tls12_selfsigned_rsa2048.pcap` | AKI==SKI → MEDIUM, 88.0 | "self-signed detected via key-identifier match" | not a trust verdict |
| 12 | Healthy chain = clean (negative control) | D | `smtps_tls12_chain_rsa2048.pcap` | STRONG 100.0 | "negative control scores clean" | none |
| 13 | Cross-session resolves what one session cannot | C | `G_control_endpoint.pcap`, 12 sessions | `CS-STARTTLS-001` → OBSERVED_ISSUE, **MEDIUM** | "one client's sessions deviate from 6 other clients at the same server" | never "we detected the attacker" |
| 14 | Honest negative case when no control exists | C | `H_no_control.pcap`, 6 sessions | COMPLIANT + explicit stated limitation | "with no control endpoint, consistent stripping and consistent plaintext config are passively indistinguishable — and the tool says so" | this is a strength; do not hide it |
| 15 | Cross-session absent from all audited competitors | A(theirs) | `docs/research/01D` §4 — grep of 5 competitor repos | 0 of 5 implement it | "our source audit of five competing implementations found none implementing cross-session reasoning" | **never** "no one has ever done this" — it is standard in NSM generally |
| 16 | ML is bounded and cannot cross a severity tier | A | `MAX_ML_ADJUSTMENT = 4.0`; narrowest tier gap 30 (weights INFO 0 → CRITICAL 55) | 4.0 vs 30 | "mathematically cannot move a finding across a severity tier" | none — this is arithmetic |
| 17 | ML has no demonstrated detection value | B+C | ADR-0015, ADR-0024 | **0 unique true detections on every held-out split** | "evaluated honestly; zero unique true detections on held-out data" | never claim ML detects attacks |
| 18 | Feature space leaks generator identity | C | Phase-6 bake-off | **98.6%** separable by generator | "the corpus, not the model, is the limiting factor" | don't present as a model failure |
| 19 | `--no-ai` equivalence proven | B+C | `test_scene_c_no_ai_equivalence_across_the_whole_stack`; `demo/expected/scene_c_no_ai_equivalence.json` | identical posture, score, penalising findings | "the security conclusion is identical with AI on or off — proven, not asserted" | none |
| 20 | 1219 tests pass | B | 3 independent full-suite runs | 1219 / 0 fail / 0 skip | "1219 automated tests" | don't claim coverage % (not measured) |
| 21 | No regression from certificate work | B+C | Phase-11 baseline diff vs `v0.5.0-phase10` | 10/10 captures score identically | "adding certificate analysis changed no existing verdict" | none |
| 22 | Provenance chain complete | A+C | `EvidenceRef`; 13 executions | frame, stream, timestamp, evidence state, provenance on every ref | "every finding traces to specific frames" | not legal chain-of-custody |
| 23 | Content-addressed integrity | A+B | PCAP SHA-256 → capture_id → assessment_id → report_sha256 | re-hashed on access | "content-addressed and integrity-verified" | none |
| 24 | Three report formats, byte-deterministic | A+B | Phase 9; verified this phase | JSON/HTML/PDF; zero `<script>`; PDF text-extractable | "JSON, HTML and PDF" | none |
| 25 | Runs fully offline, zero runtime dependencies | A | import-set inspection, re-verified 2026-09-23 | 0 third-party modules in core | "zero third-party runtime dependencies in the analysis core; runs air-gapped" | tshark is a required external binary — say so |
| 26 | Performance | C | measured this phase | **115–320 ms** per capture end-to-end | "sub-second analysis" | don't say "real-time" |
| 27 | Demo reliability | C | 4 scenes × 5 runs | **20/20** stable | "20 of 20 repeated runs produced identical results" | none |
| 28 | Dashboard has zero npm dependencies | A | `dashboard/static/`, no `package.json` | 0 | "no build step, no npm packages" | none |
| 29 | D-11 PARTIAL | A+E | ADR-0023; RFC 5280 §6 | — | "chain structure validated; trust and revocation are not observable from passive capture alone" | **never** "we validate certificates" unqualified |
| 30 | A-02 PARTIAL | B+C | ADR-0024 | — | "AI ships as a bounded secondary signal with its limitation stated" | never claim AI detection |
| 31 | 25-capture golden corpus + 10 real + 3 fixtures | A | directory listings | 25 / 10 / 3 | "38 captures across generated and real-vendor traffic" | don't inflate to "thousands" |
| 32 | Users are SOC/DFIR/IR/admins | E(PS text) | `docs/research/19` §8 item 5 | — | quote the PS | don't invent market size |
| 33 | Deadline/scale/market claims | **H** | — | — | — | **DO NOT USE** — no verified market, ROI, or user-count data exists |
| 34 | "Reduces false positives by N%" | **H** | — | no such measurement exists | — | **DO NOT USE.** Cross-session reasoning *resolves an ambiguity class*; no FP-rate delta was ever measured |

## Critical note on claim #34

The phrase "reduces false positives" is intuitively attractive and **not supported by any
measurement in this repository.** OQ-25 (does cross-session baselining measurably reduce false
positives?) was raised in research and never closed with a quantitative experiment. The defensible
claim is structural, not statistical: *cross-session evidence resolves a specific ambiguity that is
unresolvable within a single session* — demonstrated live on `G_control_endpoint.pcap`. Any
percentage attached to this claim would be fabricated.
