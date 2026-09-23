# PPT team content bank

Supporting material so the design team never has to invent content. Everything here is
pre-verified. **Labels: PRIMARY (use this) · ALTERNATIVE (equally safe) · OPTIONAL (if space) ·
DO NOT USE.**

---

## 1. Headlines

| Slide | PRIMARY | ALTERNATIVE |
|---|---|---|
| 2 | Reasoning across sessions, not just parsing packets | One session can't tell you; every session can |
| 3 | A deterministic evidence pipeline — with AI kept in its place | Standards-cited findings, bounded AI |
| 4 | A working prototype — and we can name exactly what it cannot prove | Measured, reproducible, and honest about its limits |
| 5 | Evidence an analyst can defend | From a capture you already have to a citable assessment |
| 6 | *(heading fixed)* | — |

**DO NOT USE as headlines:** "AI-powered email security", "Next-generation threat detection",
"Revolutionary forensics platform".

## 2. Taglines / one-liners

**PRIMARY:** *Passive PCAP → evidence-backed cryptographic security posture for email.*

**ALTERNATIVE:**
- *Turns an email packet capture into a standards-cited security posture — without decrypting anything.*
- *Reasons across every session with a server, not just one connection at a time.*

**OPTIONAL (closing line):** *It tells you what it can prove, and what it can't.*

**DO NOT USE:** anything containing "AI-powered", "intelligent detection", "next-gen".

## 3. Verified facts (safe to place anywhere)

| Fact | Exact value |
|---|---|
| Automated tests | 1219, 0 failures, 0 skips |
| Real-vendor captures validated | 10 (Postfix + Dovecot) |
| Protocols | SMTP, IMAP, POP3 (+ SMTPS/IMAPS/POP3S) |
| TLS modes covered | 4 |
| Deterministic rules | 16 |
| Cross-session rules | 3 |
| Published standards cited | 11 (8 RFCs + 3 NIST SPs) |
| Evidence states | 6 |
| Analysis latency | 115–320 ms per capture |
| Repeat-run stability | 20/20 identical |
| Runtime dependencies (core) | 0 third-party |
| Dashboard npm packages | 0 |
| Export formats | 3 (JSON, HTML, PDF) |
| ML adjustment cap | 4.0, vs a 30-point severity-tier gap |
| ML detection value on held-out data | 0 unique true detections |
| Certificates visible under TLS 1.3 | 0 of 10 real captures |
| X.509 fields extracted (TLS 1.2 fixture) | 38 distinct fields |
| Competing implementations audited | 5; cross-session reasoning found in 0 |

## 4. Architecture / diagram labels (use verbatim)

**Pipeline boxes:** `PCAP` → `Dissect (tshark)` → `Session reconstruction` → `16 deterministic
rules` → `3 cross-session rules` → `Evidence fusion` → `Coverage-gated posture` → `Reports
(JSON/HTML/PDF)` → `Analyst dashboard`

**ML lane label:** `ML lane — ranking only (capped 4.0 / 30-pt tier gap)` with a blocked arrow to
findings.

**Evidence states (exact spelling):** `OBSERVED` · `INFERRED` · `AMBIGUOUS` · `INCOMPLETE` ·
`UNKNOWN` · `NOT_OBSERVABLE`

**Provenance strip:** `PCAP SHA-256 → frame → TCP stream → evidence state → finding → cited
standard → report`

**Cross-session diagram labels:** `Same server, same capture` · `Client A` · `Other clients` ·
`Control endpoint` · `Deviation — evidenced` · `No control → abstain + state the limitation`

## 5. Terminology (use these words, not synonyms)

| Use | Not |
|---|---|
| passive / passively observed | sniffing, intercepting |
| finding | alert, detection |
| deviation | attack, intrusion |
| posture assessment | risk score, threat score |
| not observable | missing, failed, unknown error |
| cited standard | compliance certification |
| prioritisation signal | detection model |
| generated fixture | test case, sample (when it's a synthetic capture) |

## 6. Short descriptions (drop-in)

**15 words:** Passive PCAP analysis producing standards-cited cryptographic security posture for
SMTP, IMAP and POP3.

**30 words:** SecureMailScope reads an email packet capture and reports what its encryption
actually was — TLS version, cipher, certificates where visible, forward secrecy — citing a
published standard for every finding.

**50 words:** Email transport security fails silently, and the packet capture is often the only
evidence. SecureMailScope reconstructs each session, assesses its cryptographic posture against 11
published standards, and reasons across every session with the same server — resolving ambiguities
a single-session analyser cannot, and stating explicitly what the evidence cannot establish.

## 7. Screenshots to capture

| Screenshot | Where from | Shows | Priority |
|---|---|---|---|
| Dashboard **Overview** | `http://127.0.0.1:8000/dashboard/` after running a demo capture | posture band, score, coverage percentage | **PRIMARY** — Slide 5 |
| Dashboard **Findings** | same | prioritised findings with severity + cited standard | ALTERNATIVE — Slide 5 |
| Dashboard **Evidence** | same | abstentions with "what would resolve this" | OPTIONAL — Slide 3 |
| HTML report | `demo/reports/backup_weak_certificate.html` | a CRITICAL finding with its citation | OPTIONAL |

**How to produce them:** `bash demo/commands/start_demo.sh`, upload any capture from
`demo/captures/`, screenshot. Note `demo/screenshots/` is currently **empty** — these must be
captured before the deck is built.

## 8. Diagrams to create

1. **Cross-session contrast** (Slide 2) — ✗/✓ rows, same server, deviation callout. *Highest priority.*
2. **Pipeline flow** (Slide 3) — 9 boxes + blocked ML lane. *Highest priority.*
3. **Six evidence states strip** (Slide 3) — vertical or horizontal list.
4. **Results number strip** (Slide 4) — five large figures.
5. **Provenance strip** (Slide 3 footer) — single line, 7 tokens.

## 9. Callout lines (pre-approved)

- *Within one session, stripping and non-support are byte-identical. Across sessions, they are not.*
- *Missing evidence can never improve a score.*
- *TLS 1.3 encrypts the certificate — that's the protocol, not a tool limitation.*
- *Every security conclusion is identical with the AI lane switched off. We tested it.*
- *Chain structure is validated. Trust is not — and we say so.*

## 10. Q&A ammunition (not on slides)

Full answers: `docs/finalization/10-final-judge-cheatsheet.md` (categories A–R). Highest-value
quotes to have ready:

- Engine's own text: *"no attacker, intent or attribution is or can be established from a packet capture"*
- Engine's own text: *"absence of certificate evidence is not evidence of an absent, invalid or untrusted certificate"*
- Real cross-session finding: *"This endpoint consistently lacks the upgrade capability while comparable endpoints at the same server consistently have it."*
- Real honest-negative finding: *"No comparable control endpoint was available to corroborate this from a second angle."*

## 11. DO NOT USE

- Any statistic not listed in §3
- ADR numbers, formula names (`F2-group-damped`), class names, file paths on slides
- Phase history ("we completed 12 phases")
- Lines of code, file counts
- Competitor names in a comparison table (see `16-existing-solutions-analysis.md`)
- Stock imagery of hackers in hoodies, padlocks, or binary-code backgrounds
