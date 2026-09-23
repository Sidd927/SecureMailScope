# 05 — Six-slide master map

The architecture of the deck. Each slide has **one primary job**. Official purposes are quoted
verbatim from the template (`00-official-sih-format-research.md`).

---

## SLIDE 1

**OFFICIAL PURPOSE:** `TITLE PAGE` — Problem Statement ID · Problem Statement Title · Theme ·
PS Category (Software/Hardware) · Team ID · Team Name (Registered on portal)

**OUR SLIDE TITLE:** *(fixed by template — do not change)*

**ONE-SENTENCE OBJECTIVE:** Be administratively flawless and signal seriousness in one line.

**JUDGE QUESTION:** "Is this the right PS, correctly submitted?"

**CORE MESSAGE:** SIH26159 — SecureMailScope.

**MUST SHOW:** all six required metadata fields, complete and correct.

**MUST SAY:** PS ID `SIH26159` · full PS title · Theme: Blockchain & Cybersecurity ·
PS Category: **Software** · Team ID · Team Name (exactly as registered).

**MUST PROVE:** nothing — this is compliance.

**OPTIONAL:** a single subtitle line if the template permits one, e.g. *"Passive PCAP →
evidence-backed cryptographic posture for email."*

**DO NOT INCLUDE:** architecture, features, metrics, logos that obscure required fields.

**PRIMARY EVIDENCE SOURCES:** the PS record.

**EXPECTED JUDGE TAKEAWAY:** "Correct submission, right problem."

---

## SLIDE 2

**OFFICIAL PURPOSE:** `IDEA TITLE` — **Proposed Solution:** Detailed explanation of the proposed
solution · How it addresses the problem · Innovation and uniqueness of the solution

**OUR SLIDE TITLE:** *(heading fixed)* — content headline: **"Reasoning across sessions, not just
parsing packets"**

**ONE-SENTENCE OBJECTIVE:** Make the judge understand the inference problem and that we solve it.

**JUDGE QUESTION:** "What is it, and what's genuinely new?"

**CORE MESSAGE:** Email security evidence in a PCAP is encrypted, ambiguous and incomplete —
SecureMailScope produces a cited security posture anyway, by reasoning across every session with
the same server instead of judging each connection alone.

**MUST SHOW:** the ambiguity visual — two sessions that look byte-identical in isolation, separated
once cross-session evidence is applied.

**MUST SAY:**
- *What:* passive PCAP → cryptographic security posture for SMTP/IMAP/POP3 (incl. SMTPS/IMAPS/POP3S).
- *The problem it addresses:* within one session, a stripped STARTTLS and a client that simply
  declined are **byte-identical**; TLS 1.3 encrypts the certificate entirely.
- *Innovation/uniqueness:* cross-session reasoning over per-server baselines + six evidence states
  so missing evidence never becomes a false verdict. Our source audit of five competing
  implementations found **none** implementing cross-session reasoning.

**MUST PROVE:** the uniqueness claim is audit-backed (claim #15, `02-evidence-inventory.md`).

**OPTIONAL:** one line naming users (SOC/DFIR) if space remains — otherwise defer to Slide 5.

**DO NOT INCLUDE:** the full pipeline (that's Slide 3), test counts (Slide 4), any AI detection
claim, the word "unique" unqualified.

**PRIMARY EVIDENCE SOURCES:** `docs/research/01D-sih-competitor-source-audit.md` §4;
`docs/finalization/06-cross-session-demo.md`.

**EXPECTED JUDGE TAKEAWAY:** "They identified an inference problem the obvious approach can't
solve, and built for it."

---

## SLIDE 3

**OFFICIAL PURPOSE:** `TECHNICAL APPROACH` — Technologies to be used · Methodology and process for
implementation (Flow Charts/Images/working prototype)

**OUR SLIDE TITLE:** *(heading fixed)* — content headline: **"A deterministic evidence pipeline,
with AI kept in its place"**

**ONE-SENTENCE OBJECTIVE:** Prove a real engineered system exists and show how it works.

**JUDGE QUESTION:** "Is this built? What's it built from?"

**CORE MESSAGE:** Nine stages from PCAP to report; deterministic rules produce every security
fact; ML only re-orders within a severity tier and can never create a finding.

**MUST SHOW:** **the pipeline diagram** (primary visual) + **six evidence states** strip
(secondary) + a dashboard screenshot if space allows.

**MUST SAY:**
- *Technologies:* Python 3.9+, tshark/Wireshark, FastAPI, SQLite, ReportLab; **zero third-party
  runtime dependencies in the analysis core**; dashboard is plain ES modules (no npm, no build).
- *Methodology:* dissection → session reconstruction (SMTP/IMAP/POP3, explicit + implicit TLS) →
  **16 standards-bound rules** → **3 cross-session rules** (≥5 comparable sessions) → evidence
  fusion → coverage-gated posture → JSON/HTML/PDF + dashboard.
- *Crypto assessed:* TLS version · cipher · key exchange · forward secrecy · X.509 expiry, key
  strength, signature algorithm, chain structure · insecure configuration.
- *AI:* bounded secondary prioritisation signal — **4.0 max adjustment vs a 30-point severity-tier
  gap**, so it cannot cross a tier.

**MUST PROVE:** every finding cites one of **11 published standards** (8 RFCs + 3 NIST SPs).

**OPTIONAL:** the provenance strip (`PCAP SHA-256 → frame → stream → finding → report`) as a thin
footer line.

**DO NOT INCLUDE:** formula names (`F2-group-damped`), ADR numbers, class names, code, a full
provenance diagram (competes with the pipeline).

**PRIMARY EVIDENCE SOURCES:** `docs/phase12/00-release-state-audit.md` §3–4; `ALL_RULES`.

**EXPECTED JUDGE TAKEAWAY:** "This is engineered, and the AI boundary is deliberate."

---

## SLIDE 4

**OFFICIAL PURPOSE:** `FEASIBILITY AND VIABILITY` — Analysis of feasibility · Potential challenges
and risks · Strategies for overcoming these challenges

**OUR SLIDE TITLE:** *(heading fixed)* — content headline: **"Working prototype — and we can name
exactly what it can't prove"**

**ONE-SENTENCE OBJECTIVE:** Convert "it works" into "it works, measurably, and they know its limits."

**JUDGE QUESTION:** "Does it actually run? What breaks it? Are they honest?"

**CORE MESSAGE:** A working, tested prototype validated on real vendor traffic, with its genuine
technical limits stated and mitigated rather than hidden.

**MUST SHOW:** results strip (4–5 numbers) + risks/mitigation table (3 rows).

**MUST SAY:**
- *Feasibility:* **1219 automated tests**, 0 failures · validated on **10 real Postfix/Dovecot
  captures** across SMTP/IMAP/POP3 and 4 TLS modes · **115–320 ms** per capture · **20/20**
  reproducible demo runs · runs **fully offline**, zero third-party runtime dependencies.
- *Risks & mitigations:*
  | Risk | Reality | Strategy |
  |---|---|---|
  | TLS 1.3 encrypts the certificate (RFC 8446 §2) | 0 of 10 real captures expose one | report `NOT_OBSERVABLE` with the reason — never guess; extract fully when TLS ≤1.2 exposes it |
  | Certificate **trust** needs a trust anchor a PCAP lacks | chain *structure* validated; trust is not | state the boundary in every finding; operator-supplied trust store is the scoped next step |
  | ML showed no detection value on held-out data | 0 unique true detections | ship it bounded as a prioritisation signal only; deterministic rules remain the source of truth |
  | tshark is an external dependency | required binary | version-checked at startup, fails closed |

**MUST PROVE:** the numbers are measured, not estimated.

**OPTIONAL:** "certificate analysis validated on 3 **generated** TLS 1.2 fixtures" — include only
with the word *generated*.

**DO NOT INCLUDE:** scalability claims (untested), invented risks, apologetic framing of D-11/A-02.

**PRIMARY EVIDENCE SOURCES:** `docs/finalization/14-final-release-gate.md`;
`docs/finalization/04-real-pcap-evidence-pack.md`.

**EXPECTED JUDGE TAKEAWAY:** "They measured it, and they're not overselling — I trust the rest."

---

## SLIDE 5

**OFFICIAL PURPOSE:** `IMPACT AND BENEFITS` — Potential impact on target audience · Benefits
(social, economic, environmental, etc.)

**OUR SLIDE TITLE:** *(heading fixed)* — content headline: **"Evidence an analyst can defend"**

**ONE-SENTENCE OBJECTIVE:** Show this fits a real workflow and produces a usable artifact.

**JUDGE QUESTION:** "Who benefits, and how?"

**CORE MESSAGE:** SOC, DFIR and incident-response teams get a citable cryptographic posture from
captures they already hold — with no server access, no keys, no internet, and no message content read.

**MUST SHOW:** target-user strip + before/after workflow, or the report/dashboard artifact.

**MUST SAY:**
- *Audience (PS-named):* SOC analysts · digital-forensics investigators · incident-response teams ·
  enterprise mail administrators.
- *Operational benefits:* works on **evidence already collected** (no new instrumentation) ·
  **passive** — never touches production mail servers · **air-gapped-capable** — no internet, no
  external AI service · every finding **cites a published standard**, so it survives review ·
  exports **JSON / HTML / PDF** for incident reports.
- *Security benefit:* finds silent transport-security failures — downgrades, deprecated TLS, weak
  certificates — that leave no trace in the mail itself.

**MUST PROVE:** the audience list comes from the PS; the offline/passive properties are
architectural, not aspirational.

**OPTIONAL:** one forward-looking line ("operator-supplied trust anchors" as the next capability).

**DO NOT INCLUDE:** market size, ROI, user counts, "crores saved", national-scale statistics —
**none of it is verified and all of it is fabrication.**

**PRIMARY EVIDENCE SOURCES:** `docs/research/19-authoritative-ps-verification.md` §8;
`docs/finalization/12-offline-demo-audit.md`.

**EXPECTED JUDGE TAKEAWAY:** "This slots into a real workflow and produces something usable."

---

## SLIDE 6

**OFFICIAL PURPOSE:** `RESEARCH AND REFERENCES` — Details / Links of the reference and research work

**OUR SLIDE TITLE:** *(heading fixed)*

**ONE-SENTENCE OBJECTIVE:** Demonstrate the work is standards-grounded, not self-invented.

**JUDGE QUESTION:** "What is this built on?"

**CORE MESSAGE:** Eleven published standards plus an in-repo research corpus, including a
source-code audit of competing implementations.

**MUST SHOW:** a clean two-column citation list.

**MUST SAY:**
- *Transport security:* RFC 8446 (TLS 1.3) · RFC 8996 (deprecating TLS 1.0/1.1) · RFC 3207
  (SMTP STARTTLS) · RFC 2595 (IMAP/POP3 TLS) · RFC 8314 (implicit TLS for mail).
- *Certificates:* RFC 5280 (PKIX) · RFC 6960 (OCSP) · RFC 9155 (deprecating SHA-1).
- *Crypto guidance:* NIST SP 800-52r2 · NIST SP 800-57 Pt.1 Rev.5 · NIST SP 800-131A Rev.2.
- *Project research:* authoritative PS verification; TLS passive-visibility validation;
  STARTTLS prior-art review; competing-implementation source audit; ML evaluation (ADR-0015/0024).

**MUST PROVE:** these are the standards the rules actually cite — not a decorative list.

**OPTIONAL:** repository link, if permitted by the team's submission policy.

**DO NOT INCLUDE:** blogs, vendor marketing, uncited statistics, padding references nothing uses.

**PRIMARY EVIDENCE SOURCES:** rule `standards` tuples (verified by enumeration); `docs/research/`.

**EXPECTED JUDGE TAKEAWAY:** "Grounded in real standards."
