# FINAL SLIDE CONTENT

**This is the file the PPT team builds from.** Content is written to be copied nearly directly.
Official headings are fixed by the SIH template and must not be changed
(`00-official-sih-format-research.md`). Fields marked `⟨FILL⟩` require team-specific data.

**Format reminders:** max 6 slides including title · no paragraphs · export to **PDF only**.

> **This file is the canonical slide-content source.** If another pitch document conflicts with it,
> the conflict must be resolved **against the repository evidence** before use — not by editing
> whichever document is more convenient. The authority order is:
> *production source / executed experiment → verified project evidence → research documents →
> pitch content → visual instructions.* **A presentation document never overrides the
> implementation.**
>
> Claim-by-claim evidence: `FINAL-CLAIM-AUDIT.md` · Prohibited wording: `DO-NOT-CLAIM.md` ·
> Entry point for newcomers: `FINAL-PITCH-DECK-HANDOFF.md`

---

============================================================
## SLIDE 1 — `TITLE PAGE`
============================================================

**TITLE:**
SecureMailScope

**SUBTITLE:**
Passive PCAP → evidence-backed cryptographic security posture for email

**BODY (the six required fields):**
- Problem Statement ID – **SIH26159**
- Problem Statement Title – **SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**
- Theme – **Blockchain & Cybersecurity**
- PS Category – **Software**
- Team ID – ⟨FILL⟩
- Team Name – ⟨FILL — exactly as registered on the portal⟩

**VISUAL:** template default. No custom graphics over the required fields.

**FOOTER:** template default.

**SPEAKER INTENT:** be flawless and unremarkable; this slide can only lose points, not win them.

**EVIDENCE:** the PS record on sih.gov.in.

---

============================================================
## SLIDE 2 — `IDEA TITLE`
*(Official pointers: Detailed explanation of the proposed solution · How it addresses the problem · Innovation and uniqueness of the solution)*
============================================================

**HEADLINE:**
Reasoning across sessions, not just parsing packets

**BODY — Proposed solution:**
- Reads a passive **PCAP** of SMTP / IMAP / POP3 traffic — including SMTPS, IMAPS, POP3S
- Reconstructs each mail session and produces a **standards-cited cryptographic security posture**
- Never connects to a mail server · no keys · no message content read

**BODY — How it addresses the problem:**
- Email transport security fails **silently**; after an incident the capture is the only evidence
- But that evidence is **encrypted and ambiguous**: TLS 1.3 hides the certificate entirely, and a
  **stripped STARTTLS is byte-identical to a client that simply declined**
- Judging one session alone, a tool must either **guess** or **stay silent**

**BODY — Innovation and uniqueness:**
- **Cross-session reasoning**: compares a session against **comparable prior sessions at the same
  endpoint, protocol and TLS mode**, resolving ambiguities a single session cannot
- **Six evidence states** — so missing evidence never becomes a false verdict in either direction
- Our **source-code audit of five competing implementations found none performing cross-session
  reasoning**

**KEY METRIC:** 0 of 5 audited implementations reason across sessions

**VISUAL / DIAGRAM:** same-server contrast
```
Same server, same capture
  Client A:  ✗ ✗ ✗ ✗ ✗     never upgrades
  Others:    ✓ ✓ ✓ ✓ ✓ ✓   always upgrade
                 ↓
  "This endpoint consistently lacks the upgrade capability
   while comparable endpoints at the same server have it."
```

**LABELS:** `Session`, `Same server`, `Control endpoint`, `Deviation — evidenced`

**CALLOUT:** *Within one session, stripping and non-support are byte-identical. Across sessions,
they are not.*

**SPEAKER INTENT:** make the judge feel the inference problem, then show we solved it.

**EVIDENCE:** `docs/research/01D-sih-competitor-source-audit.md` §4;
`docs/finalization/06-cross-session-demo.md`

---

============================================================
## SLIDE 3 — `TECHNICAL APPROACH`
*(Official pointers: Technologies to be used · Methodology and process for implementation)*
============================================================

**HEADLINE:**
A deterministic evidence pipeline — with AI kept in its place

**BODY — Technologies:**
- **Python 3.9+**, **tshark/Wireshark** (dissection), **FastAPI**, **SQLite**, **ReportLab** (PDF)
- **0 third-party Python runtime packages** in the analysis core; **TShark is the required external dissection binary**
- Dashboard: plain ES modules — **no npm packages, no build step**

**BODY — Methodology:**
- **16 standards-bound rules** + **3 cross-session rules** (baseline requires ≥5 comparable sessions)
- Assesses: TLS version · cipher · key exchange · forward secrecy · X.509 validity, key strength,
  signature algorithm, chain structure · STARTTLS/STLS integrity · insecure configuration
- **Every finding cites one of 11 published standards** (8 RFCs + 3 NIST SPs)
- **AI lane is bounded**: capped at **4.0** against a **30-point severity-tier gap** — it re-orders
  within a tier and **can never create a finding**

**KEY METRIC:** 19 rules · 11 standards · 0 third-party Python runtime packages in the analysis core

**VISUAL / DIAGRAM — pipeline (primary):**
```
PCAP → dissect → session reconstruction → 16 deterministic rules
     → 3 cross-session rules → evidence fusion → coverage-gated posture
     → JSON / HTML / PDF + analyst dashboard

          ML lane ──────────► ranking only  (capped 4.0 / 30-pt tier gap)
                     ✗ never writes a finding
```

**SECONDARY VISUAL — six evidence states** *(exact spelling and order — `evidence/states.py`)*:
`OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE`

**CALLOUT:** *Missing evidence can never improve a score.*

**FOOTER STRIP (provenance):**
`PCAP SHA-256 → frame → TCP stream → evidence state → finding → cited standard → report`

**SPEAKER INTENT:** prove a real engineered system exists, and that the AI boundary is deliberate.

**EVIDENCE:** `docs/phase12/00-release-state-audit.md` §3–4; rule registry enumeration

---

============================================================
## SLIDE 4 — `FEASIBILITY AND VIABILITY`
*(Official pointers: Analysis of feasibility · Potential challenges and risks · Strategies for overcoming them)*
============================================================

**HEADLINE:**
A working prototype — and we can name exactly what it cannot prove

**BODY — Feasibility (results strip):**

| **1219** | **10** | **11** | **< 1 s** | **20/20** |
|---|---|---|---|---|
| automated tests, 0 failures | real Postfix + Dovecot captures | published standards cited | per-capture analysis (115–320 ms) | identical repeat runs |

- Validated across **SMTP, IMAP, POP3** and **4 TLS modes** on real vendor traffic
- **Runs without network access** — no internet, no external AI service
- Adding certificate analysis changed **no existing verdict** (10/10 captures scored identically)

**BODY — Challenges, risks and strategies:**

| Risk | Reality | Strategy |
|---|---|---|
| TLS 1.3 encrypts the certificate (RFC 8446 §2) | **0 of 10** real captures expose one | report `NOT_OBSERVABLE` **with the reason** — never guess; extract fully where TLS ≤1.2 permits |
| Certificate **trust** needs an anchor a PCAP lacks (RFC 5280 §6) | chain *structure* validated; trust is not | state the boundary in every finding; operator-supplied trust store is the scoped next step |
| ML showed **no detection value** on held-out data | 0 unique true detections | ship bounded as prioritisation only; deterministic rules remain the source of truth |
| tshark is an external dependency | required binary | version-checked at startup, **fails closed** |

**KEY METRIC:** 1219 tests · 0 failures · 0 of 10 certificates visible under TLS 1.3

**VISUAL:** five-number results strip across the top; risk/strategy table beneath.

**CALLOUT:** *Certificate analysis is validated on 3 **generated** TLS 1.2 fixtures — the real
corpus is entirely TLS 1.3 and structurally cannot exercise it.*

**SPEAKER INTENT:** convert "it works" into "it works, measured, and they know their limits."

**EVIDENCE:** `docs/finalization/14-final-release-gate.md`;
`docs/finalization/04-real-pcap-evidence-pack.md`

---

============================================================
## SLIDE 5 — `IMPACT AND BENEFITS`
*(Official pointers: Potential impact on the target audience · Benefits of the solution)*
============================================================

**HEADLINE:**
Evidence an analyst can defend

**BODY — Target audience (named in the problem statement):**
- **SOC analysts** · **digital-forensics investigators** · **incident-response teams** ·
  **enterprise mail administrators**

**BODY — Benefits:**
- Works on **evidence teams already collect** — no new instrumentation
- **Passive**: never touches production mail servers · no keys · no message content
- **Runs without network access**: no internet, no external AI service; 0 third-party Python runtime packages in the analysis core (TShark required as an external binary)
- Every finding **cites a published standard**, so conclusions survive review
- Exports **JSON / HTML / PDF** for incident reports
- Surfaces **silent** failures — downgrades, deprecated TLS, weak certificates — that leave no
  trace in the mail itself

**KEY METRIC:** sub-second analysis, runs without network access

**VISUAL:** four user-type icons across the top; **dashboard or report screenshot** on the right
showing posture + coverage + a finding with its cited standard.

**CALLOUT:** *From a capture you already have to a citable posture assessment — in under a second,
with no server access.*

**FOOTER:** no server access · no keys · no internet · no message content read

**SPEAKER INTENT:** show this fits a real workflow and produces a usable artifact.

**EVIDENCE:** `docs/research/19-authoritative-ps-verification.md` §8;
`docs/finalization/12-offline-demo-audit.md`

> ⛔ **DO NOT add market size, ROI, user counts, or economic-impact figures to this slide.**
> No verified data exists — see `DO-NOT-CLAIM.md`.

---

============================================================
## SLIDE 6 — `RESEARCH AND REFERENCES`
*(Official pointer: Details / Links of the reference and research work)*
============================================================

**HEADLINE:** *(heading fixed — no custom headline needed)*

**BODY — Standards implemented and cited by the rule engine:**
- **RFC 8446** — TLS 1.3 · **RFC 8996** — deprecating TLS 1.0/1.1
- **RFC 3207** — SMTP STARTTLS · **RFC 2595** — TLS for IMAP/POP3 · **RFC 8314** — implicit TLS for mail
- **RFC 5280** — PKIX certificates · **RFC 6960** — OCSP · **RFC 9155** — deprecating SHA-1
- **NIST SP 800-52r2** — TLS server configuration
- **NIST SP 800-57 Pt.1 Rev.5** — key-length guidance
- **NIST SP 800-131A Rev.2** — cryptographic algorithm transitions

**BODY — Project research:**
- Authoritative problem-statement verification (official SIH portal record)
- TLS passive-visibility validation — what a capture can and cannot expose
- STARTTLS stripping prior-art review
- Source-code audit of five competing SIH26159 implementations
- ML evaluation on generator-held-out data (negative result documented)

**VISUAL:** two clean columns — Standards | Research. No decoration.

**SPEAKER INTENT:** demonstrate the work is standards-grounded, not self-invented.

**EVIDENCE:** standards list verified by enumerating the rule registry — these are the standards
the code actually cites, not a decorative bibliography.

---

## Final checks before export

- [ ] Exactly **6 slides** (delete the template's "Important Instructions" slide)
- [ ] Official headings **unchanged**
- [ ] Official sub-pointers **preserved**
- [ ] ⟨FILL⟩ fields completed — Team ID, Team Name
- [ ] No paragraph longer than two lines
- [ ] Every generated fixture labelled **"generated"**
- [ ] Cross-checked against `DO-NOT-CLAIM.md`
- [ ] Exported as **PDF**
