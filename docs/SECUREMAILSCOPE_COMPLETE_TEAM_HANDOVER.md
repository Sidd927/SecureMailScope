# SecureMailScope — Complete Team Handover

**Problem statement:** SIH26159 — *SecureMailScope: AI-Assisted Cryptographic Security Posture
Assessment for Secure Email Communications*
**Document date:** 2026-09-18 · **Reconstructed from:** repository, tests, Git history, research docs
**Audience:** a new teammate with cybersecurity/software background and zero exposure to this project

> **How to read this.** Every substantive claim carries a status marker. Nothing here is asserted
> from memory — each fact was checked against the repository while writing.
>
> `CONFIRMED` verified against an authoritative source · `IMPLEMENTED` code exists and is tested ·
> `EXPERIMENTALLY VALIDATED` an experiment in this repo measured it · `INFERRED` reasoned from
> confirmed facts · `PLANNED` designed, not built · `NOT IMPLEMENTED` · `NOT VERIFIED`

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Authoritative problem statement](#2-authoritative-problem-statement)
3. [Problem → gap → solution](#3-problem--gap--solution)
4. [Research journey](#4-research-journey)
5. [The important experiments](#5-the-important-experiments)
6. [Key scientific conclusions](#6-key-scientific-conclusions)
7. [Complete architecture](#7-complete-architecture)
8. [Phase-by-phase status](#8-phase-by-phase-status)
9. [Source code architecture](#9-source-code-architecture)
10. [Data flow](#10-data-flow)
11. [The evidence model](#11-the-evidence-model)
12. [Threat model](#12-threat-model)
13. [Testing architecture](#13-testing-architecture)
14. [Golden corpus](#14-golden-corpus)
15. [Security review history — defects found and fixed](#15-security-review-history--defects-found-and-fixed)
16. [Current limitations](#16-current-limitations)
17. [SIH requirements traceability](#17-sih-requirements-traceability)
18. [What is left to build](#18-what-is-left-to-build)
19. [Final demo story](#19-final-demo-story)
20. [Information available for the SIH pitch deck](#20-information-available-for-the-sih-pitch-deck)
21. [Team contribution guide](#21-team-contribution-guide)
22. [Developer rules](#22-developer-rules)
23. [Setup and commands](#23-setup-and-commands)
24. [Glossary](#24-glossary)
25. [References](#25-references)
26. [Source conflicts and their resolution](#26-source-conflicts-and-their-resolution)

---

## 1. Executive summary

### What is SecureMailScope?

A **passive network-forensics tool** that reads a packet capture (PCAP) of email traffic and
produces an evidence-backed assessment of the cryptographic security posture of that email
infrastructure — with every conclusion traceable to specific packets, and with explicit refusal to
conclude anything the capture cannot support.

### What problem does it solve?

`CONFIRMED` (from the official PS text) Email infrastructures suffer cryptographic
misconfigurations — obsolete TLS versions, weak ciphers, insecure STARTTLS implementations, bad
certificates. The PS states the gap directly: existing network tools *"provide extensive
packet-level visibility"* but *"do not automatically evaluate the overall cryptographic security
posture of email communications or provide intelligent risk assessment and prioritization."*

Restated plainly: **Wireshark can already show an analyst everything. That is precisely the
problem.** The evidence is present in the capture; the *expert judgement* over it does not scale.

### Who is it for?

`CONFIRMED` The PS names: Security Operations Centers (SOC), Digital Forensics teams, Incident
Response teams, and enterprise administrators.

### What input does it take?

`CONFIRMED` PCAP/PCAPNG files containing SMTP, IMAP and POP3 traffic — including the implicit-TLS
variants SMTPS/IMAPS/POP3S. **Passive only.** No active probing, no DNS queries, no key material.

### What does it produce?

| Output | Status |
|---|---|
| `SessionEvidence` — reconstructed protocol/TLS state per TCP stream | `IMPLEMENTED` |
| `SecurityFinding[]` — standards-bound per-session findings | `IMPLEMENTED` |
| `CrossSessionFinding[]` — deviation findings vs baselines/controls | `IMPLEMENTED` |
| ML anomaly scores | `NOT IMPLEMENTED` (Phase 6) |
| Posture score / prioritisation | `NOT IMPLEMENTED` (Phase 8) |
| JSON / HTML / PDF reports | `NOT IMPLEMENTED` (Phase 9) |
| Dashboard | `NOT IMPLEMENTED` (Phase 10) |

### What makes this different from just running TShark/Zeek/Suricata?

`EXPERIMENTALLY VALIDATED` — this was audited at source level, not assumed:

- **Zeek** has no `imap.log` and **no `pop3.log` at all**; its entire SMTP STARTTLS output is a
  single boolean `tls: bool`. Its shipped `weak-keys.zeek` defaults to `tls_minimum_version = TLSv10`,
  meaning TLS 1.0/1.1 raise **no notice by default** — contradicting RFC 8996.
- **Suricata** has a 96-line IMAP file (protocol-detection patterns only) and **no POP3 parser**.
  Its `TLS_REJECTED` event structurally *cannot fire* on capability stripping, because it requires
  the client to have sent `STARTTLS` — which stripping prevents.
- **ET Open ruleset**: 43 active SMTP+IMAP+POP3 rules, **zero** referencing STARTTLS or STLS.
- **Snort 3 community**: 4,017 rules, **zero** STARTTLS references.
- **Arkime** parses all three protocols and tags `smtp:starttls`, but when cleartext continues after
  a STARTTLS exchange it **silently resumes cleartext parsing** — it observes the downgrade condition
  and normalises it into successful parsing, emitting no finding.
- **All 285 Zeek `zkg` packages** enumerated: zero mention starttls, stls, imap, pop3, downgrade,
  credential, cipher or posture.

The one-sentence version: **these tools *see* the evidence; none of them *evaluate* it.**

### Where does AI/ML fit?

`CONFIRMED` The PS explicitly requires AI/ML (*"Application of AI/ML techniques"*, *"AI-assisted
anomaly detection for suspicious TLS sessions"*). `NOT IMPLEMENTED` — the ML lane is Phase 6.

`EXPERIMENTALLY VALIDATED` A naive per-session Isolation Forest was tested against the deterministic
engine on our corpus and **performed worse**: it flagged 2/32 attacks versus the deterministic
engine's 8/32, with *more* false positives (9 vs 7). Its distinctive contribution was zero real
findings — it re-flagged truncated captures. Phase 6 therefore must select a model **empirically**,
not assume one.

### Core technical thesis

> **SecureMailScope assesses an email infrastructure rather than individual sessions. By reasoning
> across every session in a capture it distinguishes a deviation from a configuration choice — a
> distinction no per-session analyzer can make — and reports each finding with its evidence, its
> provenance, and what could not be observed.**

The project's governing discipline: **it is better to say "insufficient evidence" than to
manufacture a security conclusion.**

---

## 2. Authoritative problem statement

**Source of truth:** `docs/research/19-authoritative-ps-verification.md`, verified against the live
official portal `https://sih.gov.in/sih2026PS` on 2026-09-16. Raw portal HTML saved as immutable
evidence at `docs/research/evidence/sih2026-portal-SIH26159-20260916.html`.

| Field | Value | Status |
|---|---|---|
| PS ID | SIH26159 | `CONFIRMED` |
| Title | SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications | `CONFIRMED` |
| Organization / Department | National Technical Research Organisation (NTRO) | `CONFIRMED` |
| Category | Software | `CONFIRMED` |
| Theme | Blockchain & Cybersecurity | `CONFIRMED` |
| **Deadline** | **30 September 2026** | `CONFIRMED` — see [§26](#26-source-conflicts-and-their-resolution) |
| Submitted ideas | 1/500 at time of check (locks at 500) | `CONFIRMED` |
| Dataset | *"Synthetic - Participants May generate IMAPS, POP3S, SMTPS Data using any E-mail server/client of their interest and capture pcap dump"* | `CONFIRMED` |
| YouTube link / contact | **empty** — no official clarification channel exists | `CONFIRMED` |

### Confirmed requirements

Stable IDs used throughout the codebase, docs and tests.

**Deterministic extraction — D-01…D-18:** PCAP ingest · protocol ID · TCP reassembly · STARTTLS
detection · STARTTLS **validation** · TLS handshake reconstruction · version · cipher · key exchange ·
X.509 extraction · chain validation · expiry · public key/length · signature algorithm · weak/
deprecated crypto · insecure configuration · Forward Secrecy · cryptographic feature extraction.

**AI/ML — A-01…A-05:** cryptographic risk classification · **AI-assisted anomaly detection for
suspicious TLS sessions** · security posture scoring · threat prioritisation · mitigation
recommendation.

**Outputs — R-01…R-05:** prioritised findings · comprehensive posture assessment · exportable
reports in **JSON, PDF and HTML** · interactive visualization dashboard · comprehensive forensic
reports.

### What the PS does NOT mention — verified by mechanical search

`CONFIRMED` A word-boundary regex search over the official title + description (4,030 characters)
returns **zero occurrences** of:

```
spf   dkim   dmarc   dns   arc   dane   mta-sts   bimi   dnssec
mx record   s/mime   pgp   phishing   spoof   reputation   domain   blockchain
```

**This is load-bearing and cost real project time to discover.** The title says "Secure Email
Communications" and "Security Posture Assessment", which in common industry usage means
SPF/DKIM/DMARC domain posture. The body says something entirely different. Two competitor
repositories we audited made exactly this error (`fredfe08` ships `spf_checker.py`,
`dkim_checker.py`, `dmarc_checker.py`).

> ⛔ **Do not add DNS, SPF, DKIM, DMARC, MTA-STS, DANE or BIMI features.** They are out of scope.
> The PS is a **transport-security / packet-capture** problem, not a **domain-authentication** one.

What the PS vocabulary actually is: `tls` (14 occurrences), `certificate` (7), `smtp`/`imap`/`pop3`
(4 each), `cipher` (4), `forensic` (4), `passive` (3), `starttls` (3), `pcap` (2), `x.509` (2),
`tcp` (2), `key exchange` (2), `forward secrecy` (1).

---

## 3. Problem → gap → solution

```
REAL-WORLD PROBLEM
  Mail servers are long-lived, inherit legacy config, and are rarely re-baselined.
  Backward compatibility outranks crypto hygiene (a working inbox beats a good cipher).
  Ownership is split: mail admins own servers, security owns policy, nobody owns crypto posture.
        ↓
TOOLING GAP
  Tools decode but do not evaluate. Verified at source level: Zeek/Suricata/Snort/ET/Arkime/
  NetworkMiner expose the bytes; none produce a security verdict for mail transport.
  Two of the three mail protocols produce NO security log output at all in stock tooling.
        ↓
WHY EXISTING TOOLS ARE INSUFFICIENT
  Zeek's `tls=F` is produced identically by four different situations:
    (a) server never supported STARTTLS
    (b) client declined it
    (c) it was stripped in transit
    (d) implicit TLS on port 465 where STARTTLS is irrelevant
  Distinguishing these four is what no shipped tool does.
        ↓
SECUREMAILSCOPE
  Reuse mature dissection (tshark). Own the judgement layer.
        ↓
TECHNICAL MECHANISM
  Evidence-typed session reconstruction → standards-bound deterministic rules →
  cross-session baselines and control contrast → (future) ML anomaly lane → posture → reports
        ↓
SECURITY OUTCOME
  Findings an analyst can defend: anchored to frames, citing a standard, stating their own
  limitations, and abstaining where the capture cannot decide.
```

### The seven layers — a distinction that matters

Confusing these is the most common way to misunderstand this project.

| Layer | Question it answers | Owner |
|---|---|---|
| **Packet dissection** | What bytes were on the wire? | tshark (reused, not rebuilt) |
| **Session reconstruction** | What protocol conversation happened? | Phase 3 |
| **Deterministic security analysis** | What does *this one session* mean against a standard? | Phase 4 |
| **Cross-session reasoning** | How does this session compare with other evidence? | Phase 5 |
| **ML anomaly detection** | Is this statistically unusual vs learned normal? | Phase 6 `PLANNED` |
| **Posture assessment** | What is the overall state, and how complete is our view? | Phase 8 `PLANNED` |
| **Reporting** | How does an analyst consume and defend this? | Phase 9–10 `PLANNED` |

---

## 4. Research journey

Ten research documents in `docs/research/`. Each is summarised here as
**Question → Method → Result → Interpretation → Design consequence**.

### 4.1 Problem-statement forensics (`01-problem-statement-analysis.md`)

- **Question:** what does SIH26159 actually require?
- **Method:** retrieved verbatim PS text; mechanical term-presence analysis; requirement extraction
  into stable IDs.
- **Result:** `CONFIRMED` the PS is a passive-PCAP transport-security problem. 18 deterministic
  requirements vs 5 AI requirements.
- **Interpretation:** this is **predominantly a protocol-engineering problem with an ML layer on
  top**, despite an AI-forward title.
- **Design consequence:** scope locked to PCAP/TLS/mail protocols; effort allocated to the
  deterministic engine; requirement IDs D/A/R created and used everywhere since.

### 4.2 TLS visibility validation (`01A-tls-visibility-validation.md`)

- **Question:** what can a passive observer actually see, per TLS version?
- **Method:** RFC 8446 primary reading + Zeek documentation cross-check; built a 27-property ×
  4-version visibility matrix.
- **Result:** `CONFIRMED` TLS 1.3 encrypts everything after ServerHello including `Certificate`
  (RFC 8446 §2) — confirmed independently by Zeek's own docs: *"TLS 1.3 hides these from passive
  observation systems."* **And a wider finding: every resumed session omits the Certificate message
  at any TLS version** (RFC 8446 §2.2).
- **Interpretation:** certificate blindness is **not** a TLS 1.3 problem — it is a
  TLS-1.3-*and*-resumption problem, and mail clients resume aggressively. But it affects only
  **5 of 22** PS deliverables; version, cipher, key-exchange group, SNI and resumption stay visible.
- **Design consequence:** `NOT_OBSERVABLE` became a first-class evidence state. An early claim that
  this was our "strongest differentiator" was **withdrawn** — evidence tiering is prior art
  (Delgado 2026; Casey's Certainty Scale 2002; CVSS Report Confidence). It is a *correctness
  requirement*, not an innovation.

### 4.3 STARTTLS prior art (`01B-starttls-prior-art.md`)

- **Question:** do existing tools already detect STARTTLS stripping/injection?
- **Method:** direct source inspection — Zeek scripts, Suricata `app-layer-smtp.c`, ET Open rules.
- **Result:** `CONFIRMED` no shipped Zeek script, Suricata event or ET rule detects it. See
  [§1](#what-makes-this-different-from-just-running-tsharkzeeksuricata) for the specifics.
- **Interpretation:** an **integration and coverage gap, not a detection-science gap**. The attacks
  are published research (RFC 3207 §6 in 2002; Durumeric IMC 2015; Poddebniak USENIX Sec 2021;
  NDSS 2025). We claim **no detection novelty**.
- **Design consequence:** focus on the STARTTLS layer (cleartext at every TLS version, so immune to
  the TLS 1.3 limitation) and on IMAP/POP3, which stock tooling ignores entirely.

### 4.4 Tool-stack reconstruction (`01C-existing-tool-stack-reconstruction.md`)

- **Question:** could an analyst just combine Zeek + Suricata + Arkime instead?
- **Method:** enumerated all 285 `zkg` packages; downloaded Snort 3 community rules; read Arkime
  parser source; checked NetworkMiner docs.
- **Result:** `CONFIRMED` even combined, the stack yields no STARTTLS verdict, no IMAP/POP3 security
  evidence, and no posture assessment.
- **Interpretation, stated honestly:** **a large fraction of the PS — the entire extraction layer —
  is already solved.** Rebuilding it would be rebuilding mature infrastructure worse.
- **Design consequence:** ADR-0001 — reuse tshark for dissection; own the judgement layer.

### 4.5 Competitor source audit (`01D-sih-competitor-source-audit.md`)

- **Question:** what have other SIH teams already built?
- **Method:** source-level inspection of five public repositories (READMEs explicitly distrusted).
- **Result:** `CONFIRMED` ~10 public repos target this PS. `CipherPost` already ships
  `rule_starttls_strip` cited to RFC 3207 with SMTP *and* IMAP test fixtures. `gouravsehlangia` has
  the most complete STARTTLS/STLS state machine including POP3. `Prahari` has a well-cited rules
  engine. `saravana` implements `NOT_OBSERVABLE` posture states.
- **Interpretation:** three of four "surviving differentiators" were already built by competitors.
  A README-vs-code check proved the point in both directions: `fredfe08` was credited with a
  "four-fact STARTTLS model" that **does not exist in its source**.
- **Design consequence:** differentiation narrowed to **cross-session reasoning** — verified absent
  from all five codebases — plus correctness discipline. Claims downgraded from "novel" to
  "integration and correctness".

### 4.6 AI opportunity validation (`10A`, `10B`)

- **Question:** where does AI legitimately help?
- **Method:** traced every competitor's AI execution path in source; ran an Isolation Forest
  experiment; ran a prompt-injection experiment.
- **Result:** `EXPERIMENTALLY VALIDATED` **no competitor's AI does anything deterministic rules
  cannot.** `gouravsehlangia`'s LLM has severity decided by a hardcoded if/elif chain *inside the
  prompt builder*, with a template fallback producing the same text. `saravana`'s RandomForest
  trains on 2,500 self-generated archetypes. `CipherPost`'s ML learns its own rules engine — and
  says so in a source comment.
- **Interpretation:** the bar is on the floor. The differentiation available is not "we have AI" but
  "our AI does something that provably cannot be done deterministically, and we state what."
- **Design consequence:** two-lane architecture with a hard boundary; LLM deferred out of v1;
  Phase-6 ML must be unsupervised over **cross-session deviation features** and selected by a
  generator-held-out bake-off.

### 4.7 Requirements gate (`19-authoritative-ps-verification.md`)

- **Question:** is our understanding of the PS actually correct?
- **Method:** fetched the live official portal; diffed the description token-by-token against our
  stored mirror.
- **Result:** `CONFIRMED` every content token matched (only `<br>` tags differed). Six exact phrases
  verified verbatim.
- **Design consequence:** assumption A-01 promoted to FACT; the deadline conflict resolved; scope
  confirmed passive-PCAP-only.

---

## 5. The important experiments

All experiment code is in `research/experiments/` and is reproducible.

### 5.1 OQ-25 — cross-session baseline experiment (`02A`)

**Verdict: `EXPERIMENTALLY VALIDATED` — RESULT B, PARTIALLY VERIFIED.**

Nine scenarios, 260 sessions, deterministic, no ML. Ground truth held in a separate structure never
visible to any detector.

| Detector | False positives | False negatives |
|---|---|---|
| **D1 per-session** (competitor-style) | **120** | **70** |
| **D2 consistency rule only** | **35** (**−71 %**) | 70 (unchanged) |
| **D2 + server-contrast rule** | 75 (−38 %) | **35** (**−50 %**) |

**Two mechanisms that trade against each other.** No configuration achieved both gains.

#### The headline finding — the per-session detector is *inverted*

- **Legitimate decline:** D1 raises a CRITICAL finding on **25 of 25 benign sessions**.
- **Advertisement stripping:** D1 misses **30 of 30 genuine attack sessions**.

The reason is structural: stripping removes the advertisement, so `saw_starttls_offer` is false and
the rule never fires — while a legitimate decline keeps the advertisement and fires every time.
This applies to CipherPost's shipped rule as written.

#### What else it established

| Sub-experiment | Result |
|---|---|
| **Blind stripping (11J)** — 100 % stripped, no control | 🔴 **Total failure.** FN 30/30 for *both* detectors. Unresolvable from capture alone |
| **Control endpoint (11J′)** — same attack, control present | ✅ **FN 30 → 0, TP 0 → 30.** The strongest result in the programme |
| **Legitimate-decline inversion** | Consistency rule takes FP 25 → 0; contrast rule *adds* FP (0 → 20) on heterogeneous-but-legitimate client populations |
| **History threshold** | Step function: below 5 sessions the engine abstains; at ≥5 the baseline is usable |
| **Time-aware vs capture-wide** | Prior-history baselining beats pooling: FP 20 → 0 on a legitimate mid-capture config change |
| **NAT / shared identity** | 🔴 FP 20, no improvement. Identity collapse defeats the method |
| **Infrastructure vs session view** | Session view: 20 identical lines. Infrastructure view: per-endpoint upgrade rates making the outlier visible at a glance. Genuinely different information |

**What it proves:** cross-session reasoning eliminates the dominant false-positive class and, where
a control exists, detects what per-session analysis cannot.
**What it does NOT prove:** that stripping is detectable in general; that any attacker is
identified; that the numbers generalise beyond this corpus (they are corpus-relative, not
population rates).

### 5.2 OQ-28 — packet-level validation (`02B`)

**Verdict: `EXPERIMENTALLY VALIDATED` — the session-model result replicated on real packets.**

| Property | Value |
|---|---|
| Corpus | 18 real `.pcap` files (17 crafted + 1 striptls-produced) |
| Packets / streams | 1,113+ packets, 112 streams |
| Construction | Real Ethernet/IPv4/TCP, real sequence numbers, real 3-way handshakes and FIN teardown |
| Independent validation | **tshark 4.6.8's own SMTP dissector** extracted `EHLO`, code `250`, parameters `…,STARTTLS,AUTH PLAIN LOGIN,8BITMIME`; its **TLS dissector** identified handshake types 1/2, version `0x0303`, SNI `mail.example.org`. tcpdump 4.99.1 read every file |

| Detector | TP | FP | FN |
|---|---|---|---|
| D1 per-session | 2 | **25** | **30** |
| D2 cross-session | 2 | **7 (−72 %)** | 30 |
| D2 + control-endpoint | **8** | 7 | **24** |

**Session model gave −71 %; real packets gave −72 %.** No parameter was tuned.

#### The byte-identity proof

`EXPERIMENTALLY VALIDATED` Comparing application payloads of `B_strip_advert` (attack) and
`I_no_support` (legitimate):

```
[0] IDENTICAL  b'220 mail.example.org ESMTP Postfix\r\n'
[1] IDENTICAL  b'EHLO client.example.net\r\n'
[2] IDENTICAL  b'250-mail.example.org\r\n250-PIPELINING\r\n250-SIZE 10240...'
[3] IDENTICAL  b'AUTH LOGIN\r\n'
-> application-layer evidence identical: True
```

Every application byte matches. Only the server IP differs, which is not security evidence.
**Both detectors therefore return the same verdict for both — correctly.**

#### Network-condition handling

| Condition | Result |
|---|---|
| Retransmission (duplicate seq) | ✅ deduplicated; facts correct |
| Out-of-order (segment B before A) | ✅ reassembled by sequence |
| Lost capability response | ✅ correctly `AMBIGUOUS`, not fabricated |
| Segmentation (small MSS) | ✅ token spanning segments recovered |
| **Truncation — 5 cut points** | ✅ **all abstain; zero SUSPECT findings.** Mid-handshake yields `NOT_OBSERVABLE`, not `False` |
| Repeatability | ✅ identical output hash `2d149db5fb840b0670b420825650a62d` across 3 runs |

### 5.3 OQ-33 — actual striptls validation (`02B §15`)

**Verdict: `EXPERIMENTALLY VALIDATED` for the mangling logic; `NOT VERIFIED` for the live proxy.**

- **What was executed:** `tintinweb/striptls` v0.5 cloned fresh. It is Python 2 (`except X, e:`,
  **10 sites**). A mechanical `except`-only fix made it importable under Python 3.9 — **no logic
  changed.** The **actual mangling functions** were then run on real server responses.
- **Protocols tested:** SMTP, POP3, IMAP.
- **Result:** SMTP output was **byte-identical** to our constructed `CAPS_WITHOUT["smtp"]`.
  POP3 (`STLS`) and IMAP (`STARTTLS`) strippers confirmed semantically.
- **Generated PCAP:** `pcaps/S_striptls_real.pcap` (sha256 `b69cd2970231bb4f`) whose server payload
  was produced by striptls's own code. tshark reports **0 STARTTLS advertisements**; our extractor
  reports `starttls_advertised = AMBIGUOUS` + `plaintext_credentials = OBSERVED` — identical to the
  constructed `B_strip_advert`.
- ⛔ **What was NOT validated:** the **full live-socket proxy was never run.** Porting it to py3
  needs a genuine rewrite of the recv/send loop (6 socket I/O sites, 0 existing decode/encode
  calls), which would change the artefact under test. Live packet capture was also blocked by
  `/dev/bpf` permissions. **Do not claim a live MITM proxy was validated.**
- **GPL de-vendoring decision:** striptls is **GPLv2** and this repo has no LICENSE. Vendoring a
  modified copy would impose copyleft. The file is therefore **gitignored** and regenerated on
  demand by `research/experiments/oq28/fetch_striptls.py`.

---

## 6. Key scientific conclusions

### What we know — `EXPERIMENTALLY VALIDATED`

1. **Passive single-session analysis has a fundamental ambiguity.** Stripping and genuine
   non-support are byte-identical at the application layer. Proven, not argued.
2. **STARTTLS absence is not stripping.** Any tool that says otherwise is over-claiming.
3. **The naive per-session rule is inverted** — it fires on the benign case and is blind to the
   attack.
4. **Control endpoints provide genuinely discriminating evidence.** FN 30→0 (session model),
   FN 6→0 (packet level) when an unaffected comparable endpoint exists.
5. **History reduces noise** — −71 %/−72 % false positives via the consistency rule alone.
6. **Time-aware baselines matter** — prior-history beats capture-wide pooling on legitimate
   reconfiguration (FP 20→0).
7. **Insufficient history requires abstention** — the threshold is a step function around 5
   comparable sessions.
8. **Deterministic analysis outperformed naive ML on the tested corpus** — Isolation Forest flagged
   2/32 attacks vs deterministic 8/32, with more false positives.
9. **TLS 1.3 and all resumed sessions hide the certificate** — RFC 8446 §2 and §2.2.
10. **Evidence tiering is prior art**, not our innovation (Delgado 2026; Casey 2002; CVSS RC).

### What we do NOT know — `NOT VERIFIED`

1. **Attacker attribution.** Passive capture cannot establish who did anything. Never claim it.
2. **Universal STARTTLS stripping detection.** With 100 % stripping and no control, the method
   fails completely (FN 30/30). This is a permanent boundary, not a bug.
3. **TLS 1.3 certificate visibility.** Not recoverable passively without key material.
4. **Behaviour outside validated server dialects.** The entire corpus is single-vendor
   (Postfix/Dovecot-modelled strings we wrote). Real-world banner diversity is untested — this is
   open item **OQ-33r**.
5. **Whether any ML model beats the deterministic engine.** Unknown until the Phase-6 bake-off.
   The one model tested did worse.
6. **Real-world TLS 1.3 vs 1.2 proportions in mail traffic** (OQ-02) — never measured; our corpus
   does not answer it.
7. **Whether NAT-collapsed client identity can be disambiguated** (OQ-29).

---

## 7. Complete architecture

```
                         PCAP / PCAPNG
                              │
                              ▼
                  ┌───────────────────────┐
                  │  Capture Ingestion    │   IMPLEMENTED (Phase 2)
                  │  validate + SHA-256   │
                  └───────────┬───────────┘
                              ▼
                  ┌───────────────────────┐
                  │  tshark Dissection    │   IMPLEMENTED (Phase 2) — reused, not rebuilt
                  │  -T ek, streaming     │
                  └───────────┬───────────┘
                              ▼
                  ┌───────────────────────┐
                  │  Normalization        │   IMPLEMENTED (Phase 2)
                  │  FrameEvidence        │   isolates tshark's schema
                  └───────────┬───────────┘
                              ▼
                  ┌───────────────────────┐
                  │ Session Reconstruction│   IMPLEMENTED (Phase 3)
                  │ SMTP / IMAP / POP3    │
                  │ state machines        │
                  └───────────┬───────────┘
                              ▼
                      ╔═══════════════╗
                      ║SessionEvidence║        the stable contract
                      ╚═══════╤═══════╝
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌───────────────────────┐          ┌───────────────────────┐
│ Deterministic Security│          │  Cross-Session        │
│ Analysis (Phase 4)    │          │  Reasoning (Phase 5)  │
│ IMPLEMENTED           │          │  IMPLEMENTED          │
│ 8 rules, standards-   │          │  baselines + control  │
│ bound                 │          │  contrast, 3 rules    │
└───────────┬───────────┘          └───────────┬───────────┘
            │  SecurityFinding[]               │ CrossSessionFinding[]
            └─────────────────┬────────────────┘
                              ▼
                  ┌───────────────────────┐
                  │  ML Anomaly Lane      │   PLANNED (Phase 6)
                  │  separate lane, score │   ── never writes a finding ──
                  └───────────┬───────────┘
                              ▼
                  ┌───────────────────────┐
                  │  Posture / Risk Layer │   PLANNED (Phase 8)
                  └───────────┬───────────┘
                              ▼
                  ┌───────────────────────┐
                  │  Analyst / Dashboard  │   PLANNED (Phase 10)
                  └───────────┬───────────┘
                              ▼
                  ┌───────────────────────┐
                  │  Forensic Reports     │   PLANNED (Phase 9)
                  │  JSON / HTML / PDF    │
                  └───────────────────────┘
```

### The two-lane invariant — the single most important architectural rule

The **security lane** (deterministic rules + cross-session + risk) produces **all facts and
verdicts**. The **anomaly lane** (ML) produces **only scores**. They meet exactly once, at
prioritisation, through an explicit documented policy.

**ML and AI may never create, modify or delete a finding.** A `--no-ai` run must produce identical
security findings — a testable, demoable property.

---

## 8. Phase-by-phase status

`CONFIRMED` — all commits verified against Git on 2026-09-18.

| Phase | Purpose | Status | Branch / Commit | Major outputs |
|---|---|---|---|---|
| **Research** | PS forensics, validation passes, experiments | ✅ Complete | `f6cd544` (on `main`) | 10 research docs, experiment code, golden corpus |
| **Architecture** | Architecture package + engineering OS | ✅ Complete | `470b430` (on `main`) | 16 arch docs, ADR 0001–0014, 11 skills, 5 agents |
| **Phase 1** | Foundation + evidence schema | ✅ Complete, **merged** | tag `v0.1.0-phase1` = `8e8a288` | `EvidenceField`, `Capture`, `TsharkAdapter`, golden manifest |
| **Phase 2** | Ingest + dissection pipeline | ✅ Complete, **merged** | `36eb16b` | `analyze_capture()`, `AnalysisRun`, `fields.py`, `FrameEvidence` |
| **Phase 3** | Session reconstruction | ✅ Complete, **merged (= `main`)** | `2fd5f09` | `SessionEvidence`, 3 protocol state machines |
| **Phase 4** | Deterministic security engine | ✅ Complete, **NOT merged** | `28ed634` | `SecurityFinding`, rule registry, 8 rules |
| **Phase 5** | Cross-session reasoning | ✅ Complete, **NOT merged** | `16b130b` | `CrossSessionFinding`, baselines, contrast, 3 rules |
| **Phase 6** | ML anomaly lane | 🔴 Not started | — | `PLANNED` |
| **Phase 7** | ML integration + `--no-ai` | 🔴 Not started | — | `PLANNED` |
| **Phase 8** | Risk / posture / prioritisation | 🔴 Not started | — | `PLANNED` |
| **Phase 9** | Reports (JSON/HTML/PDF) | 🔴 Not started | — | `PLANNED` |
| **Phase 10** | Dashboard | 🔴 Not started | — | `PLANNED` |
| **Phase 11** | Optional analyst LLM | 🔴 Deferred from v1 | — | ADR-0008 |
| **Phase 12–14** | Hardening, performance, demo | 🔴 Not started | — | `PLANNED` |

**Current Git state:** branch `phase/05-cross-session-reasoning`, HEAD `16b130b`, clean tree.
`main` = `2fd5f09`. Remote `git@github.com:Sidd927/SecureMailScope.git`. All five phase branches
pushed. One tag. **No history has ever been rewritten; no force push has ever been made.**

> ⚠️ **Note on phase numbering.** The brief for this handover describes "Phase 1" as
> *research + architecture*. In the **repository**, research (`f6cd544`) and architecture
> (`470b430`) are separate commits that precede the tag, and `v0.1.0-phase1` (`8e8a288`) marks the
> **foundation code**. Both framings appear in project documents. This table uses the repository's
> structure, which is authoritative. See [§26](#26-source-conflicts-and-their-resolution).

---

## 9. Source code architecture

`CONFIRMED` — 34 Python modules under `src/securemailscope/`, listed exactly as they exist.

```
src/securemailscope/
├── __init__.py          version + ANALYSIS_VERSION
├── config.py            Config: tshark path/version, size, timeout, frame ceiling
├── evidence/            THE CORRECTNESS BACKBONE
│   ├── states.py        EvidenceState, Provenance, EvidenceField
│   ├── capture.py       Capture, sha256_file (streamed)
│   └── run.py           AnalysisRun, RunStatus, schema/engine versions
├── dissect/             tshark boundary (Phase 2)
│   ├── tshark.py        TsharkAdapter, DissectStatus, streaming
│   ├── fields.py        every tshark field name — the ONLY place they appear
│   └── normalize.py     FrameEvidence, TlsEvidence, MailEvidence, payload decoder
├── ingest/              pipeline entry point (Phase 2)
│   ├── validate.py      capture validation boundary
│   └── pipeline.py      analyze_capture()
├── session/             session reconstruction (Phase 3)
│   ├── model.py         SessionEvidence, AppState, TlsState, Transition
│   ├── grouping.py      StreamGroup, role resolution
│   ├── base.py          ProtocolSessionReconstructor, TLS classification
│   ├── protocols.py     SMTP / IMAP / POP3 reconstructors
│   └── reconstruct.py   reconstruct_sessions()
├── analysis/            deterministic security lane (Phase 4)
│   ├── model.py         SecurityFinding, Severity, FindingStatus, EvidenceRef
│   ├── registry.py      SecurityRule ABC, RuleRegistry, ref()
│   ├── engine.py        SecurityAnalysisEngine, AnalysisReport
│   └── rules/           tls_rules · starttls_rules · plaintext_rules
└── crosssession/        cross-session lane (Phase 5)
    ├── comparability.py ComparabilityKey/Assessment
    ├── baseline.py      Baseline, PopulationIndex, build_baseline
    ├── contrast.py      ContrastState, evaluate_contrast
    ├── model.py         CrossSessionFinding, Deviation
    ├── rules.py         CS-STARTTLS-001/002, CS-TLS-001, BLIND_STRIPPING
    └── engine.py        CrossSessionEngine, CrossSessionConfig
```

### Key module reference

| Module | Purpose | In → Out | Phase |
|---|---|---|---|
| `evidence/states.py` | `EvidenceField` — frozen, validating, with factory constructors. Makes forbidden conversions structurally impossible | value+basis → immutable typed field | 1 |
| `evidence/capture.py` | Content-addressed capture identity, streamed SHA-256 | path → `Capture` | 1 |
| `evidence/run.py` | `AnalysisRun` with 8 statuses and all four versions | — | 2 |
| `dissect/tshark.py` | Safe subprocess boundary. Arg-array only, never shell. Exit-code map, timeout, size guard, streaming `-T ek` | path → `DissectResult` | 1–2 |
| `dissect/fields.py` | Every tshark field name isolated here so version drift touches one file | — | 2 |
| `dissect/normalize.py` | tshark records → `FrameEvidence`; bounded payload decoder | records → frames | 2 |
| `ingest/pipeline.py` | `analyze_capture(path) -> (AnalysisRun, [FrameEvidence])` — the single entry point | PCAP → run + frames | 2 |
| `session/protocols.py` | Three protocol grammars behind one interface | frames → events | 3 |
| `session/model.py` | `SessionEvidence` — the Phase-4/5 input contract | — | 3 |
| `analysis/engine.py` | Applies the rule registry per session; fails closed on rule errors | sessions → findings | 4 |
| `crosssession/baseline.py` | Prior-history baselines + `PopulationIndex` (the O(n²) fix) | sessions → `Baseline` | 5 |
| `crosssession/contrast.py` | ADR-0005 four-state control contrast | sessions → `ContrastResult` | 5 |

---

## 10. Data flow

```
PCAP file
   │  IMPLEMENTED — validate_capture(): NOT_FOUND / NOT_A_FILE / UNREADABLE /
   ▼                EMPTY_FILE / TOO_LARGE  (EMPTY_FILE ≠ parsed-EMPTY)
SHA-256 (streamed, ours — not delegated to capinfos)
   │  IMPLEMENTED
   ▼
AnalysisRun  (CREATED → VALIDATING → DISSECTING → NORMALIZING →
   │          COMPLETED | EMPTY | PARTIAL | FAILED)
   │          ⚠ run status describes the ANALYSIS, never the SECURITY
   ▼
tshark -T ek  (streaming, stderr to temp file to avoid pipe deadlock)
   │  IMPLEMENTED
   ▼
FrameEvidence[]   capture_id · frame · tcp_stream · ISO timestamp · TLS · mail · protocol stack
   │  IMPLEMENTED
   ▼
StreamGroup[]     grouped on tshark's tcp.stream; roles from observed greeting, not port order
   │  IMPLEMENTED
   ▼
SessionEvidence[] app_state · tls_state · starttls_{advertised,requested,accepted} ·
   │              tls_negotiated_version · transitions[] · events[] · completeness
   │  IMPLEMENTED
   ├──────────────────────────────┐
   ▼                              ▼
SecurityFinding[]            CrossSessionFinding[]
   status/severity/            deviation + baseline +
   evidence_refs               contrast provenance
   IMPLEMENTED                 IMPLEMENTED
   │                              │
   └──────────────┬───────────────┘
                  ▼
        ML features / anomaly score      PLANNED (Phase 6)
                  ▼
        Posture score + prioritisation   PLANNED (Phase 8)
                  ▼
        JSON / HTML / PDF reports        PLANNED (Phase 9)
```

---

## 11. The evidence model

**This is the heart of the project.** `docs/architecture/04-evidence-provenance.md` is the contract.

### `EvidenceField`

Every non-structural fact is not a bare value but a frozen wrapper:

```python
EvidenceField(
    value,        # the fact, or None
    state,        # how well the capture supports it
    basis,        # WHY it holds that state (human + machine readable)
    provenance,   # observed | inherited | historical | retrieved | decrypted
    frames,       # supporting frame numbers
)
```

Construction goes through intent-revealing factories (`observed`, `inferred`, `unknown`,
`ambiguous`, `incomplete`, `not_observable`) that **validate their own invariants**: OBSERVED must
carry a value; UNKNOWN/INCOMPLETE/NOT_OBSERVABLE must **not**; INFERRED must record a basis.

The safe read path is `.value_or(default)`, which **refuses to return a value for non-conclusive
states**.

### The six states

| State | Meaning | Example |
|---|---|---|
| **OBSERVED** | Directly present in captured bytes | `250-STARTTLS` in the reassembled stream |
| **INFERRED** | Deduced from observed facts; basis recorded | client sent STARTTLS ⇒ it was advertised |
| **UNKNOWN** | Insufficient evidence to decide | no server bytes captured |
| **AMBIGUOUS** | Evidence supports more than one reading | advertisement absent: stripped **or** unsupported |
| **INCOMPLETE** | Capture truncated at the relevant point | capture ends mid-handshake |
| **NOT_OBSERVABLE** | Structurally impossible passively | TLS 1.3 certificate |

### Forbidden semantic conversions

```
UNKNOWN         → FALSE               FORBIDDEN
UNKNOWN         → SECURE              FORBIDDEN
NOT_OBSERVABLE  → FALSE / FAIL        FORBIDDEN
INFERRED        → OBSERVED            FORBIDDEN
AMBIGUOUS       → ATTACK              FORBIDDEN
INCOMPLETE      → NORMAL              FORBIDDEN
PLAINTEXT       → CREDENTIAL THEFT    FORBIDDEN
NO STARTTLS     → STRIPPING           FORBIDDEN
```

These are enforced three ways: the frozen dataclass has no setter; the factories validate; and
tests assert them directly (`test_evidence_states.py`, plus forbidden-semantics tests in Phases 4
and 5).

### Three orthogonal axes (Phase 4+)

Collapsing these is how a forensic tool starts lying, so they are separate fields:

| Axis | Meaning |
|---|---|
| **Severity** | impact **if** the condition holds |
| **Evidence state** | how well the capture supports it |
| **FindingStatus** | the analytic outcome: OBSERVED_ISSUE · COMPLIANT · INFORMATIONAL · AMBIGUOUS · INSUFFICIENT_EVIDENCE · NOT_OBSERVABLE |

**Enforced at construction:** only `OBSERVED_ISSUE` may carry severity above INFO, and it must cite
a standards basis. Violations raise a `ValueError`.

---

## 12. Threat model

Full document: `docs/architecture/06-threat-model.md`.

**Governing principle:** *everything derived from the PCAP is untrusted data.* The capture may have
been produced by an attacker — it contains attacker-controlled SMTP/IMAP/POP3 content.

| Threat | Defence | Status |
|---|---|---|
| Malformed / corrupted PCAP | tshark handles; typed `MALFORMED` status; fuzz-tested | ✅ Implemented |
| Huge PCAP | streaming `-T ek`, size ceiling, frame ceiling → `PARTIAL` not silent truncation | ✅ Implemented |
| Truncated capture | `INCOMPLETE` / `NOT_OBSERVABLE`, never a finding — all 5 cut points abstain | ✅ Implemented + tested |
| Shell injection via filename | argument-array subprocess, never `shell=True` | ✅ Implemented + tested |
| Subprocess hang | timeout + kill | ✅ Implemented |
| stderr pipe deadlock | stderr to temp file | ✅ Fixed (see §15) |
| Hostile text in protocol payload | treated as data; conclusions are rule-authored constants | ✅ Implemented + tested |
| **Prompt injection** | Demonstrated contained: verdict computed from structural facts; injected DATA body cannot reach it | ✅ Demonstrated (`X_prompt_injection.pcap`) |
| Poisoned history | one outlier makes history inconsistent ⇒ no expectation derived | ✅ Implemented + tested |
| Broken rule | fails closed — error recorded, **no finding emitted** | ✅ Implemented + tested |
| Analyst overtrust | coverage-aware posture; limitations on every finding | 🟡 Partial — posture layer is Phase 8 |
| Stored XSS in reports | context-aware escaping | 🔴 Phase 9 |
| ML model poisoning / drift | unsupervised, generator-held-out eval | 🔴 Phase 6 |

---

## 13. Testing architecture

`CONFIRMED` — **159 tests, all passing**, verified 2026-09-18.

| File | Tests | Layer |
|---|---|---|
| `test_evidence_states.py` | 8 | Unit — evidence contract |
| `test_capture_hash.py` | 6 | Unit — hashing / capture metadata |
| `test_tshark_adapter.py` | 9 | Unit + security — subprocess boundary |
| `test_ingest_pipeline.py` | 22 | Integration — Phase 2 matrix |
| `test_integration_pcap_to_evidence.py` | 6 | Golden regression |
| `test_session_reconstruction.py` | 25 | Phase 3 + invariants |
| `test_security_analysis.py` | 26 | Phase 4 + forbidden semantics |
| `test_security_analysis_adversarial.py` | 12 | Phase 4 adversarial |
| `test_cross_session.py` | 32 | Phase 5 + safety semantics |
| `test_cross_session_adversarial.py` | 13 | Phase 5 adversarial + scaling |
| **Total** | **159** | |

### Major security invariants asserted by tests

- No forbidden evidence-state conversion ever occurs.
- Truncated/incomplete captures never produce a SUSPECT or insecure finding.
- `TLS_ESTABLISHED` requires sufficient evidence; a ClientHello is never success.
- Implicit TLS never yields a STARTTLS transition or failure.
- Retransmission never duplicates an application event.
- **`B_strip_advert` and `I_no_support` produce identical output** at Phase 3 *and* Phase 4.
- No attacker attribution, no "stripped", no "credential theft" anywhere in output.
- Same PCAP + same versions ⇒ identical output (byte-level JSON equality).
- Cross-session analysis is order-independent (reversed and rotated populations agree).
- Cross-session analysis scales **linearly**, guarded by a regression test.
- No Phase-4 vocabulary in Phase-3 output; no ML imports in the Phase-4/5 lanes (AST-checked).

---

## 14. Golden corpus

`CONFIRMED` **`tests/golden/manifest.json`, schema v2.0, 20 captures** with SHA-256, scenario ID,
protocol, purpose, provenance and expected structural observations. 25 `.pcap` files exist on disk;
**5 are used by tests but are not in the manifest** — see [§16](#16-current-limitations).

Generated deterministically by `research/experiments/oq28/craft.py`.

### The MAC-address lesson — an important engineering story

`EXPERIMENTALLY VALIDATED` During Phase 4 the golden-hash guard failed unexpectedly. Investigation
(byte-diffing an old and new capture) traced the difference to **Ethernet source MAC bytes 6–11**.

**Root cause:** `craft.py` used a bare `Ether()`. Scapy fills the source MAC from the **host's
network interface** — so generated captures differed per machine and per session. The Phase-3
hashes had only matched because regeneration happened on the same host minutes later.

**Impact:** the golden corpus — an *integrity control* — was never actually reproducible off this
machine. The control was unsound.

**Fix:** MACs pinned (`02:00:00:00:00:01` / `02:00:00:00:00:02`); determinism verified by
regenerating twice and comparing all hashes (0 differences across 25 captures); manifest
re-baselined to **v2.0** with the reason recorded in the manifest itself.

**Why Phase-3 output stayed byte-identical:** only link-layer addressing changed, not protocol
semantics — verified by re-running reconstruction across the corpus and comparing results.

**The lesson:** the hash guard did its job. A corpus that cannot be regenerated identically is not
an integrity control, it is a coincidence.

---

## 15. Security review history — defects found and fixed

Seven real defects, each found by deliberate review rather than by a failing feature.

| # | Defect | Root cause | Impact | Fix | Validation |
|---|---|---|---|---|---|
| 1 | **stderr PIPE deadlock** | Streaming path used `stderr=PIPE` and never drained it | A capture emitting large stderr could deadlock the child process | stderr redirected to a temp file | Full suite green; streaming path exercised |
| 2 | **Contradictory STARTTLS responses** | `_acceptance_evidence` checked `accepted` first, so accept+reject silently preferred acceptance | Fabricated certainty from contradictory evidence | Returns `AMBIGUOUS` citing both frame sets | Adversarial probe + test |
| 3 | **POP3 CAPA body invisible** | tshark's POP dissector reports `pop_response_data` as `['','','','']` — line *count* but not *content* | STLS advertisement undetectable ⇒ wrong `AMBIGUOUS` on legitimate POP3 | Bounded `tcp.payload` decoder, used only for cleartext mail frames | `P_pop3_*` captures now resolve correctly |
| 4 | **Golden corpus non-reproducible** | Bare `Ether()` inherited host NIC MAC | Integrity control was unsound off-machine | MACs pinned; manifest v2.0 | Regenerated twice, 0 hash differences |
| 5 | **TLS evidence contradiction** | `SEC-TLS-002` claimed COMPLIANT when `tls_state` said ESTABLISHED but transition evidence disagreed | Confident claim on unconfirmed evidence | Fails closed as `AMBIGUOUS` | Adversarial test |
| 6 | **Server-scoped cross-session baseline** | First Phase-5 design keyed baselines on server only, pooling victim *and* control sessions | Mixed baseline **suppressed the decisive contrast** — the entire point of Phase 5 | Client-scoped baseline + cross-client contrast (ADR-0014) | OQ-25 control/no-control result reproduced |
| 7 | **O(n²) cross-session performance** | Full-population rescan per subject; `stream_key` is a string-formatting property | 99.2 s at n=16,000; unusable at scale | `PopulationIndex`, window-before-filter slicing, single-client early exit | **~0.115 ms/session flat, 2k→16k. 52× speedup.** Scaling regression test added |

### Two process lessons worth keeping

- **Defect 7 was found by profiling after two wrong guesses.** Guessing at performance twice cost
  more than profiling once would have.
- **Defect 6 was found by a smoke test, not a unit test.** The unit tests all passed; the design was
  wrong. End-to-end sanity checks on real captures catch design errors that unit tests cannot.

---

## 16. Current limitations

Stated bluntly. Hiding these would undermine the project's central claim.

### Technical
- **No certificate validation.** `SEC-TLS-003` reports `NOT_OBSERVABLE`. We do not perform PKIX
  validation and do not pretend to.
- **No EMS (RFC 7627) or renegotiation (RFC 5746) rules.** tshark can dissect these; our contract
  does not carry them and the corpus does not contain them.
- **No cipher-strength grading.** The value is observed, but no validated IANA strength table exists.
- **No posture score, no reports, no dashboard, no ML.** Phases 6–10.

### Evidence
- **Blind stripping.** Consistently-stripped and consistently-legitimate plaintext are
  indistinguishable without an unaffected control. Permanent boundary.
- **NAT / shared identity** collapses distinct clients into one key (OQ-29, unsolved).
- **TLS 1.3 and resumed sessions** hide the certificate — unfixable passively.

### Dataset — the largest single gap
- **The entire corpus is synthetic and single-vendor.** Dialogue strings are modelled on
  Postfix/Dovecot but were written by us. **No real mail-server traffic has ever been analysed.**
  Tracked as **OQ-33r**.
- 5 of 25 on-disk captures are **not hash-guarded** in the manifest: `F_shared_identity`,
  `G_control_endpoint`, `H_no_control`, `I_no_support`, `X_prompt_injection`. They are used by tests
  but a silent change would not be caught. **Worth fixing.**
- **The live striptls proxy was never executed** — only its mangling functions.

### Deployment
- Requires **tshark** (GPL-2, invoked as subprocess). Version drift could change field names,
  mitigated by `fields.py` isolation + golden regression.
- Packaged as a library only. No CLI, no API, no installer yet.
- `pip install -e .` proved flaky on the system's old pip; tests run via `PYTHONPATH=src`.

### SIH requirement gaps
See [§17](#17-sih-requirements-traceability). The material gaps are **D-10…D-14 (X.509)** and
**A-02 (ML anomaly detection)**, plus all of A-03/A-04 and R-01…R-05.

---

## 17. SIH requirements traceability

`CONFIRMED` against actual code and tests, not against architecture documents.

### Deterministic extraction

| Req | Description | Implementation | Status | Evidence |
|---|---|---|---|---|
| D-01 | PCAP ingest | `ingest/pipeline.py`, `validate.py` | ✅ | 22 ingest tests |
| D-02 | Protocol ID (SMTP/IMAP/POP3 + implicit TLS) | `dissect/normalize.py`, `session/reconstruct.py` | ✅ | protocol tests, all 3 protocols |
| D-03 | TCP reassembly | tshark (reused) + `session/grouping.py` | ✅ | `K_network_cond` |
| D-04 | STARTTLS detection | `session/protocols.py` | ✅ | A/B/J/P_* regression |
| D-05 | STARTTLS **validation** | `session/protocols.py` + `SEC-STLS-001/002` | ✅ | 4 distinct outcomes tested |
| D-06 | TLS handshake reconstruction | `session/base.py:classify_tls` | ✅ | `C_normal_tls` |
| D-07 | TLS version | `session/base.py:negotiated_version` | ✅ | T_TLS10/11/12 |
| D-08 | Cipher suite | `session/base.py:negotiated_cipher` | ✅ | observed `0x1301` |
| D-09 | Key exchange | `dissect/normalize.py` (named group / suite) | 🟡 | captured as evidence; no dedicated rule |
| **D-10** | X.509 extraction | — | 🔴 | `SEC-TLS-003` = NOT_OBSERVABLE |
| **D-11** | Chain validation | — | 🔴 | not implemented |
| **D-12** | Certificate expiry | — | 🔴 | not implemented |
| **D-13** | Public key / length | — | 🔴 | not implemented |
| **D-14** | Signature algorithm | — | 🔴 | not implemented |
| D-15 | Weak / deprecated crypto | `SEC-TLS-001` (RFC 8996 + NIST SP 800-52r2) | ✅ | T_TLS10/11/12 |
| D-16 | Insecure configuration | `SEC-PLAIN-001/002`, `SEC-STLS-*` | 🟡 | bounded subset only |
| D-17 | Forward Secrecy | — | 🔴 | derivable from evidence; no rule yet |
| D-18 | Cryptographic feature extraction | `crosssession/baseline.py:_feature_values` | 🟡 | 5 features; ML features are Phase 6 |

### AI / ML

| Req | Description | Implementation | Status | Evidence |
|---|---|---|---|---|
| A-01 | Risk classification | 8 deterministic standards-bound rules | ✅ | 38 Phase-4 tests |
| **A-02** | **AI-assisted anomaly detection** | Deterministic cross-session deviation (Phase 5) | 🟡 | 45 Phase-5 tests. **No ML model exists.** See note |
| A-03 | Posture scoring | — | 🔴 | Phase 8 |
| A-04 | Threat prioritisation | — | 🔴 | Phase 8 |
| A-05 | Mitigation recommendation | `remediation` field on findings | 🟡 | per-rule text; no engine |

> ⚠️ **A-02 is the most important honest gap.** The PS explicitly requires *"Application of AI/ML
> techniques"* and *"AI-assisted anomaly detection"*. Phase 5 delivers **deterministic** deviation
> detection. That is a defensible *interpretation* (the PS never prescribes a trained model), but it
> is an interpretation, not PS text — tracked as **OQ-35**. **Phase 6 must ship a real ML component.**

### Outputs

| Req | Description | Status |
|---|---|---|
| R-01 | Prioritised findings | 🔴 findings exist; no prioritisation (Phase 8) |
| R-02 | Posture assessment | 🔴 Phase 8 |
| R-03 | JSON / PDF / HTML export | 🟡 every object has `to_dict()`; no renderers (Phase 9) |
| R-04 | Interactive dashboard | 🔴 Phase 10 |
| R-05 | Forensic reports | 🟡 provenance + versions carried end-to-end; no report artefact |

**Summary: 9 ✅ · 7 🟡 · 12 🔴 of 28 requirements.**

---

## 18. What is left to build

### Phase 6 — the real ML anomaly lane (highest priority)

Design in `docs/architecture/05-ai-anomaly-design.md`; decision in ADR-0006.

- **Features:** **cross-session deviation features**, not raw per-session values. This is the key
  design choice — naive per-session ML already failed.
- **Candidates:** Isolation Forest, LOF, One-Class SVM, robust-statistical (Mahalanobis/MAD),
  temporal drift. **Autoencoder deprioritised** on data grounds.
- **Anti-circularity — non-negotiable:** must be **unsupervised**. Do **not** train a classifier on
  labels produced by our own rules engine; that is the exact trap all three audited competitors fell
  into.
- **Generator-held-out evaluation:** split train/test by **generator and scenario**, never randomly.
  A model that only works when train and test share a generator is rejected.
- **Selection metric:** *does the model flag genuine issues the deterministic engine missed, without
  raising more false positives than it removes?* Report TP/FP/FN/TN, precision, recall, F1, FPR,
  **PR-AUC** (not accuracy — imbalanced), seed stability across ≥5 seeds.
- **Honest failure path:** if no model adds detections, ship the best stable one as a **secondary
  prioritisation signal** and document the limitation. Escalate rather than ship a bad model.

> ⛔ **Do not assume Isolation Forest is the answer.** It was already tested and lost to the
> deterministic baseline (2/32 vs 8/32 attacks, more FPs).

### Phase 7 — ML integration
Separate lane; `anomaly_score` / `band` / `feature_contributions` / `model_version` only.
`--no-ai` flag producing **identical security findings** (diff test).

### Phase 8 — posture / risk
Evidence fusion, **coverage-aware** posture ("assessed 13 of 18 properties; 5 NOT_OBSERVABLE"),
deterministic prioritisation, explicit ML-influence policy.

### Phase 9 — reporting
One canonical report object → JSON (direct), HTML (template), PDF (offline renderer). All
PCAP-derived text escaped. **Never three separate engines** (ADR-0009).

### Phase 10 — dashboard
Overview · session explorer · finding detail · infrastructure view · anomaly view. Static SPA served
by the backend (ADR-0010). Every visualization must support an analyst decision.

---

## 19. Final demo story

Design in `docs/architecture/08-demo-architecture.md`. **All scenes are `PLANNED`** — no demo
currently runs end-to-end.

| Scene | Story | Depends on |
|---|---|---|
| **1 — Normal secure session** | `C_normal_tls`: STARTTLS → TLS 1.3, reported COMPLIANT | ✅ works today at API level |
| **2 — Legitimate decline** | `A_legit_decline`: advertised, client declines. Naive rule says CRITICAL; we say INFORMATIONAL | ✅ works today |
| **3 — Ambiguous absence** | `B_strip_advert` vs `I_no_support` side by side, identical output. **The honesty scene** | ✅ works today |
| **4 — Cross-session contrast** | `G_control_endpoint` vs `H_no_control`: control present → SUSPICIOUS_DEVIATION; absent → abstains | ✅ works today |
| **5 — ML anomaly** | Anomaly lane surfaces what rules missed | 🔴 Phase 6 |
| **6 — Forensic report** | JSON/HTML/PDF export with frame-level provenance | 🔴 Phase 9 |

**Three scenes that win or lose it:** the **inversion** (scene 2+3 — competitors flag the benign
case and miss the attack), the **honesty** scene (TLS 1.3 / truncation → `NOT_OBSERVABLE` with
coverage), and the **`--no-ai` equivalence** proof.

**Demo rules:** fully offline, deterministic corpus, precomputed fallback for every capture, **never
live internet traffic**.

---

## 20. Information available for the SIH pitch deck

> **Read the AVAILABLE NOW / AFTER FUTURE PHASES split carefully. Do not present planned work as
> delivered.**

### Slide 1 — Problem
**AVAILABLE NOW:**
- The PS's own framing: existing tools give packet-level visibility but *"do not automatically
  evaluate the overall cryptographic security posture"*.
- The human problem: posture assessment is **expertise-gated**. An analyst must hold RFC-level TLS
  and X.509 knowledge and apply it manually across thousands of sessions.
- Consequence: it effectively does not happen, so obsolete TLS, weak ciphers and broken certificates
  persist unnoticed.

### Slide 2 — Existing gap
**AVAILABLE NOW — all source-verified, all citable:**
- Zeek: no `imap.log`, **no `pop3.log`**; SMTP STARTTLS output is one boolean.
- Zeek's `weak-keys.zeek` default `tls_minimum_version = TLSv10` — TLS 1.0/1.1 raise **no notice**,
  contradicting RFC 8996.
- Suricata: no POP3 parser; `TLS_REJECTED` **structurally cannot fire** on capability stripping.
- ET Open: 43 email rules, **zero** STARTTLS references. Snort 3: 4,017 rules, **zero**.
- Arkime observes the downgrade condition and **silently normalises it** into successful parsing.
- **All 285 Zeek packages** enumerated: zero relevant.

### Slide 3 — Innovation
**AVAILABLE NOW:**
- Evidence-first architecture: six evidence states; forbidden conversions structurally blocked.
- **Cross-session reasoning** — verified absent from all five competitor codebases.
- Two-lane architecture with a hard AI boundary.
- Frame-level forensic provenance on every finding.

⚠️ **Honesty requirement:** claim **integration and correctness**, *not* novelty. STARTTLS detection
is published research (2002–2025) and four competitors ship it.

### Slide 4 — How it works
**AVAILABLE NOW:** PCAP → validation + SHA-256 → tshark → normalization → session reconstruction
(3 protocols + implicit TLS) → deterministic standards-bound rules → cross-session baselines and
control contrast.
**AFTER FUTURE PHASES:** ML lane → posture → reports → dashboard.

### Slide 5 — Technical / AI / Impact
**AVAILABLE NOW:**
- 34 modules, 159 tests, 11 rules (8 deterministic + 3 cross-session).
- Standards-bound: RFC 8996, NIST SP 800-52r2, RFC 3207, RFC 2595, RFC 8446, RFC 8314.
- **Linear scaling: ~0.115 ms/session, flat from 2,000 to 16,000 sessions.**
- Offline-capable; zero runtime dependencies in the core.

**AFTER FUTURE PHASES:** the ML anomaly lane. ⚠️ **Do not claim ML results.** What *can* be said
today: *"we tested a naive model, it lost to the deterministic engine, so Phase 6 selects one
empirically rather than for appearance."* That is a credibility asset, not a weakness.

### Slide 6 — Results / Deployment / Future
**AVAILABLE NOW — real measured numbers:**
- Cross-session reasoning: **−71 % false positives** (session model), **−72 %** (real packets).
- Control endpoint: **FN 30 → 0** (session), **FN 6 → 0** (packet level).
- **The per-session detector is inverted**: CRITICAL on 25/25 benign, blind to 30/30 attacks.
- Byte-identity proof that attack and legitimate config are indistinguishable.
- Performance: 99.2 s → 1.9 s at n=16,000 (52×).

⚠️ **State these as corpus-relative, not population rates.** The corpus is synthetic and
single-vendor.

**Strongest scientific message for the deck:**
> *Passive PCAP cannot always distinguish a legitimate plaintext configuration from a stripped one.
> We proved it byte-for-byte, and we built a system that says so instead of guessing.*

---

## 21. Team contribution guide

### ML team (Phase 6) — the critical path
**You get:** `SessionEvidence` + `CrossSessionFinding` + `Baseline.features` (5 security-relevant
features already computed per population) + a 20-capture golden corpus + a working deterministic
baseline to beat.
**You must:** build a **diversity-controlled** corpus (≥2 generators — this needs OQ-33r), run the
bake-off, split held-out **by generator**, report honest metrics including PR-AUC and seed
stability.
**Read first:** `05-ai-anomaly-design.md`, `10B-ai-architecture-decision.md`, ADR-0006.
**Hard rule:** unsupervised only. Never train on our own rule labels.

### Backend team (Phases 8–9)
**You get:** `analyze_capture()`, `SecurityAnalysisEngine`, `CrossSessionEngine`, and `to_dict()` on
every object — the serialisation contract already exists.
**You must:** build the posture/risk layer and the canonical report object → 3 renderers.
**Read first:** ADR-0007 (SQLite), ADR-0009 (reporting), ADR-0011 (FastAPI monolith).

### Frontend team (Phase 10)
**You get:** stable JSON from `AnalysisReport.to_dict()` and `CrossSessionReport.to_dict()`.
**You must:** the five views in ADR-0010. **Do not** build visualizations that do not support an
analyst decision. Every finding already carries frames — surface them.

### Security / research team
**Highest-value open work:** **OQ-33r** — real Postfix/Dovecot traffic. It gates the ML corpus,
X.509 work, and every generalisation claim. Also: OQ-29 (NAT identity), OQ-34 (TLS 1.3 + implicit
TLS at packet level), and the certificate rules (D-10…D-14).

### Testing team
**Gaps:** 5 unmanifested captures; no real-traffic regression; no end-to-end CLI test; Phase 8–10
have no tests because they do not exist.
**Read first:** `07-test-architecture.md`.

### Documentation / pitch team
Everything you need is in [§20](#20-information-available-for-the-sih-pitch-deck) and
`docs/research/`. **Preserve the AVAILABLE NOW / FUTURE split.** The honest limitations are a
credibility asset with an NTRO audience — do not sand them off.

---

## 22. Developer rules

1. **Do not reimplement TCP.** tshark did reassembly; consume it.
2. **Do not duplicate tshark parsing.** All field names live in `dissect/fields.py`.
3. **Preserve evidence states.** Never collapse six states into a boolean.
4. **Never turn absence into attack.** `NO STARTTLS ≠ STRIPPED`.
5. **Preserve provenance.** Every finding cites frames, not "the session".
6. **Do not modify the golden corpus casually.** A change needs a new hash, new manifest version and
   a documented reason.
7. **Never rewrite Git history. Never force-push.**
8. **Do not add ML for SIH optics.** It must earn its place empirically.
9. **Do not claim unsupported requirements.** Mark 🔴 honestly.
10. **Prefer abstention to fabricated certainty.**
11. **Research the standard before writing a security rule.** Every severity cites an authority.
12. **Keep the deterministic and ML lanes separate.** ML never writes a finding.
13. **Competitor READMEs are marketing.** Only source counts.
14. **Profile before optimising.** Two guesses cost more than one profile.

---

## 23. Setup and commands

`CONFIRMED` against `pyproject.toml` and actual usage.

### Prerequisites
- **Python ≥ 3.9** (developed on 3.9.6)
- **tshark ≥ 4.x** (developed and validated on **4.6.8**) — `brew install wireshark` / `apt install tshark`
- Core has **zero runtime dependencies** (stdlib only). Dev needs `pytest`.
- Experiment scripts additionally use `scapy` (corpus generation) and `scikit-learn` (the OQ-21 ML test).

### Install and run

```bash
# dev dependencies
pip3 install --user pytest

# run the full suite (159 tests)
PYTHONPATH=src python3 -m pytest -q

# run one phase
PYTHONPATH=src python3 -m pytest tests/test_cross_session.py -q
```

> `pip install -e .` proved unreliable with the system's older pip; `PYTHONPATH=src` is the
> supported path today. Packaging is unfinished.

### Analyse a capture (library API — there is no CLI yet)

```python
from securemailscope.ingest import analyze_capture
from securemailscope.session import reconstruct_sessions
from securemailscope.analysis import SecurityAnalysisEngine
from securemailscope.crosssession import CrossSessionEngine

run, frames = analyze_capture("path/to/capture.pcap")
sessions    = reconstruct_sessions(frames, run.capture.capture_id)
findings    = SecurityAnalysisEngine().analyse(sessions, run.capture.capture_id)
deviations  = CrossSessionEngine().analyse(sessions, run.capture.capture_id)

print(findings.to_dict())
print(deviations.to_dict())
```

### Experiment scripts

```bash
# regenerate the golden corpus (deterministic; verify hashes afterwards)
python3 research/experiments/oq28/craft.py

# OQ-25 cross-session experiment
python3 research/experiments/oq25/run.py
python3 research/experiments/oq25/run2.py
python3 research/experiments/oq25/run3.py

# OQ-33: fetch striptls (GPLv2 — not vendored) then run the validation
python3 research/experiments/oq28/fetch_striptls.py
PYTHONPATH=src python3 research/experiments/oq28/oq33_striptls.py

# OQ-21 ML test (requires scikit-learn)
PYTHONPATH=src python3 research/experiments/oq28/oq21_ml_test.py
```

---

## 24. Glossary

| Term | Meaning |
|---|---|
| **PCAP / PCAPNG** | Packet capture file formats. The only input this system accepts |
| **tshark** | Wireshark's CLI. Does our dissection and TCP reassembly (GPL-2, subprocess) |
| **TCP stream** | One bidirectional connection. Identified here as `capture_id:tcp_stream` |
| **STARTTLS** | SMTP/IMAP extension upgrading a cleartext connection to TLS (RFC 3207, RFC 2595) |
| **STLS** | The POP3 equivalent of STARTTLS |
| **SMTPS / IMAPS / POP3S** | **Implicit TLS** on ports 465/993/995 — encrypted from the first byte, no upgrade dialogue |
| **Implicit vs explicit TLS** | Implicit starts inside TLS; explicit upgrades mid-session. **Never conflate them** |
| **Stripping** | Active removal of the STARTTLS capability in transit, forcing cleartext |
| **FrameEvidence** | Phase-2 per-packet normalized observation |
| **SessionEvidence** | Phase-3 reconstructed session — the stable contract for Phases 4–5 |
| **EvidenceField** | Value + state + basis + provenance + frames. The correctness backbone |
| **SecurityFinding** | Phase-4 per-session conclusion with severity, status and evidence refs |
| **CrossSessionFinding** | Phase-5 comparison conclusion with baseline and contrast provenance |
| **Baseline** | Behaviour of *prior comparable* sessions for one client→server population |
| **Contrast** | Comparison against sessions from a *different client* to the same server |
| **Comparability** | Explicit decision about whether two sessions may be compared at all |
| **Abstention** | Returning INSUFFICIENT/NOT_ASSESSED instead of guessing. A feature |
| **Ambiguity** | Evidence supports more than one reading. Preserved, never resolved by fiat |
| **Provenance** | The chain from a finding back to specific frames and a capture hash |
| **TLS 1.2 / 1.3** | `0x0303` / `0x0304`. In 1.3 everything after ServerHello is encrypted |
| **SNI** | Server Name Indication — cleartext hostname in the ClientHello (unless ECH) |
| **X.509** | Certificate format. **Not validated by this system today** |
| **EMS** | Extended Master Secret (RFC 7627). **Not implemented** — evidence unavailable |
| **ML anomaly detection** | Statistical outlier detection vs learned normal. **Phase 6, not built** |
| **Posture assessment** | Overall security state + how much of it was observable. **Phase 8** |

---

## 25. References

Full provenance with retrieval dates in `docs/research/SOURCES.md` (33 sources, S-01…S-33). No
citation was added without being retrieved and read.

### Official SIH
- SIH 2026 portal, PS SIH26159 — `https://sih.gov.in/sih2026PS` (retrieved 2026-09-16; raw HTML
  saved as evidence)
- Community mirror dataset (corroborating) — `NoBugNinja/Smart-India-Hackathon-SIH-2026-Problem-Statements`

### RFCs / Standards
- **RFC 8446** — TLS 1.3 (Aug 2018). §2: *"All handshake messages after the ServerHello are now
  encrypted."* §2.2: PSK handshakes send no Certificate
- **RFC 8996 / BCP 195** — Deprecating TLS 1.0 and 1.1 (Mar 2021). §4–5: *"MUST NOT be used"*
- **RFC 3207** — SMTP STARTTLS (Feb 2002). §6: *"A man-in-the-middle attack can be launched by
  deleting the '250 STARTTLS' response"*
- **RFC 2595** — STARTTLS for IMAP/POP3
- **RFC 8314** — Cleartext considered obsolete; implicit TLS for submission/access
- RFC 7627 (EMS), RFC 5746 (renegotiation) — cited but **deliberately not implemented**

### NIST
- **NIST SP 800-52r2** (Aug 2019, **current, not superseded**) §3.1: *"Servers shall be configured
  to use TLS 1.2 and should be configured to use TLS 1.3 as well. These servers should not be
  configured to use TLS 1.1 and shall not use TLS 1.0, SSL 3.0, or SSL 2.0."*

### Academic
- **Poddebniak, Ising, Böck, Schinzel** — *Why TLS is better without STARTTLS*, USENIX Security 2021
- **Durumeric et al.** — *Neither Snow Nor Rain Nor MITM*, ACM IMC 2015 ⚠️ figures cited from a
  search summary; **read the PDF before quoting them**
- **NDSS 2025** — *A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems*
  ⚠️ summary only
- **Holz, Amann et al.** — *TLS in the wild* (2015) ⚠️ summary only
- **Delgado** — *Observability for Post-Quantum TLS Readiness* (arXiv 2605.02978, May 2026) —
  **the prior art that refuted our evidence-tiering novelty claim**
- **Casey** — Certainty Scale (2002); DECDs

### Tools
- tshark / Wireshark 4.6.8 (GPL-2) · tcpdump 4.99.1 · scapy 2.7.0 · scikit-learn 1.6.1
- `tintinweb/striptls` v0.5 (**GPLv2 — deliberately not vendored**)
- Zeek, Suricata, Snort 3, Arkime, NetworkMiner — audited as prior art

### Competitor / prior-art research
Five SIH26159 repositories audited at source level — see `01D` and `SOURCES.md` S-27.
**Treated as competitor interpretations, never as requirements.**

---

## 26. Source conflicts and their resolution

Per the source-of-truth hierarchy, conflicts are documented rather than silently resolved.

### Conflict 1 — Submission deadline

| Source | Value | Rank |
|---|---|---|
| `docs/research/19-authoritative-ps-verification.md` (live official portal) | **30 September 2026** | 1 |
| `docs/research/evidence/SIH26159-official-ps.json` (community mirror, scraped 2026-08-22) | 20 September 2026 | 2 |

**Resolution: 30 September 2026.** The live portal is authoritative and its footer read verbatim
`SIH26159 1/500 Blockchain & Cybersecurity 30 September 2026 30-09-2026`. The mirror's value was
stale or wrong; doc 19 records the refutation. The mirror file is **deliberately left unedited** —
it is immutable evidence of what that source said when read.

⚠️ **Open, team-owned:** the **college SPOC's internal cutoff** may precede the national date.
Unverified; cannot be resolved by research.

### Conflict 2 — Phase numbering

The handover brief calls Phase 1 "research + architecture"; the repository's `v0.1.0-phase1` tag
marks **foundation code**, with research (`f6cd544`) and architecture (`470b430`) as preceding
commits. **Resolution:** [§8](#8-phase-by-phase-status) uses the repository structure, which is
authoritative, and notes the alternative framing.

### Conflict 3 — Golden corpus count

25 `.pcap` files on disk vs **20** in `manifest.json` v2.0. **Resolution:** the manifest is
authoritative for *hash-guarded* captures; the extra 5 are real test fixtures that are **not
hash-protected**. Recorded as a gap in [§16](#16-current-limitations).

### Conflict 4 — A-02 status

`docs/architecture/requirements-traceability.md` marks A-02 partially satisfied by deterministic
cross-session deviation. The PS text says *"Application of AI/ML techniques"*. **Resolution:** 🟡
Partial, with the interpretation flagged explicitly as interpretation (OQ-35), not as PS text.
**Phase 6 must close it.**

---

## Final word for whoever picks this up

The most valuable thing in this repository is not the code — it is the **discipline about what the
evidence does and does not support**. Two sessions that are byte-identical produce identical output,
even when one is an attack. Truncated captures abstain. Absent certificates are `NOT_OBSERVABLE`,
not invalid. A difference is never an attack.

That discipline is what makes the findings defensible to a forensic analyst, and it is the thing
most likely to be eroded by a well-meaning change. If you preserve nothing else, preserve that.

**Open questions are tracked in `docs/research/RESEARCH_STATUS.md` and
`docs/architecture/ARCHITECTURE_STATUS.md`. Start there.**
