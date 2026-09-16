# RESEARCH_STATUS

**Project:** SecureMailScope — SIH26159 (NTRO)
**Last updated:** 2026-09-16
**Mode:** Research complete → **ARCHITECTURE phase (11) complete, awaiting approval.** No product
source code written. Architecture artifacts live in `docs/architecture/`; engineering operating system
in `.claude/`. Implementation has NOT begun.

> **TRANSITION 2026-09-16:** RESEARCH → ARCHITECTURE. Research phases 0–2 + validation/experiment
> passes (01A–01D, 02A–02B, 10A–10B) + requirements gate (doc 19) are complete and frozen. See
> `docs/architecture/ARCHITECTURE_STATUS.md` for the architecture state and the decisions awaiting
> human approval.

---

## 1. Phase status

| Phase | Name | Status | Output |
|---|---|---|---|
| 0 | Project reconnaissance | ✅ **Complete** | doc 01 §1 |
| 1 | Problem statement forensics | ✅ **Complete (v1)** | doc 01 §2–§9, §11 |
| 2 | Define the actual problem | ✅ **Complete (v1)** | doc 01 §10 |
| 3 | Stakeholder analysis | ⬜ Not started | 02-stakeholders.md |
| 4 | Email security domain deep dive | ⬜ Not started | 03, 04 |
| 5 | Existing solution landscape | ⬜ Not started | 05 |
| 6 | Competitive / alternative analysis | ⬜ Not started | 06 |
| 7 | Real user workflow | ⬜ Not started | 07 |
| 8 | Threat model | ⬜ Not started | 08 |
| 9 | Data & evidence model | ⬜ Not started | 09 |
| 10 | AI opportunity analysis | ✅ **Complete** | 10A, 10B |
| 11 | Out-of-the-box innovation (20+ concepts) | ⬜ Not started | 11 |
| 12 | Find the real novelty | ⬜ Not started | 11 |
| 13 | Patent / academic prior art | ⬜ Not started | 12 |
| 14 | Solution space | ⬜ Not started | 13 |
| 15 | SIH prototype reality check | ⬜ Not started | 14 |
| 16 | SIH evaluation lens | ⬜ Not started | 15 |
| 17 | Demo design | ⬜ Not started | 16 |
| 18 | Research gaps | ⬜ Not started | 17 |
| 19 | Master synthesis | ⬜ Not started | 18 |
| 20 | Final recommendation | ⬜ Not started | 18 |

**2 of 20 phases complete** (plus Phase 0). Phases 1 and 2 are marked v1 because both are
conditional on verifying A-01 (see §3).

---

## 2. Important findings so far

### 2.1 🔴 Scope correction — the PS is not what the title suggests

SIH26159 is a **passive PCAP network-forensics problem** over SMTP/IMAP/POP3 TLS traffic. It is
**not** a DNS/domain email-authentication posture problem. SPF, DKIM, DMARC, DANE, MTA-STS, BIMI,
DNSSEC, "domain", "phishing" and "spoof" occur **zero times** in the official text
(mechanically verified — see `SOURCES.md`, *Verified-absence record*).

**Consequence.** The DNS/SPF/DKIM/DMARC research direction in the original tasking brief is
off-target for this PS and, if pursued, would produce a working product that does not answer the
problem statement. Phases 4, 7 and 9 must be re-scoped to TLS/X.509/PCAP before they run.

### 2.2 🟡 Certificate visibility — AMENDED after validation pass (doc 01A)

**Original claim (2.2, v1):** TLS 1.3 encrypts the certificate, so D-10…D-14 are unachievable; this
is our strongest differentiator.

**After validation — facts upheld, framing and strategy corrected:**

- ✅ **Upheld.** TLS 1.3 encrypts everything after ServerHello, including `Certificate`
  (RFC 8446 §2), independently confirmed by Zeek's own docs: *"TLS 1.3 hides these from passive
  observation systems."*
- 🆕 **Wider than stated, for a different reason.** *Every resumed session* omits the `Certificate`
  message at *any* TLS version (RFC 8446 §2.2; TLS 1.2 abbreviated handshake). Mail clients poll and
  resume aggressively, so this may dominate even in pure TLS 1.2 environments.
- ⚠️ **Scale corrected.** Only **5 of 22** PS deliverables are certificate-dependent. The other 17
  are fully achievable passively at every TLS version. v1 gave a 5/22 sub-problem the status of the
  defining problem.
- ⚠️ **"Sees least when target is safest" overstated.** Negotiated version, cipher suite,
  key-exchange group, SNI, resumption status and 0-RTT all remain visible under TLS 1.3.
- 🔴 **Differentiator claim WITHDRAWN.** See 2.6.

### 2.6 🔴 Evidence tiering is prior art — novelty claim withdrawn

The hypothesis "distinguish VERIFIED / INFERRED / NOT OBSERVABLE" is **not novel**:

- **Delgado, arXiv 2605.02978 (4 May 2026)** formalises exactly this for TLS — four evidence
  surfaces, seven planes, typed states `unknown`/`not_applicable`/`ambiguous`/`contradictory`,
  coverage scored by *plane closure*, and correct `unknown` output explicitly rewarded.
- **Casey's Certainty Scale (2002)** established evidence-confidence tiering in digital forensics 24
  years ago; **DECDs** continue it.
- **CVSS Report Confidence** (Confirmed/Reasonable/Unknown) — though ⚠️ **removed in CVSS v4.0**.
- **Qualys confirmed vs. potential** vulnerabilities — shipped commercially for two decades.

**Remaining gap (narrow, honest):** Delgado's work is HTTPS/TLS and post-quantum-specific; it does
**not** cover SMTP/IMAP/POP3 or STARTTLS. Applying it to email transport is *legitimate engineering,
not a research contribution*, and must be described that way.

**Decision:** evidence tiering is now a **correctness requirement** of the system — it prevents
false forensic claims — and is **not** to be presented as innovation.

### 2.8 🟢 OQ-14 RESOLVED — finding 2.7 survives, restated more precisely

**Verdict:** the attacks are **not** detected by stock open-source tooling — but the primitives
mostly exist and are unused. **It is an integration and coverage gap, not a detection-science gap.**
Full audit in [01B](01B-starttls-prior-art.md). Four source-verified sub-findings:

1. **No shipped Zeek script, Suricata event, or ET rule detects STARTTLS stripping.** ET Open's
   SMTP+IMAP+POP3 rulesets are **43 active rules with zero STARTTLS/STLS references**.
2. **Zeek's entire SMTP STARTTLS security output is one boolean** (`tls: bool`); the handler sets it
   and nothing more. Zeek does not track SMTP `AUTH` at all.
3. **IMAP and POP3 are effectively uncovered.** Zeek `imap/main.zeek` is 13 lines (port registration;
   **no `imap.log`**); Zeek has **no `pop3/main.zeek` and no `pop3.log`**. Suricata
   `app-layer-imap.c` is 96 lines of detection patterns only, and Suricata has **no POP3 parser**.
4. **Suricata's `TLS_REJECTED` structurally cannot fire on the actual attack** — it requires the
   client to have *sent* `STARTTLS`, which capability stripping prevents.

**Load-bearing sentence:** Zeek's `tls=F` is produced identically by (a) server never supported
STARTTLS, (b) client declined, (c) attacker stripped it, (d) implicit TLS on 465. **Distinguishing
these four is what no shipped tool does.**

⚠️ **Conceded openly:** a large fraction of SIH26159 — the whole extraction layer (D-01/02/03/06/
07/08/09/10–14) — **is already solved by Zeek and Suricata.** Reimplementing it would be rebuilding
mature infrastructure worse. Also conceded: the attacks are published research (RFC 3207 §6 (2002),
Durumeric 2015, Poddebniak 2021, NDSS 2025) — **we claim no detection novelty**, and a competent
competitor could close much of the gap in about a week.

### 2.11 🔴 OQ-18/19 closed — but the differentiation hypothesis was falsified by competitors

**OQ-18 RESOLVED.** Snort 3 (4,017 community rules): **zero** STARTTLS references; email rules are
legacy exploit signatures. NetworkMiner: strongest email artifact extractor (SMTP/IMAP/POP3 +
implicit-TLS, credentials, X.509) but **no detection, no posture**. Arkime: parses all three
protocols, tags `smtp:starttls`, and — decisively — **silently normalises the cleartext-after-
STARTTLS downgrade condition into successful parsing**, with no tag or finding. `imap.c`/`pop3.c`
contain **zero** TLS logic.

**OQ-19 RESOLVED.** All **285** zkg packages enumerated: **zero** mention starttls, stls, imap,
pop3, downgrade, credential, cipher or posture. Existing TLS packages do fingerprinting/logging;
one exists purely to *suppress* certificate notices.

🔴 **But the hypothesis died anyway.** An unplanned search for complete systems found **~10
competing SIH26159 repositories**, all created in the last three weeks. **`soumyajit-cys/CipherPost`
(65 Python files, pushed 2026-09-15) already implements `rule_starttls_strip`, cited to RFC 3207,
with test fixtures for SMTP *and IMAP* stripping** — the exact capability finding 2.9 claimed as
ours, including the multi-fact STARTTLS state model.

**We were auditing the wrong competitors.** The competition is not Zeek; it is the other teams
answering this PS.

**Calibration finding:** competitor READMEs are unreliable. `fredfe08/SecureMailScope` was credited
with a four-fact STARTTLS model; source inspection found **zero** matches for those terms, and its
`tls-engine/` contains SPF/DKIM/DMARC checkers — i.e. that team made the doc 01 §8 scope error.
**Only source inspection counts.**

### 2.19 ✅ REQUIREMENTS GATE PASSED — A-01 confirmed, deadline resolved (doc 19)

Official portal `sih.gov.in/sih2026PS` retrieved 2026-09-16 (server-rendered this time), saved as
evidence. **A-01 promoted ASSUMPTION → FACT:** the description is token-identical to our mirror (only
`<br>` tags differed); six exact PS phrases verified; SPF/DKIM/DMARC/DNS re-confirmed absent.
**Deadline authoritative: 30 September 2026** (mirror's "20 Sept" refuted). Submitted: 1/500.
**Scope confirmed PASSIVE PCAP ONLY** — auxiliary evidence out of PS scope. **AI/ML explicitly
required** but method-open (no LLM/RAG/trained-model prescribed); our deterministic-A-02 reading is a
defensible interpretation, flagged OQ-35. **No contradiction with phases 0–10.** Only open timeline
item: SPOC internal cutoff.

### 2.18 ✅ PHASE 10 COMPLETE — AI decided (OQ-21 fully resolved)

[10B](10b-ai-architecture-decision.md). Two experiments run on the OQ-28 corpus:

- **Unsupervised ML REJECTED** (`oq21_ml_test.py`): IsolationForest flags 2/32 attacks vs
  deterministic 8/32, with *more* false positives (9 vs 7); inverted test surfaced 7 outliers, all
  truncated/normal captures, **zero attacks**. It duplicates the cross-session baseline and adds
  noise. The honest "report zero" outcome (OQ-27).
- **Prompt injection contained** (`X_prompt_injection.pcap`): attacker-controlled email body cannot
  reach the verdict, which is computed from structural facts. PCAP text = data, never instructions.

**Decision:** AI is **analyst-facing only** — NL query over evidence (primary) + grounded
explanation (optional). No AI in the security path. No ML. LLM optional, offline (local 7–8B), cloud
rejected as a requirement, `--no-ai` build fully functional. All PS A-01…A-05 satisfied; A-02 met by
the deterministic anomaly baseline. Competitor AI: **none changes a core security decision.**

**Thesis:** *SecureMailScope uses AI to let an analyst query and understand deterministically-
established evidence in natural language, while deterministic analysis handles all parsing, TLS
assessment, cross-session reasoning, findings, severity and every verdict.*

### 2.17 ✅ OQ-33 CLOSED — real striptls executed, matches the corpus

[02B §15](02B-packet-level-validation.md). Cloned `tintinweb/striptls` v0.5 (Python 2) and ran its
**actual mangling code** under py3 after a mechanical `except`-only fix (no logic changed).
`Vectors.SMTP.StripFromCapabilities.mangle_server_data` output is **byte-identical** to our
constructed `CAPS_WITHOUT["smtp"]`; POP3 and IMAP strippers confirmed. Generated
`S_striptls_real.pcap` (payload from striptls's own code); tshark and our extractor both read it as
the same evidence signature as the constructed `B_strip_advert`.

**The main §2.3 caveat ("striptls not executed") is removed.** The OQ-28 construction was faithful,
not a convenient simplification. Not executed: the full live-socket proxy (needs a real py2→py3
port) and live bpf capture — neither adds evidential value since the attack-defining logic ran
unmodified. Harness: `research/experiments/oq28/oq33_striptls.py`.

### 2.16 🟡 OQ-28 EXECUTED — packet-level replication CONFIRMS OQ-25

[02B](02B-packet-level-validation.md). 17 real `.pcap` files, 1,113 packets, 111 streams, genuine
TCP reassembly. Corpus independently validated by **tshark's own SMTP and TLS dissectors**.

| Detector | TP | FP | FN |
|---|---|---|---|
| D1 per-session | 2 | **25** | **30** |
| D2 cross-session | 2 | **7** (**−72%**) | 30 |
| D2 + control-endpoint | **8** | 7 | **24** |

**Session model gave −71%; real packets give −72%.** The result is not an artefact of abstraction.
All six success criteria met; no parameter tuned.

🔴 **Byte-identity now PROVEN, not asserted:** `B_strip_advert` (attack) and `I_no_support`
(legitimate) have **identical application payloads** — banner, EHLO, capability response, AUTH line.
Both detectors return the same verdict for both, which is *correct*: identical evidence must yield
identical conclusions.

**Replicated:** the D1 inversion (SUSPECT on 6/6 benign; blind to 6/6 attacks) — now in **SMTP,
IMAP and POP3 with real protocol bytes**, making this a genuine protocol validation where OQ-25's
was a non-result. The control-endpoint win (FN 6→0 with a control, unchanged without). Truncation:
**all 5 cases abstain, zero SUSPECT** — missing packets never become security failures.
Retransmission, reordering, segmentation and loss all survived reassembly.

**Also found:** tshark recovers the same raw facts we do — the gap is *judgement*, not extraction,
which argues for reusing it (OQ-20). Two implementation gaps identified: OQ-31 (client-command
inference — free evidence we don't take) and OQ-32 (completeness check overrides positive TLS
evidence).

**H7: PARTIALLY VERIFIED — confirmed, not upgraded.** Failure modes are structural.

### 2.15 🟡 OQ-25 EXECUTED — RESULT B, partially verified

[02A](02A-cross-session-baseline-experiment.md). Deterministic seeded experiment, 9 scenarios,
260 sessions, no ML. Code in `research/experiments/oq25/`.

| Detector | FP | FN |
|---|---|---|
| D1 per-session (competitor-style) | **120** | **70** |
| D2 consistency rule only | **35** (**−71%**) | 70 (unchanged) |
| D2 + server-contrast rule | 75 (−38%) | **35** (**−50%**) |

**Two mechanisms that trade against each other.** No configuration achieved both gains.

🔴 **Headline: the per-session detector is *inverted*.** It raises CRITICAL on **25 of 25 benign**
sessions (legitimate decline), and misses **30 of 30 genuine attack** sessions (advertisement
stripping) — because stripping removes the advertisement the rule keys on. This applies to
CipherPost's shipped `rule_starttls_strip` as written.

**Two unresolved failures:** (1) attacker strips 100% of sessions with no control endpoint → FN=30/30
for both detectors, unresolvable from capture alone; (2) NAT/shared identity → FP=20, no improvement.
Also: the contrast rule *actively hurts* on legitimately heterogeneous client populations (FP 0→20).

**Confirmed:** history threshold ≈ **5 sessions**, below which D2 abstains honestly; **time-aware
baselines strictly beat capture-wide pooling** (FP 20→0 on legitimate config change); the
**infrastructure framing survives** — produces genuinely different information, not reformatting.
Protocol differences: **untested, not a finding** (generator models none).

**Thesis revised** — the old claim ("distinguishes attack from configuration") is **not supported**.
See 02A §11 for the version backed by numbers.

### 2.13 🔴 Competitor source audit — 3 of 4 surviving differentiators lost

Source-level inspection of five competitor repos ([01D](01D-sih-competitor-source-audit.md)):

| 01C differentiator | Outcome |
|---|---|
| Evidence-observability discipline | ❌ **saravana has it** — `security_posture="NOT_OBSERVABLE"`, `score_confidence`, `NOT_OBSERVED`, `is_confirmed_plaintext_payload()` |
| POP3 / STLS coverage | ❌ **gouravsehlangia has it** — `POP3_STLS_ADV/CMD/OK/ERR` + implicit TLS + all three protocols |
| Resumption-aware reasoning | ❌ **Prahari has it** — `sess.resumed and not sess.ems` → CFG-006, citing RFC 7627 |
| **Cross-session reasoning** | ✅ **SURVIVES — verified absent from all five.** saravana's "correlation" is cross-*layer*, single-session |

**Hypotheses:** H0–H3 ❌ rejected · H4/H5/H8 ⚠️ partial · H6/H9 🟡 unresolved · **H7 (cross-session
posture aggregation) ✅ SURVIVES** — technical + product differentiation, **not research novelty**.

**No competitor has everything.** Each is strong in one dimension: gourav (protocol coverage),
Prahari (citation rigour + 65 KB report builder), saravana (observability + live capture agent),
CipherPost (completeness + disclosed ML methodology). Assembling all four *plus* H7 is defensible as
**integration and correctness**, never as novelty.

⚠️ **Severe risk:** four teams have working code pushed daily since 2026-09-01; we have research
documents and zero code, with 4–14 days left.

### 2.14 🎯 OQ-21 RESOLVED — the AI inversion

[10A](10A-ai-opportunity-validation.md). Of 12 candidate AI roles, **3 defensible**. Verified at
source: gourav's LLM is a report rewriter with severity hardcoded *into the prompt* (and needs cloud
access); saravana's RandomForest trains on 2,500 self-generated archetypes (circular, undisclosed);
CipherPost's ML learns its own rules engine (circular, **disclosed in a code comment**).

**Nobody's AI does anything deterministic rules cannot.**

**The inversion:** every competitor trains ML on their own rule output. Instead, use **unsupervised
outlier detection to find what the rules *missed*** — sessions that are statistical outliers but
were flagged clean. No labels, non-circular by construction, satisfies A-02 in the PS's own words,
and **feeds H7**.

**Boundary architecture with enforceable invariants:** no AI component may create/modify/delete a
finding; every AI statement cites a structured evidence object; ML output is a pointer, never a
verdict; and **the tool must produce identical security output with AI disabled** (`--no-ai` diff
test — testable and demoable).

**Honest position to state openly:** removing AI costs almost nothing of security consequence. Net
delivery — 1 of 5 PS AI requirements uses ML as primary mechanism, 4 deterministic with ML support.
**Fewer AI components than competitors, more functional AI than any of them.**

### 2.12 🟡 What actually survives — execution-grade, not capability-grade

Verified absent from CipherPost's rules engine *and* from every tool audited:

1. **Evidence-observability discipline** — zero matches for `provenance`/`inherited`/`confidence`/
   `coverage`/`unobservable`. **Not novel** (Delgado 2026), but nobody building this PS does it.
2. **POP3/STLS coverage** — uncovered by general tooling *and* by the strongest competitor.
3. **Resumption-aware certificate reasoning** — absent; a false-finding source for anyone without it.
4. **Multi-session / longitudinal posture** — every competitor reasons per-session. ⚠️ Unverified.

**These are reasons our output would be more *correct*, not more *capable*.** A weaker but honest
position than we held this morning.

**Hypothesis verdicts:** H0 ❌ rejected · H1 ⚠️ true of tooling, false of competitors (useless) ·
H2 ❌ rejected · H3 ⚠️ weak · H4 ❌ rejected (table stakes) · H5 🟡 unresolved.

### 2.9 🟡 ~~Composability gap~~ — SUPERSEDED by 2.11, see 01C §7 (H2 REJECTED)

Strongest verified statement available: **even combining Zeek + Suricata + Wireshark, an analyst
cannot obtain a cryptographic posture assessment covering SMTP *and* IMAP *and* POP3, because the
evidence for two of the three protocols the PS names does not exist in stock tooling output.**

Survives prior art: (1) STARTTLS security state reconstruction across all three protocols;
(2) cross-protocol email posture; (3) analyst-ready assessment rather than logs and alerts.
**Label: POTENTIAL DIFFERENTIATION. Product/engineering differentiation, not a research contribution.**

### 2.10 🎁 `striptls` de-risks the experiment corpus

`tintinweb/striptls` is **CC0-1.0 public domain**, proxies **SMTP/POP3/IMAP**, and ships the exact
named attack vectors we must detect (`StripFromCapabilities`, `StripWithTemporaryError`,
`InjectCommand`, `ProtocolDowngradeStripExtendedMode`, …). This collapses the hardest part of corpus
construction and gives citable test-case IDs.

### 2.7 🟢 Reweighted opportunity — the STARTTLS negotiation layer

The STARTTLS phase is **cleartext at every TLS version**, so it is entirely unaffected by the
certificate limitation — and it is what the PS Background actually emphasises ("insecure STARTTLS
implementations", "downgrade attacks").

- **Poddebniak et al., USENIX Security 2021** — attack taxonomy across SMTP/POP3/IMAP: stripping,
  command injection, response injection, tampering, UI spoofing. ~320,000 servers (2%) vulnerable to
  command injection; only 3 of 28 clients and 7 of 23 servers clean.
- **Durumeric et al., IMC 2015** — 426+ ASes performing STARTTLS stripping; 14% of failed hosts
  echoed back the command, a passively detectable middlebox signature.
- **RFC 3207 §6** — stripping recognised normatively since 2002.

Every one of these has an observable signature in the cleartext phase. ⚠️ **Not yet a novelty
claim** — OQ-14 must first establish whether Zeek/Suricata already detect these passively.

### 2.3 🟡 The PS is mostly a protocol-engineering problem

18 deterministic requirements vs. 5 AI requirements. Of the AI requirements, only **anomaly
detection (A-02)** is clearly unsuited to deterministic rules. Risk classification and posture
scoring are arguably *better* served by auditable rules bound to RFC 8996 / NIST authorities than
by a model with no ground truth to learn from. Hypothesis to test in Phase 10: the most defensible
architecture uses *less* AI than competitors, and justifies each use.

### 2.4 🟡 No data is supplied; building the corpus is a real deliverable

NTRO provides no dataset. Exercising "weak crypto" detection requires deliberately standing up
insecure mail servers (TLS 1.0/1.1, RC4/3DES, expired/self-signed certs, SHA-1), which modern
OpenSSL and mail software actively resist. Two integrity traps follow: **(a)** decrypting with
`SSLKEYLOGFILE` and presenting it as passive capability, and **(b)** training and evaluating an
anomaly detector on traffic from our own generator, which measures the generator rather than the
detector.

### 2.5 🟡 NTRO's PS portfolio suggests a broader interest

NTRO submitted 22 problem statements to SIH 2026, 9 in Blockchain & Cybersecurity, including
SIH26160 (IPsec VPN protocol analyzer), SIH26164 (Enterprise Cryptographic Discovery & Analysis)
and SIH26155 (Multi-Vendor Network Security Compliance Auditor). **Speculative inference:** the
sponsor's interest is cryptographic inventory and posture *across protocols*, not email
specifically. A protocol-agnostic core with an email front-end may read as more valuable than an
email-only point tool. **Unverified — test in Phase 14.**

---

## 3. Assumptions currently in force

| ID | Assumption | Impact if wrong | Verification route |
|---|---|---|---|
| ~~A-01~~ | ~~mirrored PS is current official text~~ | ✅ **PROMOTED TO FACT 2026-09-16** — portal-confirmed token-identical (doc 19, S-33) | closed |
| **A-02** | Deployment context is offline / restricted-network | **High** — determines whether cloud LLM APIs are permissible, changing the AI architecture | NTRO context research; no official channel exists (contact field is empty) |
| A-03 | "PCAP" includes `.pcapng` | Low | Support both; costs little |
| A-04 | Evaluators can probe protocol-level claims | Medium — shapes demo and depth strategy | Phase 16 |
| A-05 | The team can run mail servers and capture traffic in a lab | **High** — blocks the entire data strategy | Team confirmation |

No assumption in this list has been promoted to FACT. Promotion requires a `SOURCES.md` entry plus
a changelog line in §6.

---

## 4. Unresolved questions

### Blocking — require team/SPOC input, cannot be resolved by research

| ID | Question | Why it blocks |
|---|---|---|
| ~~OQ-01~~ | ~~deadline 20 or 30 Sept?~~ | ✅ **RESOLVED — 30 September 2026** (official portal, doc 19). 14 days out. Remaining: SPOC internal cutoff (team) |
| **OQ-11** | Has an idea already been submitted for this PS? | An existing submission is effectively a locked requirement |
| **OQ-12** | Team size and skill distribution (protocol vs. ML vs. frontend)? | Dominant input to Phase 15 feasibility |
| **OQ-10** | Do prior decisions exist outside version control? | Repository is empty; absence of evidence is not evidence of absence |

### Non-blocking — resolvable by research in later phases

`OQ-02` **(elevated)** what fraction of real mail traffic is TLS 1.3 vs 1.2, and how much is
resumed — determines whether certificate blindness is a footnote or the dominant case ·
`OQ-03` authority for "weak"/"deprecated" (Phase 4) · `OQ-04` trust store and enterprise internal
CAs (Phase 4) · `OQ-05` defensibility of anomaly detection without real labelled data (Phase 10) ·
`OQ-06` does "passive" permit live tap (interpretation) · `OQ-07` shape of the posture-assessment
artifact (design) · `OQ-08` applicable Indian cryptographic policy (Phase 4) · `OQ-09` required
capture scale (team).

**New from the 01A validation pass:**

| ID | Question | Why it matters |
|---|---|---|
| **OQ-13** | Is a key-log-assisted (`SSLKEYLOGFILE`) mode within the PS's intent? | Changes what is demonstrable and the whole integrity story. Default: support it only as an explicitly-labelled optional mode |
| ~~OQ-14~~ | ~~Do existing tools already detect STARTTLS stripping?~~ | ✅ **RESOLVED 2026-09-16** — see finding 2.8 and [01B](01B-starttls-prior-art.md) |
| **OQ-15** | How reliably can implicit-TLS sessions (465/993/995) be identified without banners or certificates? | D-02 confidence on the exact variants NTRO's dataset hint names |
| **OQ-16** | Is inherited-evidence linkage across TLS 1.2 resumption sound enough to report? | Could recover much of the otherwise-lost certificate coverage |

**New from the 01B prior-art audit:**

| ID | Question | Why it matters | Priority |
|---|---|---|---|
| **OQ-17** | Does any PCAP analyzer already ship email cleartext-credential / "AUTH without STARTTLS" detection? | ✅ **Largely answered** — NetworkMiner extracts credentials from all three protocols (S-26); Arkime tags SMTP AUTH. **Capability L is prior art.** | closed |
| ~~OQ-18~~ | ~~Snort/NetworkMiner/Arkime~~ | ✅ **RESOLVED** — 01C §2. None detects stripping or does posture assessment | closed |
| ~~OQ-19~~ | ~~Zeek `zkg` packages~~ | ✅ **RESOLVED** — 01C §3. All 285 enumerated; zero relevant | closed |
| ~~OQ-23~~ | ~~Does multi-session posture survive competitor inspection?~~ | ✅ **RESOLVED — YES.** Verified absent from all five (01D §4) | closed |
| ~~OQ-24~~ | ~~Do competitors implement POP3/STLS or observability?~~ | ✅ **RESOLVED — YES, both.** gourav (POP3/STLS), saravana (observability) | closed |
| ~~OQ-21~~ | ~~Legitimate AI role?~~ | ✅ **RESOLVED** — 10A. Unsupervised inverted outlier detection + NL query. Analyst-facing only | closed |
| 🔴 **OQ-25** *(new)* | **Does cross-session baselining measurably reduce false positives vs. per-session analysis?** The entire provisional thesis rests on this and it is **untested** | **HIGHEST** — experiment | open |
| **OQ-26** *(new)* | Is shipping a local LLM (size, licensing, RAM) practical for an offline forensic tool? If not, NL query becomes deterministic-query-only | High | open |
| **OQ-27** *(new)* | On a synthetic corpus, does inverted outlier detection surface anything the rules miss — or is the honest answer zero? **We must be willing to report zero** | High | open |
| **OQ-20** | Build **on** Zeek (consume `ssl.log`/`x509.log`) or standalone? | Trades honesty and effort against "wrapper" perception and offline packaging | **team** + Phase 14 |
| **OQ-21** | Given that STARTTLS detections are deterministic state-machine checks, where does AI genuinely add value? | The PS title mandates AI; shoehorning is the risk | **Phase 10 — high** |
| **OQ-22** | Can pure-omission stripping be soundly inferred via multi-session baselining? | Single-session omission is indistinguishable from non-support | Medium |

Full text in doc 01 §11 and doc 01A §10.

---

## 5. Next research actions, in order

| # | Action | Phase | Depends on |
|---|---|---|---|
| 1 | **Re-verify the PS description against the live portal** — resolves A-01; everything downstream rests on it | 1 | — |
| 2 | **Resolve OQ-01 (deadline) with SPOC** — determines the shape of all remaining work | — | team |
| 3 | ~~Resolve OQ-14~~ | ✅ **DONE** — doc 01B | — |
| 3a | ~~Close OQ-18 / OQ-19~~ | ✅ **DONE** — doc 01C. Both closed in our favour; hypothesis falsified by competitors instead | — |
| 3b | ~~Competitor source audit~~ | ✅ **DONE** — doc 01D. 3 of 4 differentiators lost; H7 survives | — |
| 3c | ~~Phase 10 AI opportunity~~ | ✅ **DONE** — doc 10A. OQ-21 resolved via the inversion | — |
| 3d | ~~Test OQ-25~~ | ✅ **DONE** — doc 02A, RESULT B | — |
| 3e | ~~Packet-level replication (OQ-28)~~ | ✅ **DONE** — doc 02B, confirmed | — |
| 3f | ~~OQ-33: actual striptls run~~ | ✅ **DONE** — 02B §15, striptls executed & matches corpus | — |
| ~~3e-old~~ | ~~Packet-level replication~~ — run the 01B §10 `striptls` corpus through the same two detectors. 02A validated *reasoning*; this validates it on real captures. **Do no ML work before this** | experiment | lab |
| ~~3d-old~~ | ~~Test OQ-25~~ — does cross-session baselining actually reduce false positives? The provisional thesis depends entirely on it. Minimal test: one benign capture where a client legitimately declines a real STARTTLS offer → confirm per-session tools (incl. CipherPost) emit a false CRITICAL, and that cross-session baselining suppresses it | experiment | lab |
| 4 | Re-scope the Phase 4 domain deep dive from DNS/authentication to TLS/X.509/SMTP-IMAP-POP3 transport security | 4 | finding 2.1 |
| 5 | Read S-09 (Poddebniak), S-10 (Durumeric), S-20 (NDSS'25), S-21 (*TLS in the wild*) **in full** — all currently cited from summaries; build the passive-detection signature catalogue per attack class | 4, 8 | — |
| 6 | Pull primary standards: RFC 2595, 5280, 8314, 7525/9325, NIST SP 800-52r2 / 800-131A *(RFC 3207 ✅ done, S-11)* | 4 | — |
| 7 | Establish the authority for "weak"/"deprecated" (OQ-03, OQ-08), including any CERT-In/MeitY guidance | 4 | 6 |
| 8 | Stakeholder analysis for the four PS-named user groups: SOC, DFIR, IR, enterprise admins | 3 | — |
| 9 | Inspect the S-06 competitor repositories directly; confirm or refute the "default architecture" claim | 5, 6 | — |
| 10 | Survey the real tool landscape: Wireshark/tshark, Zeek, Suricata, testssl.sh, sslyze, Hardenize/Internet.nl, DFIR suites — and why each falls short of the PS | 5, 6 | 8 |
| 11 | Execute the 01A §11 capture experiment (design ✅ complete; **execution is implementation-phase work**) | 9, 10 | lab |

Actions 1 and 2 gate meaningful progress on everything else. **Action 3 is now urgent** — it tests
the finding that replaced the one withdrawn in 2.6, and we should not build strategy on it twice.

---

## 6. Changelog

| Date | Change |
|---|---|
| 2026-09-16 | Repository created. Phase 0, 1, 2 complete (v1). Official PS text retrieved, stored as evidence, and mechanically analysed. Scope correction (2.1) and observability paradox (2.2) identified. RFC 8446 and RFC 8996 cited as Tier 1 sources. |
| 2026-09-16 | **OQ-18/19 closure + competitor audit (doc 01C).** Inspected Snort 3 community rules (4,017), Arkime parsers, NetworkMiner docs, and **enumerated all 285 zkg packages**. Both OQs resolved in our favour. 🔴 **But Part H found ~10 competing SIH26159 repos, and CipherPost already ships `rule_starttls_strip` with SMTP+IMAP fixtures — falsifying H1/H2.** Built the 7-option tool-stack reconstruction and the one-week-competitor commodity/real-work split. Surviving differentiation downgraded to **execution-grade**: observability discipline, POP3/STLS, resumption-aware certs, multi-session posture. Established that competitor READMEs are unreliable (fredfe08 four-fact claim is README-only). Added S-23…S-27, OQ-23/24; closed OQ-17/18/19. |
| 2026-09-16 | **OQ-14 prior-art audit (doc 01B).** Inspected Zeek, Suricata and ET Open **source directly**. **OQ-14 RESOLVED:** attacks not detected by stock tooling; primitives exist unused; IMAP/POP3 largely uncovered (finding 2.8). Built the A–Q capability matrix, the parsing-vs-detection test, STARTTLS state machines with 11 attack deviations, the "competitor can already do this" test (**conceded: the whole extraction layer is already solved**), and a 14-objection red team with **6 unresolved risks**. Finding 2.9 labelled POTENTIAL DIFFERENTIATION, explicitly not research novelty. Found `striptls` (CC0-1.0) as corpus generator (2.10). Added S-15…S-22, OQ-17…OQ-22. |
| 2026-09-16 | **Critical validation pass (doc 01A).** Built the TLS 1.0–1.3 × 27-property passive visibility matrix and the PS requirement feasibility matrix. **Finding 2.2 amended** — facts upheld; certificate blindness widened to all resumed sessions at any version; rescaled to 5 of 22 deliverables. **🔴 Evidence-tiering novelty claim WITHDRAWN** on discovery of Delgado 2026, Casey's C-Scale, CVSS Report Confidence and Qualys confirmed/potential (2.6). **Opportunity reweighted to the STARTTLS layer** (2.7), pending OQ-14. Doc 01 §6.1 amended in place with the correction visible. Added sources S-07…S-14. Added OQ-13…OQ-16. Designed the 12+13-cell capture experiment (01A §11); **not executed**. |

---

## 7. Capability gaps affecting this research

Recorded per the brief's instruction to report missing capabilities. **None of these currently
block progress**; each would improve rigour.

| Gap | Impact | Remedy |
|---|---|---|
| **`gh` CLI not installed** | Could not inspect the GitHub remote's issues/wiki/projects for prior decisions, or read competitor repos efficiently | `brew install gh`. *(Remote refs were verified directly via `git ls-remote` — only `main` exists, so no hidden branches.)* |
| **`sih.gov.in` is JS-rendered and paginated** | Blocks direct primary-source verification of the PS body (A-01) — the single most important outstanding check | A team member opens the PS page in a browser and confirms the text, or we drive the in-app browser to the detail page |
| **No IEEE / ACM / ScienceDirect access** | Phase 13 prior-art search will be limited to open-access venues (arXiv, Google Scholar abstracts, patents) | Institutional library access, if available |
| **No packet-capture lab yet** | Phases 9–10 need real handshake data to move beyond theory; OQ-02 needs an experiment | Docker-based mail server lab. **Implementation-phase work — deliberately not started, per operating mode** |

---

## 8. Operating-mode compliance

- ✅ No product source code created or modified. Only `docs/research/**` written.
- ✅ No technology selected. No architecture chosen.
- ✅ No novelty claimed — §2.2 is labelled a *candidate* differentiator pending Phase 13.
- ✅ No statistics or citations fabricated. All four numbered sources were retrieved and read.
- ✅ Assumptions labelled and tracked; none silently promoted to fact.
- ✅ The tasking brief's own framing was challenged where evidence contradicted it (§2.1).
