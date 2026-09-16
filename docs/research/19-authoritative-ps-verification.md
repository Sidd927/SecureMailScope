# 19 — Authoritative PS & Deadline Verification Gate

**Purpose:** Resolve the two foundational uncertainties before any architecture — (1) what SIH26159
actually requires, (2) the authoritative deadline.
**Status:** ✅ **BOTH RESOLVED against the official portal.**
**Date:** 2026-09-16 · **Not** a new research phase; a requirements gate.

---

## 0. Headline

> ## ✅ Assumption A-01 is CONFIRMED. The mirror was accurate. Nothing built so far is invalidated.
> ## 🔴 Deadline is **30 September 2026** — authoritative, 14 days away. The mirror's "20 September" was WRONG.

The official portal (`https://sih.gov.in/sih2026PS`) returned full server-rendered HTML on this
attempt — unlike earlier attempts where it appeared JS-gated. The complete SIH26159 record was
retrieved, saved as immutable evidence, and diffed against our stored mirror.

---

## 1. Part 1 — authoritative source retrieved

| | |
|---|---|
| **Source** | `https://sih.gov.in/sih2026PS` — official SIH 2026 portal (Ministry of Education / AICTE) |
| **Retrieved** | 2026-09-16 |
| **HTTP** | 200, 2,794,861 bytes, server-rendered (SIH26159 present in raw HTML) |
| **Evidence** | `evidence/sih2026-portal-SIH26159-20260916.html` (sha256 `12a3f78df87eda8e03b08e68…`) |
| **Authority** | **Tier 1 for this project** — the official portal itself, not a mirror |

### Authoritative metadata (from the portal)

| Field | Value |
|---|---|
| PS ID | SIH26159 |
| Title | SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications |
| Organization / Department | National Technical Research Organisation (NTRO) |
| Category | Software |
| Theme | Blockchain & Cybersecurity |
| Dataset | *"Synthetic - Participants May generate IMAPS, POP3S, SMTPS Data using any E-mail server/client of their interest and capture pcap dump"* |
| YouTube / Contact | empty |
| **Submitted ideas** | **1/500** (was 0/500 in the 2026-08-22 mirror) |
| **Deadline** | **30 September 2026** (`30-09-2026`) |

Portal footer string, verbatim: `SIH26159 1/500 Blockchain & Cybersecurity 30 September 2026
30-09-2026`.

---

## 2. Part 2 — A-01 verification (mirror vs portal)

**Method.** Extracted the SIH26159 description from portal HTML, stripped tags, normalised
whitespace, and diffed token-by-token against `evidence/SIH26159-official-ps.json`.

**Result: every content token matches.** The only differences were `<br>` / `<br><br>` HTML tags
present in the portal markup and absent from the mirror's plain text. Six exact PS phrases confirmed
present on the portal verbatim:

- ✅ *"Design and develop an AI-assisted passive network forensic framework"*
- ✅ *"Passive analysis of encrypted SMTP, IMAP, and POP3 traffic from PCAP files"*
- ✅ *"Extraction and validation of X.509 digital certificates"*
- ✅ *"AI-assisted anomaly detection for suspicious TLS sessions"*
- ✅ *"Exportable forensic reports in JSON, PDF, and HTML formats"*
- ✅ *"Synthetic - Participants May generate IMAPS, POP3S…"*

Absence check re-run on portal text: **`spf`, `dkim`, `dmarc`, `dns` all absent** — the scope
correction (doc 01 §8) holds against the authoritative source.

> **A-01 promoted from ASSUMPTION to FACT.** The mirror was faithful. Requirement IDs D-01…D-18,
> A-01…A-05, R-01…R-05 stand as extracted.

### Requirement confirmation matrix

| Req group | In official PS? | Status |
|---|---|---|
| D-01…D-03 (PCAP ingest, protocol ID, TCP reassembly) | Yes — Objectives + Deliverables | **CONFIRMED** |
| D-04 STARTTLS detection | Yes — *"Detection of STARTTLS negotiation and encrypted session upgrades"* | **CONFIRMED** |
| D-05 STARTTLS validation | Yes — *"STARTTLS negotiation detection **and validation**"* (Deliverables) | **CONFIRMED** |
| D-06…D-09 (handshake, version, cipher, KEX) | Yes | **CONFIRMED** |
| D-10…D-14 (X.509 extract/chain/expiry/key/sig) | Yes — all five named in Deliverables | **CONFIRMED** (⚠️ passively conditional — 01A) |
| D-15 weak crypto / deprecated TLS | Yes | **CONFIRMED** |
| D-16 insecure configuration | Yes — *"Identification of insecure protocol configurations"* | **CONFIRMED** (scope still open — AMB-06) |
| D-17 Forward Secrecy | Yes — *"Forward Secrecy assessment"* | **CONFIRMED** |
| D-18 crypto feature extraction | Yes — *"Extraction of cryptographic features for intelligent analysis"* | **CONFIRMED** |
| A-01 risk classification | Yes — *"Cryptographic risk classification"* | **CONFIRMED** (as PS wording) |
| A-02 anomaly detection | Yes — *"AI-assisted anomaly detection for suspicious TLS sessions"* | **CONFIRMED** |
| A-03 posture scoring | Yes — *"AI-based cryptographic risk scoring"* / *"Security posture scoring"* | **CONFIRMED** |
| A-04 prioritisation | Yes — *"Threat prioritization"* / *"Prioritized security findings"* | **CONFIRMED** |
| A-05 remediation | Yes — *"Recommendation of mitigation measures"* | **CONFIRMED** |
| R-01…R-03 (prioritised findings, posture assessment, JSON/PDF/HTML) | Yes | **CONFIRMED** |
| R-04 dashboard | Yes — *"Interactive visualization dashboard"* | **CONFIRMED** |
| R-05 forensic reports | Yes — *"comprehensive forensic reports"* | **CONFIRMED** |
| **I-01 offline/air-gapped** | **Not stated** | **INFERENCE — remains our inference, not PS text** |
| **I-02 passive / non-interference** | Yes — *"passive network forensic framework"* | **CONFIRMED** |
| I-03 evidence integrity | Implied by *"forensic"* (×3) | **PARTIALLY CONFIRMED** (word present; requirements inferred) |
| I-04 enterprise scale | *"enterprise email infrastructures"* | **PARTIALLY CONFIRMED** |
| I-05 data generation | Yes — dataset field | **CONFIRMED** |
| I-06 opaque-session handling | Not stated | **INFERENCE** |
| I-07 compliance mapping | *"compliance with modern cryptographic best practices"* | **PARTIALLY CONFIRMED** |
| I-08 explainability | *"assist … analysts in rapidly identifying … prioritizing"* | **PARTIALLY CONFIRMED** |

No requirement is **CONTRADICTED**. No mirror-only invention survived that isn't in the official text.

---

## 3. Part 3 — what the PS actually says about AI

Established from the authoritative text, no judgement about acceptance.

| Question | Answer from the official PS |
|---|---|
| Is AI explicitly mandatory? | **Yes.** Title is *"AI-Assisted"*; Objectives require *"Application of AI/ML techniques for: … "* |
| Is ML explicitly mandatory? | **Yes** — *"AI/ML techniques"* named explicitly |
| Is anomaly detection explicitly required? | **Yes** — *"AI-assisted anomaly detection for suspicious TLS sessions"* (Objectives **and** Deliverables) |
| Is explainability required? | **Not explicitly.** Implied only by "assist analysts" / "actionable". |
| Is RAG / LLM mentioned? | **No.** Neither term appears. |
| Is natural-language interaction mentioned? | **No.** Our NL-query role (10B) is **our design choice**, not a PS requirement. |
| Wording requiring a *trained model*? | **Ambiguous.** *"Application of AI/ML techniques"* and *"AI-assisted anomaly detection"* imply a technique, but the text never prescribes a trained/supervised model, accuracy target, or architecture. |
| Could deterministic anomaly detection satisfy it? | **Textually plausible** — the PS says *"AI-assisted anomaly detection"*, not *"a trained ML classifier"*. Whether an evaluator reads our deterministic cross-session baseline as satisfying "AI/ML techniques" is **OQ-35, unresolved**. The text neither confirms nor forbids it. |

**Which A-01…A-05 mappings were assumptions?** The *requirements themselves* are all in the PS
(confirmed above). What was **our inference** is the **implementation choice** — deterministic-first
with minimal AI (10B). The PS wording *"AI/ML techniques"* is genuinely open on method; our reading
that deterministic anomaly detection can satisfy A-02 is a defensible interpretation, **not** PS
text. This is now explicitly flagged, not silently retained.

---

## 4. Part 4 — input / dataset requirement

| Question | Official PS |
|---|---|
| PCAP | ✅ *"analyzing captured network traffic (PCAP files)"* |
| SMTP / IMAP / POP3 | ✅ all three named repeatedly |
| TLS | ✅ throughout |
| X.509 | ✅ *"Extraction and validation of X.509 digital certificates"* |
| Synthetic data | ✅ dataset field — participant-generated |
| Provided dataset | ❌ **None** — NTRO supplies no data |
| Participant-generated | ✅ *"Participants May generate IMAPS, POP3S, SMTPS Data … capture pcap dump"* |
| Passive analysis | ✅ *"passive network forensic framework"* |
| **Auxiliary evidence** | **Not mentioned.** No CT logs, no active probing, no key logs in the text. |

**Resolution — PASSIVE PCAP ONLY vs PCAP + AUXILIARY:** the PS describes **passive analysis of PCAP
files** and nothing else. It neither mentions nor authorises auxiliary evidence. Therefore:

> **The authoritative scope is PASSIVE PCAP ONLY.** Auxiliary evidence (active probing, CT logs, key
> logs) is **out of PS scope** and, if ever used, must be an explicitly-labelled optional mode — as
> 01A §4 already required. The PS text confirms our conservative reading.

The dataset hint names **IMAPS/POP3S/SMTPS** (implicit TLS) specifically — reinforcing that
implicit-TLS handling (OQ-15, OQ-34) is in scope, not optional.

---

## 5. Part 5 — deadline reconciliation

| Date | Event | Scope | Authority | Confidence |
|---|---|---|---|---|
| **30 September 2026** | Idea submission deadline for SIH26159 | Per-PS, on the official portal | **Official portal** (`30-09-2026`) | **HIGH — authoritative** |
| ~~20 September 2026~~ | ~~claimed idea deadline~~ | — | 2026-08-22 community mirror | **REFUTED** — contradicted by the live portal |
| 30 September 2026 | National nomination + idea deadline | National | Institutional/aggregator reporting (S-05) | Medium — **consistent** with the portal |

**Resolved.** The conflict is gone: the mirror's `20 September` value was **wrong** (or a stale
default). The official portal shows **30 September 2026** for this PS, and independent institutional
reporting agrees. The earlier "two different stages" hypothesis is unnecessary — both authoritative
signals converge on 30 September.

---

## 6. Part 6 — time sensitivity

**Current date: 2026-09-16. Deadline: 2026-09-30 → 14 days.** Not inside the 7-day flag window, but
close. The near-term deliverable is the **idea/abstract submission**, not a working system (Grand
Finale is December 2026). 🔴 **Confirm with your SPOC that the college internal deadline is not
earlier than the national 30 September** — SPOC-nomination cutoffs are often days ahead of the portal
date. That is the one remaining timeline risk, and only you can close it.

---

## 7. Part 7 — competitor / architecture impact

| Question | Answer |
|---|---|
| Does the PS require functionality we ignored? | **No.** Every deliverable maps to an existing requirement ID. |
| Does it invalidate architecture assumptions? | **No.** Passive-PCAP-only (our conservative reading) is confirmed. |
| Does it make the AI layer more important? | **Marginally.** AI/ML and anomaly detection are explicitly required — reinforcing that we must *ship* an A-02 mechanism (we do: the deterministic baseline) and defend it (OQ-35). It does **not** require an LLM or NL interaction. |
| Does it change cross-session relevance? | **No** — neither supports nor forbids it; it remains our differentiator. |
| Does it change protocol scope? | **No** — SMTP/IMAP/POP3 confirmed; implicit-TLS variants reinforced by the dataset hint. |

Nothing learned from competitors changes. The scope correction, the observability finding, the
STARTTLS focus, cross-session reasoning, and the AI decision all survive the authoritative text.

---

## 8. LOCKED REQUIREMENTS

Confirmed by the official portal (verbatim PS). These are now **FACT**, not assumption:

1. **Input:** passive analysis of participant-generated **PCAP** files containing **SMTP, IMAP,
   POP3** — including implicit-TLS (**SMTPS/IMAPS/POP3S**). No dataset provided. **Passive only.**
2. **Extraction:** protocol ID, TCP stream reassembly, STARTTLS detection **and validation**, TLS
   handshake reconstruction, negotiated version/cipher/key-exchange, X.509 extraction/chain/expiry/
   public-key/signature-algorithm, weak-crypto & deprecated-TLS detection, insecure-config
   identification, Forward Secrecy assessment, cryptographic feature extraction. *(D-01…D-18)*
3. **AI/ML (explicitly required):** cryptographic risk classification, **AI-assisted anomaly
   detection for suspicious TLS sessions**, posture scoring, threat prioritisation, mitigation
   recommendation. *(A-01…A-05)*
4. **Outputs:** prioritised findings, comprehensive cryptographic posture assessment, exportable
   forensic reports in **JSON, PDF, and HTML**, interactive visualization dashboard. *(R-01…R-05)*
5. **Users:** SOC, Digital Forensics, Incident Response, enterprise administrators.
6. **Nature:** passive network **forensic** framework. *(I-02 confirmed)*

## 9. ASSUMPTIONS REMOVED / RECLASSIFIED

- **A-01 (mirror accuracy)** — ✅ **removed as an assumption; now FACT.** Portal-confirmed.
- **Deadline 20 September** — ❌ **removed; refuted.** Authoritative date is **30 September 2026**.
- **"Auxiliary evidence may be in scope"** — ❌ **removed.** PS is passive-PCAP-only; auxiliary is
  out of scope / optional-labelled only.
- **"The PS mandates a trained ML model"** — ⚠️ **reclassified to AMBIGUOUS.** PS says *"AI/ML
  techniques"* / *"AI-assisted anomaly detection"*, not a trained model. Our deterministic-baseline
  reading of A-02 is a defensible interpretation, **not** PS text (OQ-35).
- **I-01 (offline/air-gapped)** — ⚠️ **remains our INFERENCE**, not PS text. NTRO context makes it
  reasonable, but the PS does not state it. Do not present it as a requirement.
- **I-03/I-04/I-06/I-07/I-08** — remain inferences/partials as marked in §2.

## 10. DEADLINE STATUS

> **AUTHORITATIVE: 30 September 2026** (official portal, `30-09-2026`, retrieved 2026-09-16,
> evidence saved). **14 days out.** Submitted ideas: **1/500** (lock at 500).
> 🔴 **Only remaining timeline risk: the college SPOC's internal cutoff may precede 30 September —
> confirm with your SPOC.** This cannot be resolved by research.

---

## 11. Gate result

✅ **Requirements gate PASSED.** A-01 confirmed, deadline resolved, scope confirmed passive-PCAP-only,
AI requirement clarified (required, but method-open). **No contradiction with anything built in
phases 0–10.** The one item needing your input is the SPOC internal deadline (§6). Architecture may
begin once you confirm that.
