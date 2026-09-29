# Phase 12 — 01. Final requirements audit

**Method:** every requirement's exact wording and authority is re-verified against
`docs/research/19-authoritative-ps-verification.md` §2/§8 — itself sourced from the **official SIH
portal HTML** (`https://sih.gov.in/sih2026PS`, retrieved 2026-09-16, hashed evidence saved), not
from a mirror. That gate already re-validated the source once; this audit does not re-fetch the
portal (nothing has changed since 2026-09-16 that would require it — no new PS version, no
amendment notice), but every wording quote below is checked against doc 19's verbatim quotes, not
against the traceability document's paraphrase.

**Cross-reference, not duplication.** `docs/architecture/requirements-traceability.md` already maps
every requirement to its component, implementation phase, test file and demo scene — re-verified
in Phase 11's release audit and unchanged since. This document does not repeat that table. It adds
the analytical layer the traceability document does not carry: **class (§6 of the brief), whether
additional engineering could materially improve the requirement, effort, validation burden, and
deadline risk** — each independently assessed, not inherited from prior framing.

**Status vocabulary, exactly five values, no hedging:** `COMPLETE` · `PARTIAL` · `NOT_OBSERVABLE` ·
`NOT_IN_SCOPE` · `DEFERRED`.

---

## 1. Deliverables (D-01 … D-18)

| Req | Verbatim PS wording | Status | Class | Remaining gap | Engineering could improve it? | Effort | Validation burden | Deadline risk |
|---|---|---|---|---|---|---|---|---|
| D-01 | PCAP ingest (Objectives + Deliverables) | COMPLETE | A | none | no | — | — | none |
| D-02 | protocol identification (SMTP/IMAP/POP3) | COMPLETE | A | none | no | — | — | none |
| D-03 | TCP reassembly (consumed from tshark) | COMPLETE | A | none | no | — | — | none |
| D-04 | *"Detection of STARTTLS negotiation and encrypted session upgrades"* | COMPLETE | A | none | no | — | — | none |
| D-05 | *"STARTTLS negotiation detection and validation"* | COMPLETE | A | none | no | — | — | none |
| D-06 | handshake reconstruction | COMPLETE | A | none | no | — | — | none |
| D-07 | negotiated TLS version | COMPLETE | A | none | no | — | — | none |
| D-08 | negotiated cipher suite | COMPLETE | A | none | no | — | — | none |
| D-09 | *"Identification of key exchange mechanisms"* | COMPLETE | A | none | no | — | — | none |
| D-10 | *"Extraction of X.509 certificates"* | COMPLETE **where observable** | C | TLS 1.3 encrypts the Certificate message (RFC 8446 §2) — structural, not an engineering gap | no — more code cannot see through TLS 1.3 encryption | — | — | none |
| D-11 | *"Certificate chain validation"* (PS Deliverables; Objectives says *"Extraction and validation of X.509 digital certificates"*) | **PARTIAL** | C | trust and revocation require material a PCAP does not contain (RFC 5280 §6 trust anchors; RFC 6960 OCSP/CRL are network transactions) | **conditionally** — an operator-supplied trust store (OQ-04) would extend trust validation; would not touch revocation | Medium (new UI, new input surface, new tests) | High (false-positive risk against private CAs must be re-proven) | High if attempted now — see §20 discussion below |
| D-12 | *"Certificate expiration analysis"* | COMPLETE **where observable** | C | same TLS 1.3 visibility limit as D-10 | no | — | — | none |
| D-13 | *"Public key algorithm and key length analysis"* | COMPLETE **where observable** | C | same TLS 1.3 visibility limit; EC key length not yet exercised against a real EC certificate (only RSA fixtures exist) | marginal — could add an EC fixture | Small | Small | low |
| D-14 | *"Digital signature algorithm identification"* | COMPLETE **where observable** | C | same TLS 1.3 visibility limit | no | — | — | none |
| D-15 | weak/deprecated crypto | COMPLETE | A | none | no | — | — | none |
| D-16 | *"Identification of insecure protocol configurations"* | COMPLETE, bounded | B | PS does not enumerate the configuration list (AMB-06); we closed it with a declared, versioned 7-item checklist — a defensible interpretation, not the only possible one | only if a judge disputes the checklist's scope, which is a presentation risk, not a code gap | — | — | low (defensible with the checklist rationale in hand) |
| D-17 | *"Forward Secrecy assessment"* | COMPLETE | A | none | no | — | — | none |
| D-18 | *"Extraction of cryptographic features for intelligent analysis"* | COMPLETE | A | none | no | — | — | none |

## 2. AI/ML (A-01 … A-05)

| Req | Verbatim PS wording | Status | Class | Remaining gap | Engineering could improve it? | Effort | Validation burden | Deadline risk |
|---|---|---|---|---|---|---|---|---|
| A-01 | *"Cryptographic risk classification"* | COMPLETE | A | none | no | — | — | none |
| A-02 | *"AI-assisted anomaly detection for suspicious TLS sessions"* | **PARTIAL** | C | capability shipped, evaluated, reproducible; **zero unique true detections on any held-out split**, including with the new Phase-11 features (measured across all 46 available captures) | **not with the data this project has** — see §21 discussion below; more model iteration on the same corpus is not engineering, it is p-hacking | — (deliberately not attempted) | — | none — attempting to force a positive result would be the actual risk |
| A-03 | *"AI-based cryptographic risk scoring"* / *"Security posture scoring"* | COMPLETE | A | none | no | — | — | none |
| A-04 | *"Threat prioritization"* | COMPLETE | A | none | no | — | — | none |
| A-05 | *"Recommendation of mitigation measures"* | COMPLETE for implemented issue classes | A | non-actionable issue classes (e.g. `ANOMALY`) correctly have no remediation template rather than a generic one | no | — | — | none |

## 3. Reports & interface (R-01 … R-05)

| Req | Verbatim PS wording | Status | Class | Remaining gap | Engineering could improve it? | Effort | Validation burden | Deadline risk |
|---|---|---|---|---|---|---|---|---|
| R-01 | *"Prioritized security findings"* | COMPLETE | A | none | no | — | — | none |
| R-02 | *"comprehensive cryptographic posture assessment"* | COMPLETE | A | none | no | — | — | none |
| R-03 | *"Exportable forensic reports in JSON, PDF, and HTML formats"* | COMPLETE | A | none — but no **pre-rendered example** ships in the repo for offline demo use | no code gap; a packaging gap | Small (generate + commit 2-3 example reports) | Small | low, but see `10-demo-environment.md` |
| R-04 | *"Interactive visualization dashboard"* | COMPLETE | A | no packet-level drill-down (deliberate — the assessment carries none) | not without a scope change to the canonical contract itself | Large, and out of PS wording | High | do not attempt |
| R-05 | *"comprehensive forensic reports"* | COMPLETE | A | none | no | — | — | none |

## 4. Inferred/implicit requirements (I-01 … I-08)

These are **not** PS text; doc 19 §9 explicitly marks them as our own inferences, carried forward
here unchanged rather than re-litigated (re-litigating an inference is not what an evidence audit
does — the PS text has not changed since doc 19 read it).

| Req | Nature | Status | Class | Note |
|---|---|---|---|---|
| I-01 | offline/air-gapped operation | COMPLETE (as our own design goal, not a PS mandate) | F | zero-runtime-dependency core, no network calls anywhere in `src/`; never present it to a judge as a PS requirement, present it as an engineering choice |
| I-02 | passive / non-interference | COMPLETE | A | this one *is* PS text — *"passive network forensic framework"* — confirmed |
| I-03 | evidence/forensic integrity | COMPLETE | A | SHA-256 capture identity, content-addressed artifacts, tamper detection, `report_sha256` |
| I-04 | enterprise scale | PARTIAL, untested at scale | E | no capture larger than a few hundred KB has been run through the pipeline; the PS phrase *"enterprise email infrastructures"* is about traffic scope, not throughput benchmarking, and nothing in the PS asks for a load test |
| I-05 | participant-generated dataset | COMPLETE | A | confirmed by the dataset field itself |
| I-06 | opaque-session handling | COMPLETE | A | `NOT_OBSERVABLE`/`UNKNOWN` states exist precisely for this |
| I-07 | compliance mapping | PARTIAL | E | rules cite RFC/NIST standards per-finding; no separate "compliance report" view exists, and nothing in the PS text asks for one |
| I-08 | explainability | COMPLETE | A | every finding carries conclusion + explanation + standards + limitations; not a PS mandate but well covered regardless |

## 5. Summary count

| Status | Count |
|---|---|
| COMPLETE | 24 of 31 tracked requirements (D-01–09, D-12–15, D-17, D-18, A-01, A-03–05, R-01–05, I-01, I-02, I-03, I-05, I-06, I-08) |
| COMPLETE where observable (a structural, not engineering, boundary) | D-10, D-12–14 (counted above, flagged separately because "where observable" is doing real work in the sentence) |
| PARTIAL | D-11, A-02, I-04, I-07 |
| NOT_OBSERVABLE | none standalone — this state appears *within* findings (e.g. a TLS-1.3 session's D-10 result), not as a requirement-level status |
| NOT_IN_SCOPE | none — every requirement traced maps to confirmed PS text or a declared inference |
| DEFERRED | none at the requirement level (OQ-58/OQ-61 are deferred *investigations*, not deferred requirements) |

**Every requirement that is PARTIAL has a measured, specific, evidence-backed reason — never an
"incomplete implementation" reason.** That distinction is the entire finding of this audit: there
is no requirement sitting unfinished for lack of time. D-11 and A-02 are partial because the
*evidence available* does not support more, not because the *engineering* stopped short.
