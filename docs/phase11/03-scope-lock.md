# Phase 11 — 03. Scope lock

**Date:** 2026-09-22 · **Status:** binding for Phase 11
**Inputs:** `00-current-state-audit.md`, `01-requirement-gap-audit.md`,
`02-x509-observability-research.md`, `docs/research/01A-tls-visibility-validation.md`

This document closes the research gate. Nothing outside Category A, B or C may be
implemented in Phase 11. Categories D and E exist so that what was *rejected* is recorded as
deliberately as what was accepted.

---

## Category definitions

| | Meaning |
|---|---|
| **A** | **Implement fully.** Passively observable at every TLS version; no condition attached. |
| **B** | **Implement conditionally.** Observable only under stated preconditions; every other case must return an explicit non-observable state, never a negative verdict. |
| **C** | **Implement partially, by necessity.** One component is honestly deliverable; the rest is declared `NOT_OBSERVABLE` with a statement of what would be required. |
| **D** | **Out of scope — would violate a project invariant.** Rejected, with reason. |
| **E** | **Not earned.** Re-evaluated against evidence; status unchanged unless the evidence changes it. |

---

## Category A — implement fully

### A-i · D-09 — *"Identification of key exchange mechanisms."*

Derive the key-exchange mechanism from the negotiated suite (TLS ≤1.2) or from the ServerHello
`key_share` group (TLS 1.3). Both paths measured present. Unknown suite code ⇒ `AMBIGUOUS`.
No ServerHello ⇒ `UNKNOWN`.

**Precondition:** an observed ServerHello. **Never:** guess a mechanism from a partial suite name.

### A-ii · D-17 — *"Forward Secrecy assessment."*

Derived from the same audited table as D-09. TLS 1.3 removed static RSA and static DH key
exchange (RFC 8446 §1.2, appendix D.5) ⇒ every TLS 1.3 suite is forward secret by
construction. TLS ≤1.2: `ECDHE_`/`DHE_` ⇒ forward secret; `TLS_RSA_` ⇒ not.

**Never:** report "no forward secrecy" from an unobserved handshake. Absence of evidence
about the key exchange is `UNKNOWN`, which is a different claim from "not forward secret".

### A-iii · D-16 — *"Identification of insecure protocol configurations."*

AMB-06 records that the PS does not enumerate which configurations count. Phase 11 resolves
this by **declaring a bounded, versioned checklist** rather than leaving the requirement
open-ended, and by extending the existing eight-rule engine rather than adding a parallel one.
The checklist is fixed in doc 05; adding to it later is a versioned change, not a silent one.

---

## Category B — implement conditionally

**Shared precondition for all of Category B:** a cleartext `Certificate` handshake message —
TLS ≤1.2, full (non-resumed), untruncated handshake. When that precondition fails, the
outcome is `NOT_OBSERVABLE` with the reason stated, and the reason distinguishes *encrypted*
(TLS 1.3), *not sent* (resumption) and *truncated capture*.

| | Requirement | Delivered |
|---|---|---|
| **B-i** | D-10 *"Extraction of X.509 certificates."* | leaf and any further chain certificates present in the handshake, with serial, version, subject, issuer, SAN |
| **B-ii** | D-12 *"Certificate expiration analysis."* | `notBefore` / `notAfter`, evaluated **against the capture timestamp** |
| **B-iii** | D-13 *"Public key algorithm and key length analysis."* | algorithm, and length derived from the modulus (RSA) or curve (EC) |
| **B-iv** | D-14 *"Digital signature algorithm identification."* | signature algorithm OID → name |

**Binding rule (from 01A §4.1, adopted unchanged):** every certificate finding carries its
**provenance**. Phase 11 emits only `observed`. `inherited` is deferred (**OQ-58**);
`actively-retrieved` and `decrypted` are Category D.

**Binding rule (D-12):** the reference instant is the capture timestamp, never wall-clock.
A certificate that expired after the capture was taken was **valid during the captured
session**, and that is what a forensic tool must say.

**Declared false-negative:** absence of an extracted certificate is **not** evidence that no
certificate was presented. Every Category B output states this.

---

## Category C — implement partially, by necessity

### C-i · D-11 — *"Certificate chain validation."*

| Component | Disposition |
|---|---|
| Chain **structure** — order, count, issuer↔subject linkage, `basicConstraints cA`, AKI/SKI, self-signed detection | **IMPLEMENT** |
| Chain **trust** — validation against a trust anchor | **`NOT_OBSERVABLE`.** RFC 5280 §6 requires trust anchors; a PCAP contains none. Trust-store choice is itself unresolved (**OQ-04**, open since Phase 1). |
| **Revocation** — OCSP / CRL status | **`NOT_OBSERVABLE`.** RFC 6960 OCSP and CRL retrieval are separate network transactions absent from a mail-session capture. |

The finding must state *what would be required* to answer the parts it cannot. "Chain
structure analysed; trust not evaluated — no trust anchor is present in a packet capture" is
honest. "Chain invalid" would not be.

**PS-closure note.** D-11's PS wording is *"Certificate chain validation."* Phase 11 delivers
structural validation and explicitly declines trust validation. **This requirement closes as
PARTIAL, and the traceability entry will say so.** A technically honest PARTIAL is the correct
outcome here; claiming COMPLETE would require either bundling a trust store (systematic false
positives against enterprise private CAs) or redefining "validation" to mean something the
reader would not understand by that word.

---

## Category D — out of scope, with reason

| Rejected | Reason |
|---|---|
| Active certificate retrieval (TLS probe, `openssl s_client`) | Breaks **I-02 passive / non-interference** — the one invariant the PS states in its own words (*"passive network forensic framework"*). It also answers a different question: the certificate *now*, not the certificate in the captured session. |
| Session-key decryption (SSLKEYLOGFILE, private-key import) | Breaks the offline/evidence-only model; requires material a forensic capture does not carry. |
| Bundling a public CA root store | Systematic false positives against private enterprise CAs — the exact deployment population the PS targets. Does not resolve OQ-04, only hides it. |
| OCSP / CRL fetching | Active network access (I-02) and breaks offline operation (I-01). |
| Certificate Transparency log lookup | Same — a network service, not capture evidence. |
| Hostname verification against an external DNS view | Requires resolution the capture does not contain. SAN↔SNI comparison **within the capture** is permitted; anything beyond it is not. |
| Any new runtime dependency for X.509 parsing | tshark already decodes all 38 required fields (doc 02 §7). Adding `cryptography`/`pyOpenSSL`/`openssl` buys nothing and costs the zero-dependency core. |
| SPF · DKIM · DMARC · DNS security · attacker attribution · email-content analysis · blockchain · SOC/SIEM · chatbot · LLM-generated verdicts | Feature creep; outside the PS; explicitly rejected by the Phase-11 brief. |

---

## Category E — re-evaluated, not earned

### E-i · A-02 — *"AI-assisted anomaly detection for suspicious TLS sessions."*

ADR-0015 records Outcome D: **zero unique true detections on every held-out split**. Phase 11
makes certificate- and key-exchange-derived features available for the first time, so the
question is re-opened honestly in `04-ai-reassessment.md`.

**Pre-committed decision rule, fixed before the evaluation runs:**

> A-02 moves from PARTIAL only if new features produce **unique true detections on a
> held-out split that the deterministic rules do not already produce**. Anything less —
> including improved scores, better separation, or nicer clustering — leaves A-02 **PARTIAL**.

A negative result is a valid outcome and will be reported as one. The ML lane remains bounded
by `MAX_ML_ADJUSTMENT = 4.0` against a narrowest severity-tier gap of 30 (ADR-0015); Phase 11
does not touch that bound.

---

## Locked invariants for the implementation milestones

1. `PostureAssessment` remains the single canonical security truth. New evidence flows
   **into** it; no downstream layer recomputes security meaning.
2. The six evidence states are never collapsed. A missing certificate is `NOT_OBSERVABLE`,
   not a finding of absence.
3. Severity / evidence certainty / observability stay independent (Phase 7).
4. Core package stays zero-runtime-dependency; Python 3.9 compatible.
5. All PCAP-derived text is hostile. No `innerHTML`, `insertAdjacentHTML`, `document.write`,
   `eval`, `new Function`; no API-controlled executable URLs; no class names built from
   untrusted input.
6. Forbidden inferences, restated: *certificate not visible* ↛ *certificate invalid*;
   *handshake incomplete* ↛ *weak TLS*; *no observed advertisement* ↛ *STARTTLS stripped*;
   *anomaly score high* ↛ *attack detected*.
7. No historical tag, `main`, or previous release artifact is modified.

---

## New open questions

| ID | Question | Disposition |
|---|---|---|
| **OQ-58** | Should `inherited` certificate provenance (TLS 1.2 resumption re-using a session ID whose full handshake appears earlier in the same capture) be implemented? | **Deferred.** The corpus contains no TLS 1.2 resumption. Implementing it without evidence to validate against would be untested code on a forensic claim. |
| **OQ-59** | Is OCSP stapling (`status_request`) visible in a cleartext TLS ≤1.2 handshake, and does it carry usable revocation evidence? | **Not measured this phase, not claimed.** Recorded rather than assumed. |
| **OQ-60** | The real corpus is 100 % TLS 1.3, so the entire Category B family can only be validated against captures synthesised in this phase. What real-world TLS ≤1.2 mail traffic can be obtained? | **Stated as a limitation in the traceability entry, not papered over.** |

**OQ-04** (trust store / enterprise internal CAs) remains **open** and is now the explicit
reason D-11 closes PARTIAL rather than COMPLETE.
