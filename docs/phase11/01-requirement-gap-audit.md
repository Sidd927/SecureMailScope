# Phase 11 — 01. Authoritative requirement gap audit

**Date:** 2026-09-22 · **Source of truth:** `docs/research/19-authoritative-ps-verification.md`
and the preserved portal capture `docs/research/evidence/SIH26159-official-ps.json`.

Every requirement below is quoted **verbatim from the official PS Deliverables list**. No
requirement semantics are inferred from memory.

---

## 0. Authoritative wording — the Deliverables list

From `SIH26159-official-ps.json`, *"Expected Solution/Deliverables"*, in PS order. The
project's D-numbering maps onto it one-to-one:

| ID | Verbatim PS deliverable |
|---|---|
| D-09 | *"Identification of key exchange mechanisms."* |
| D-10 | *"Extraction of X.509 certificates."* |
| D-11 | *"Certificate chain validation."* |
| D-12 | *"Certificate expiration analysis."* |
| D-13 | *"Public key algorithm and key length analysis."* |
| D-14 | *"Digital signature algorithm identification."* |
| D-16 | *"Identification of insecure protocol configurations."* |
| D-17 | *"Forward Secrecy assessment."* |
| A-02 | *"AI-assisted anomaly detection for suspicious TLS sessions."* |

The Objectives section independently states *"Extraction **and validation** of X.509 digital
certificates"* and *"Identification of negotiated TLS versions, cipher suites, and **key
exchange mechanisms**"*, confirming the same scope from a second place in the PS.

**FACT:** doc 19 already flags D-10…D-14 as **"CONFIRMED (⚠️ passively conditional)"**. That
caveat is the crux of this phase.

---

## 1. Measured observability evidence

All numbers below come from `research/experiments/p11cert/results/observability.json`,
produced this phase with tshark 4.6.8 over `-T ek`.

| Capture | Handshake types seen | X.509 fields | `key_share_group` |
|---|---|---:|---|
| **synthetic TLS 1.2** (this phase) | ClientHello, ServerHello, **Certificate**, ServerKeyExchange, ServerHelloDone, ClientKeyExchange | **38** | — |
| `postfix_smtp_starttls_upgrade` (real) | ClientHello, ServerHello | **0** | `29` |
| `dovecot_imap_imaps_implicit_tls` (real) | ClientHello, ServerHello | **0** | `29` |
| `dovecot_pop3_stls_upgrade` (real) | ClientHello, ServerHello | **0** | `29` |

**FACT:** the entire existing real corpus negotiates **TLS 1.3**. Under RFC 8446 §2 the
Certificate message is sent after `ServerHello` under handshake-traffic keys, so it is
encrypted and structurally invisible to a passive observer. The zero X.509 count is not a
tooling gap — it is the protocol.

**FACT:** in the synthetic TLS 1.2 capture the certificate is in cleartext and tshark decodes
38 X.509 fields *without any new dependency*, including `notBefore`/`notAfter`, RSA modulus
and exponent, signature `algorithm_id` OID, SAN `dNSName`, `basicConstraints cA`, and
Subject/Authority Key Identifiers.

---

## 2. Per-requirement audit

### D-09 — *"Identification of key exchange mechanisms."*

| | |
|---|---|
| Current status | **NOT IMPLEMENTED.** Zero references to key exchange, named groups or supported groups in `src/`. The cipher suite is stored as raw hex and never interpreted. |
| Existing evidence | `SessionEvidence.tls_cipher_suite` = `"0x1302"`; `tls.handshake.extensions_key_share_group` present in captures but not consumed. |
| Missing capability | map suite code → key-exchange mechanism (TLS ≤1.2); read negotiated group from ServerHello `key_share` (TLS 1.3). |
| Required inputs | ServerHello only. Already captured. |
| Passive observability | **FULL.** Both paths measured present. |
| Architectural support | Present — add an `EvidenceField` on `SessionEvidence`, derived in `session/base.py` beside `negotiated_cipher`. |
| Complexity | Low. Needs an IANA-derived static table (no new dependency). |
| Validation | Real captures (TLS 1.3, group 29) + synthetic TLS 1.2 (ECDHE-RSA). |
| FP / FN risk | Very low. An unknown suite code must yield `AMBIGUOUS`, never a guess. |
| Security risk | Misreporting KEX would mislead a FS claim — mitigated by deriving both from one audited table. |
| Synthetic sufficient? | No — real captures already exercise the TLS 1.3 path. Both are used. |
| **Disposition** | **IMPLEMENT** |

### D-17 — *"Forward Secrecy assessment."*

| | |
|---|---|
| Current status | **NOT IMPLEMENTED.** Zero occurrences of `forward`, `ephemeral`, `ECDHE`, `DHE`. |
| Missing capability | derive FS from the negotiated suite and version. |
| Passive observability | **FULL and deterministic.** TLS 1.3 removed static RSA and static DH key exchange entirely (RFC 8446 §1.2, appendix D.5), so **every** TLS 1.3 suite is forward secret by construction. For TLS ≤1.2 the suite name carries the key exchange: `ECDHE_`/`DHE_` ⇒ forward secret; `TLS_RSA_` ⇒ not. |
| Architectural support | Present. Same derivation point as D-09. |
| Complexity | Low, and it shares the table with D-09. |
| FP / FN risk | Low. Unknown suite ⇒ `AMBIGUOUS`. A resumed session without a visible ServerHello ⇒ `UNKNOWN`, not "no FS". |
| Security risk | **Real:** declaring "no forward secrecy" from an unobserved handshake would be a false negative about a real security property. Guarded by requiring an observed ServerHello. |
| **Disposition** | **IMPLEMENT** |

### D-10 — *"Extraction of X.509 certificates."*

| | |
|---|---|
| Current status | **NOT IMPLEMENTED.** `SEC-TLS-003` reports the observability boundary and nothing is extracted. |
| Passive observability | **CONDITIONAL.** TLS ≤1.2: full (38 fields measured). TLS 1.3: **none** — encrypted per RFC 8446 §2. Resumed sessions: none. Truncated capture: partial. |
| Required inputs | A cleartext `Certificate` handshake message. |
| Architectural support | Present — tshark already decodes it; `-T ek` already emits it; only field mapping and an evidence carrier are missing. |
| Complexity | Medium. Chain ordering, multiple certificates, multiple streams. |
| Validation | Synthetic TLS 1.2 corpus required — the real corpus cannot exercise it. |
| FP / FN risk | FN is inherent and must be disclosed: absence of a certificate is **not** absence of a certificate on the wire. |
| Violates passive scope? | No. |
| **Disposition** | **IMPLEMENT (conditional)** — extraction where visible, `NOT_OBSERVABLE` otherwise. |

### D-12 — *"Certificate expiration analysis."* · D-13 — *"Public key algorithm and key length analysis."* · D-14 — *"Digital signature algorithm identification."*

Same observability profile as D-10 and the same disposition. Measured field evidence:

| Requirement | tshark field measured | Example value |
|---|---|---|
| D-12 expiry | `x509af_x509af_utcTime` (notBefore/notAfter) | `2026-09-21 20:04:26 (UTC)` |
| D-13 key alg + length | `pkixalgs_pkixalgs_modulus`, `pkixalgs_pkixalgs_publicExponent` | modulus present, exponent `65537` |
| D-14 signature alg | `x509af_x509af_algorithm_id` | `1.2.840.113549.1.1.11` (sha256WithRSAEncryption) |

**Disposition for D-12, D-13, D-14: IMPLEMENT (conditional).**

D-12 carries a specific hazard: expiry is a comparison against a reference time. The only
defensible reference is the **capture timestamp**, not the analyst's clock. Comparing a 2019
capture against today would manufacture "expired" findings. This is a **DESIGN DECISION**
recorded in doc 05.

### D-11 — *"Certificate chain validation."*

| | |
|---|---|
| Current status | **NOT IMPLEMENTED.** |
| Passive observability | **SPLIT, and this split is the whole answer.** *Structure* is observable when the chain is in cleartext: order, count, issuer↔subject linkage, `basicConstraints cA`, Authority/Subject Key Identifiers, self-signed detection (issuer == subject and AKI == SKI). *Trust* is **not** observable: it requires a trust store the PCAP does not contain. *Revocation* is **not** observable: OCSP/CRL are separate network transactions. |
| Required external material | A root trust store (for trust) and live OCSP/CRL (for revocation). Neither is in a PCAP. |
| Violates passive scope? | Trust and revocation validation would. Structural validation would not. |
| FP risk | **High if misframed.** Calling a chain "invalid" because an intermediate was not captured, or because we hold no trust anchor, would be a fabricated security claim. |
| **Disposition** | **PARTIAL — implement structural chain analysis; report trust and revocation as `NOT_OBSERVABLE` with an explicit statement of what would be required.** |

### D-16 — *"Identification of insecure protocol configurations."*

| | |
|---|---|
| Current status | **PARTIAL, undeclared.** Eight rules already identify insecure configurations: deprecated TLS version, plaintext authentication, absent transport protection, STARTTLS upgrade failure. What is missing is (a) a *declared bounded checklist* so the requirement can be assessed rather than gestured at, and (b) the configuration facts D-09/D-13/D-14/D-17 unlock. |
| Open ambiguity | AMB-06 (recorded in doc 19) — the PS does not enumerate which configurations count. |
| **Disposition** | **IMPLEMENT** as an explicit, versioned checklist bound to the new evidence, extending the existing rule set rather than adding a parallel engine. |

### A-02 — *"AI-assisted anomaly detection for suspicious TLS sessions."*

| | |
|---|---|
| Current status | **PARTIAL.** Capability shipped and evaluated; ADR-0015 records **zero unique true detections on every held-out split**. |
| Existing evidence | Leakage-controlled bake-off, generator- and scenario-held-out splits, feature space 98.6 % separable by generator. |
| What Phase 11 could change | New *certificate-derived* and key-exchange features become available for the first time. Whether they add **independent** detection value is an empirical question, assessed in doc 04. |
| Hard rule | If no genuine value is demonstrated, **A-02 stays PARTIAL**. A negative result is a valid scientific outcome and will be reported as one. |
| **Disposition** | **RE-EVALUATE** (doc 04). Status unchanged unless evidence earns the change. |

---

## 3. Summary

| Req | Observable passively? | Disposition |
|---|---|---|
| D-09 key exchange | Yes, fully | IMPLEMENT |
| D-10 certificate extraction | TLS ≤1.2 only | IMPLEMENT (conditional) |
| D-11 chain validation | structure yes · trust no · revocation no | PARTIAL by necessity |
| D-12 expiry | TLS ≤1.2 only | IMPLEMENT (conditional) |
| D-13 key alg + length | TLS ≤1.2 only | IMPLEMENT (conditional) |
| D-14 signature algorithm | TLS ≤1.2 only | IMPLEMENT (conditional) |
| D-16 insecure configuration | Yes | IMPLEMENT (bounded checklist) |
| D-17 forward secrecy | Yes, deterministically | IMPLEMENT |
| A-02 anomaly detection | n/a | RE-EVALUATE; PARTIAL unless earned |

**UNRESOLVED (carried to doc 03):** the real corpus contains no TLS 1.2 traffic, so the
certificate family can only be validated against captures generated in this phase. That is a
genuine limitation of the evidence base and will be stated in the traceability entry rather
than papered over.
