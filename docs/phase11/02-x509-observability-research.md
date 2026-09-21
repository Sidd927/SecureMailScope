# Phase 11 — 02. X.509 observability research

**Date:** 2026-09-22 · **Status:** research gate, measured
**Primary project source:** `docs/research/01A-tls-visibility-validation.md` §4–§5
**Measured evidence:** `research/experiments/p11cert/results/observability.json`

> **This document does not claim new research.** Doc 01A already established the passive
> certificate-visibility matrix. Phase 11's contribution is *measured confirmation at field
> level* with tshark 4.6.8 against actual captures, plus the concrete field inventory needed
> to implement. Where measurement and 01A agree, that is stated as corroboration — not as a
> discovery.

---

## 1. The two questions this gate must answer

### Q1 — Which certificate security properties can SecureMailScope honestly assess from a passive PCAP?

**When a cleartext `Certificate` message is present (TLS ≤1.2, full handshake):**
certificate extraction · validity window (`notBefore`/`notAfter`) · public-key algorithm and
key length · certificate signature algorithm · subject and issuer distinguished names ·
subjectAltName entries · `basicConstraints` CA flag · Subject and Authority Key Identifiers ·
chain *structure* (order, count, issuer↔subject linkage) · self-signed detection.

### Q2 — Which properties require external trust material or active network access and must not be claimed?

**Trust** (requires a root trust store the PCAP does not contain) · **revocation status**
(OCSP and CRL are separate network transactions — RFC 6960) · **hostname/endpoint binding
beyond what the capture shows** · **the server's *current* certificate** (an active probe
yields the certificate at probe time, which is a different claim from the captured session) ·
**anything at all under TLS 1.3** (the Certificate message is encrypted — RFC 8446 §2).

---

## 2. Measured evidence (this phase)

Method: `tshark -r <pcap> -T ek`, full field inventory, no `-e` filter. tshark 4.6.8.
Reproduce with `research/experiments/p11cert/probe.sh`.

| Capture | Handshake types | X.509 fields | `key_share_group` |
|---|---|---:|---|
| synthetic TLS 1.2, self-signed RSA-2048 | CH, SH, **Certificate**, ServerKeyExchange, ServerHelloDone, ClientKeyExchange | **38** | — |
| `postfix_smtp_starttls_upgrade` (real) | CH, SH | **0** | `29` |
| `dovecot_imap_imaps_implicit_tls` (real) | CH, SH | **0** | `29` |
| `dovecot_pop3_stls_upgrade` (real) | CH, SH | **0** | `29` |

**FACT:** all ten real OQ-33r captures negotiate TLS 1.3 (`supported_version` = 772). Zero
X.509 fields is the protocol, not a tooling gap.

### 2.1 Field inventory — what maps to which requirement

Every field below was observed in the synthetic TLS 1.2 capture.

| PS requirement | tshark field(s) | Observed value |
|---|---|---|
| D-10 extraction | `x509af_signedCertificate_element`, `x509af_serialNumber`, `x509af_version` | serial `06:5e:d9:…`, version `2` (= v3) |
| D-12 expiry | `x509af_utcTime` under `notBefore` / `notAfter` | `2026-09-21 20:04:26 (UTC)` |
| D-13 key alg + length | `pkixalgs_modulus`, `pkixalgs_publicExponent` | modulus present, exponent `65537` |
| D-14 signature alg | `x509af_algorithm_id` | `1.2.840.113549.1.1.11` = sha256WithRSAEncryption |
| D-11 chain structure | `x509ce_cA`, `x509ce_keyIdentifier`, `x509ce_SubjectKeyIdentifier`, `x509af_issuer`, `x509af_subject` | `cA = True`, AKI == SKI |
| identity | `x509sat_uTF8String`, `x509ce_dNSName` | CN `mail.example.test`, SAN `mail.example.test` |

**INFERENCE:** self-signed is detectable structurally — issuer DN equals subject DN **and**
Authority Key Identifier equals Subject Key Identifier. That is a *structural* observation,
not a trust verdict.

**OBSERVATION:** key length is not a field. It must be derived from the modulus octet length.
That derivation is arithmetic on observed bytes, not an inference about security.

---

## 3. Visibility matrix (from 01A §4.1, corroborated)

| Scenario | Certificate available? | Corroborated this phase |
|---|---|---|
| TLS 1.0/1.1/1.2 full handshake | ✅ cleartext `Certificate` | ✅ 38 fields measured |
| TLS 1.2 resumed | ❌ abbreviated handshake omits it | not measured |
| TLS 1.2 resumed, full handshake earlier in same capture | ⚠️ **inherited** via cleartext session ID | not measured |
| TLS 1.3 full handshake | ❌ encrypted (RFC 8446 §2) | ✅ 0 fields, 10/10 real captures |
| TLS 1.3 PSK resumption | ❌ not sent at all | not measured |
| TLS 1.3 + ECH | ❌ and SNI concealed too | not measured |
| Truncated / mid-stream | ❌ — **must be reported as truncation, not absence** | not measured |

---

## 4. The provenance rule — inherited from 01A, non-negotiable

01A §4.1 establishes, and Phase 11 adopts unchanged:

> Every certificate finding must carry its provenance: `observed`, `inherited`, `historical`,
> `actively-retrieved`, or `decrypted`. A tool that presents an actively retrieved certificate
> as if it were passively observed is making a false forensic claim.

**DESIGN DECISION (Phase 11):** only **`observed`** is in scope. `inherited` is deferred
(needs TLS 1.2 resumption evidence the corpus lacks); `historical`, `actively-retrieved` and
`decrypted` are out of scope entirely — the last two would break I-02 (passive) and the
offline assumption.

---

## 5. Why trust validation stays out

RFC 5280 §6 defines certification path validation as an algorithm over a set of **trust
anchors**. A PCAP contains no trust anchors. Three candidate substitutes were considered and
all rejected:

| Candidate | Rejected because |
|---|---|
| Bundle a public CA root store | Enterprise mail infrastructure routinely uses private CAs. Validating against Mozilla/system roots would mark legitimate internal deployments "untrusted" — a systematic false positive on exactly the target population. |
| Treat the captured chain as self-contained | Circular: it validates the chain against itself and can only ever say "the issuer signed the leaf", which is a structural fact already reported without calling it trust. |
| Ask the analyst for a trust store | Defensible in principle, but it makes the verdict a function of operator-supplied material, and Phase 11 has no corpus to validate that path. **Recorded as OQ-04, still open.** |

**FACT:** revocation is separately impossible. OCSP (RFC 6960) and CRL fetches are network
transactions that do not appear in a mail-session PCAP. OCSP *stapling* would be visible in a
cleartext handshake — **UNRESOLVED:** not measured this phase, and not claimed.

**Consequence:** D-11 can honestly deliver *chain structure analysis*. It cannot deliver
*chain trust validation*, and the finding must say so in those words.

---

## 6. The expiry hazard

**DESIGN DECISION.** Expiry is a comparison against a reference instant. 01A §5 already
specifies: *"Evaluate against capture timestamp, never wall-clock."*

Comparing a 2019 capture against today's date would manufacture "expired certificate"
findings for certificates that were entirely valid when the traffic was recorded. A forensic
tool reports what was true at capture time. The capture timestamp is itself observed evidence
(frame time); the analyst's clock is not evidence at all.

---

## 7. Extraction feasibility — no new dependency

**FACT:** tshark 4.6.8 already decodes the full X.509 structure under `-T ek`, which the
pipeline already requests with no `-e` field filter. Nothing new is required to *reach* the
data — only field mapping and an evidence carrier.

| Alternative considered | Verdict |
|---|---|
| **tshark (existing)** | **Selected.** Already a hard dependency (ADR-0001); already decoding these fields; no install, licence or offline cost. |
| `cryptography` / `pyOpenSSL` on extracted DER | Rejected for now: adds a runtime dependency to a zero-dependency core for data tshark already decodes. Would only be justified if DER-level parsing proved necessary (e.g. full chain reconstruction across segments). |
| `openssl` CLI | Rejected: a runtime subprocess dependency beyond tshark, for no additional field. |

**CORRECTION (measured 2026-09-22, after the first draft of this document).** An earlier draft
recorded a limitation that `notBefore` and `notAfter` could only be told apart by ordering.
That was wrong: tshark emits them as **distinct keys**, `x509af_x509af_notBefore` and
`x509af_x509af_notAfter`, alongside the raw `x509af_x509af_utcTime` values. No ordering
heuristic is needed. The erroneous claim is recorded here rather than deleted, because it was
briefly load-bearing for the D-12 design.

**Counting note.** "38" throughout this document means **38 distinct X.509 field names**. The
same capture yields **64 field occurrences** (one field can appear in several records). Both
figures are correct; they measure different things, and the distinct-name count is the one
that matters for field mapping.

---

## 8. What this gate establishes

1. D-09 and D-17 are **fully** passively observable at every TLS version. *(corroborates 01A)*
2. D-10, D-12, D-13, D-14 are observable **only** in a cleartext handshake — TLS ≤1.2, full,
   untruncated. *(corroborates 01A; measured at field level this phase)*
3. D-11 splits: structure observable, **trust and revocation not**.
4. No new dependency is needed.
5. The existing real corpus **cannot** validate the certificate family — it is entirely
   TLS 1.3. A synthetic TLS 1.2 corpus is required, and that limitation must be stated in the
   traceability entry rather than hidden.
