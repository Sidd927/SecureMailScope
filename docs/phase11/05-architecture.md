# Phase 11 — 05. Architecture

**Date:** 2026-09-22 · **Binding input:** `03-scope-lock.md`
**Implements:** D-09, D-10, D-11 (partial), D-12, D-13, D-14, D-16, D-17
**Does not touch:** the ML lane (see `04-ai-reassessment.md`)

---

## 1. Where the new work goes, and why

The project already has a strict layering, and Phase 11 does not bend it:

```
dissect/     raw tshark fields          — no interpretation
  ↓
crypto/      NEW: reference data + factual derivation — no security verdicts
  ↓
session/     SessionEvidence            — facts, as EvidenceField
  ↓
analysis/    deterministic rules        — security verdicts
  ↓
posture/     PostureAssessment          — the single canonical truth
```

**DESIGN DECISION — why a new `crypto/` package rather than code inside `analysis/`.**
Mapping suite `0xc030` to "ECDHE key exchange, RSA authentication, AES-256-GCM, SHA-384" is a
*factual lookup*, not a judgement. Deciding that ECDHE is acceptable and static RSA is not
*is* a judgement. The existing architecture puts facts in `session/` and judgements in
`analysis/`, so the lookup table belongs to neither and is shared by both. Putting it in
`analysis/` would mean the session layer imports a rules module to learn a fact, inverting the
dependency.

`crypto/` is pure: no I/O, no network, no randomness, no global mutable state — the same
purity contract `analysis/registry.py` already states for rules.

### Module layout

| Module | Contents |
|---|---|
| `crypto/suites.py` | IANA-derived cipher-suite table → `SuiteProfile(code, name, kex, auth, cipher, mac, is_tls13)` |
| `crypto/oids.py` | OID → algorithm name (signature, public key, named curve) |
| `crypto/keyexchange.py` | derive key-exchange mechanism and forward secrecy (D-09, D-17) |
| `crypto/certificates.py` | `CertificateEvidence` + assembly from dissected fields (D-10…D-14) |

---

## 2. The closed-world table problem

`analysis/rules/tls_rules.py:14-17` deliberately deferred cipher-suite grading:

> *"mapping every IANA suite to a NIST-approved/not-approved verdict needs a maintained table
> we have not built or validated; a half-populated table would silently mislabel unknown
> suites."*

That objection is correct and Phase 11 must answer it, not ignore it.

**DESIGN DECISION.** The table is **explicitly closed-world**. Every lookup returns
`Optional[SuiteProfile]`, and `None` propagates to `EvidenceState.AMBIGUOUS` — never to a
default, a guess, or a "probably fine". The table records its IANA registry snapshot date.
Unknown is a first-class answer, which is exactly what makes a partial table safe.

**FACT:** tshark itself resolves suite names, so the table is not needed to *read* the
capture — only to interpret it offline and deterministically without a new dependency.

---

## 3. D-09 key exchange · D-17 forward secrecy

**The TLS 1.3 subtlety that drives the design.** In TLS ≤1.2 the suite name encodes the key
exchange (`TLS_ECDHE_RSA_WITH_…`). In TLS 1.3 it does **not** — RFC 8446 decoupled them, and
every TLS 1.3 suite is `Kx=any`. The negotiated group comes from the ServerHello `key_share`
extension, measured present as group `29` (x25519) in all ten real captures.

So the derivation has two distinct paths, and conflating them would misreport TLS 1.3:

| Version | Key exchange from | Forward secrecy |
|---|---|---|
| TLS 1.3 | ServerHello `key_share` group | **`INFERRED` True** — RFC 8446 §1.2 and App. D.5 removed static RSA and static DH entirely |
| TLS ≤1.2 | suite name | `OBSERVED` from the suite: `ECDHE_`/`DHE_` ⇒ True, `TLS_RSA_` ⇒ False |
| no ServerHello | — | **`UNKNOWN`** |

**DESIGN DECISION — TLS 1.3 forward secrecy is `INFERRED`, not `OBSERVED`.** The capture does
not show a forward-secrecy property directly; it shows a version, from which the property
follows by the RFC. That is the textbook definition of `INFERRED`, and the evidence model
requires a basis string, which the RFC citation supplies. Marking it `OBSERVED` would be the
small dishonesty the whole evidence model exists to prevent.

**Never:** report "not forward secret" from an unobserved handshake. No ServerHello ⇒
`UNKNOWN`, which is a different claim.

### New `SessionEvidence` fields

```
tls_cipher_suite_name   EvidenceField   # "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
tls_key_exchange        EvidenceField   # "ECDHE" | "DHE" | "RSA" | "PSK"
tls_named_group         EvidenceField   # "x25519" | "secp256r1" | ...
tls_forward_secrecy     EvidenceField   # True | False
tls_certificates        Tuple[CertificateEvidence, ...]
tls_certificate_chain   EvidenceField   # chain observability + provenance
```

The raw `tls_cipher_suite` (`"0x1302"`) is **kept unchanged**. Phase 11 adds the
interpretation beside it rather than replacing the observation — the raw value stays
auditable, and no existing consumer breaks.

---

## 4. D-10…D-14 certificates

### 4.1 Provenance — already supported

`evidence/states.py:42-50` **already defines** the `Provenance` enum with exactly the
vocabulary doc 01A mandates: `OBSERVED`, `INHERITED`, `HISTORICAL`, `RETRIEVED`, `DECRYPTED`,
`NONE`. It was built in Phase 2 in anticipation of this work and has been carried unused ever
since.

**Phase 11 emits only `Provenance.OBSERVED`.** `INHERITED` is deferred (OQ-58); `RETRIEVED`
and `DECRYPTED` are Category D and no code path may produce them.

### 4.2 A latent defect in the existing field map

`dissect/fields.py:44-45` currently reads:

```python
X509_NOT_BEFORE = ("x509af_x509af_utcTime",   "x509af_x509af_notBefore")
X509_NOT_AFTER  = ("x509af_x509af_utcTime_1", "x509af_x509af_notAfter")
```

**This is a real defect — category (A), production defect** — though latent, because no code
read these constants yet. Both lines are wrong, and measurement (doc 02 §7.1) showed the fix is
not the obvious one:

* tshark 4.6.8 emits **no `_1`-suffixed keys at all**, so `X509_NOT_AFTER` fell through to
  `x509af_x509af_notAfter` — which is the ASN.1 **CHOICE selector** (`"0"` = utcTime), not a
  date. Expiry would have been computed from the string `"0"`.
* The dates live in `x509af_x509af_utcTime` as an **ordered list**, two entries per
  certificate: `[leaf.notBefore, leaf.notAfter, issuer.notBefore, issuer.notAfter]`.

An intermediate draft of this document "corrected" the first line by preferring
`x509af_x509af_notBefore`/`notAfter` as semantic keys. That correction was itself wrong, for
the reason above. The record is kept because a confident correction of a correct statement is
exactly the failure mode this project guards against.

**Resolution:** `X509_VALIDITY_UTC` reads the ordered list, and the pairing rule lives in
`crypto/certificates.py` where it is guarded and tested. The ordering dependence is real and
unavoidable — `-T json` decodes no X.509 at all in this build — so it is bounded by the
attribution rule below rather than wished away.

### 4.3 Expiry — the capture timestamp is the reference instant

**DESIGN DECISION (from 01A §5, binding).** `notAfter` is compared against
`SessionEvidence.start_epoch`, never `datetime.now()`.

A 2019 capture assessed today would otherwise produce "expired certificate" findings for
certificates that were entirely valid when the traffic was recorded. The capture timestamp is
itself observed evidence; the analyst's clock is not evidence at all. This also keeps the
assessment **deterministic** — re-running the same PCAP next year must produce the same
`assessment_id`, which a wall-clock comparison would break outright.

That determinism requirement is independent of the honesty requirement, and both point the
same way.

### 4.4 Key length is derived, not read

**FACT:** no tshark field carries RSA key length. It is computed from the modulus octet
length. That is arithmetic on observed bytes, so the result is `OBSERVED`, with the basis
recording the derivation.

### 4.5 Chain structure (D-11)

**The attribution rule (measured, doc 02 §7.2).** EK output is flat: a chain yields one list
per field, not one object per certificate. A value is attributed to a specific certificate
**only** when its list length is exactly *n* or 2*n*; everything else is recorded at chain
level and marked unattributed. Two measurements forced this to be strict:

* `basicConstraints cA` is emitted **only when true**, so a `[leaf CA:FALSE, root CA:TRUE]`
  chain yields a single `true`. Index-pairing would hand the root's CA flag to the leaf.
* A leaf with two SAN entries in a two-certificate chain gives `len(san) == n` by
  coincidence. Index-pairing credited the root CA — which has no SAN at all — with the
  leaf's second name. **Matching cardinality is not evidence of correspondence**, so SANs
  are attributed only for a single-certificate chain.

Observable and implemented: certificate count, ordering, chain linkage, and self-signed
detection — all from **Authority/Subject Key Identifiers** (RFC 5280 §4.2.1.1), which are
index-safe. Self-signed is `AKI == SKI`; the chain link is `cert[i].AKI == cert[i+1].SKI`.

**Distinguished-name text is never used, and subject/issuer identity is not reported at all.**
tshark emits each RDN component as a bare value with no marker for which name it belongs to: a
single self-signed certificate yields `[CN, O, CN, O]`. An implementation that read `[0]` as
the subject and `[-1]` as the issuer reported `issuer = "SecureMailScope Probe"` — an
Organization component, not an issuer identity. Identity is reported from `subjectAltName`,
which is unambiguous.

Not observable and **explicitly reported as such**: trust-anchor validation (RFC 5280 §6
requires anchors a PCAP does not contain — OQ-04 open) and revocation (RFC 6960 OCSP and CRL
are separate network transactions).

---

## 5. Rules

| Rule | Requirement | Emits |
|---|---|---|
| `SEC-KEX-001` | D-09 | key exchange mechanism identified / unknown / ambiguous |
| `SEC-FS-001` | D-17 | forward secrecy present / absent / undetermined |
| `SEC-CERT-001` | D-10 | certificate evidence present, or the **reason** it is not |
| `SEC-CERT-002` | D-12 | validity window vs capture timestamp |
| `SEC-CERT-003` | D-13 | public-key algorithm and length |
| `SEC-CERT-004` | D-14 | signature algorithm, incl. SHA-1/MD5 |
| `SEC-CERT-005` | D-11 | chain structure; trust and revocation `NOT_OBSERVABLE` |
| `SEC-CFG-001` | D-16 | bounded insecure-configuration checklist |

### 5.1 SEC-TLS-003 is narrowed, not deleted

`SEC-TLS-003` currently carries the limitation *"Certificate extraction is not implemented in
this phase."* Phase 11 makes that sentence false, and leaving it would be a lie in the output.

**DESIGN DECISION.** `SEC-TLS-003` is **narrowed** to what remains permanently true: the
*trust and revocation* boundary. Certificate presence and absence move to `SEC-CERT-001`,
which can now state the specific reason — encrypted (TLS 1.3) · not sent (resumption) ·
truncated capture — instead of one flat "not available".

The rule is not removed. Its `rule_id`, `IssueClass` and fusion identity are stable, so
historical assessments remain interpretable. This is a deliberate, versioned narrowing of a
canonical contract, recorded in ADR-0023 — not a silent change.

### 5.2 D-16's bounded checklist

AMB-06 records that the PS does not enumerate which configurations count. Rather than leave the
requirement open-ended, `SEC-CFG-001` evaluates a **declared, versioned list** and reports each
item's outcome explicitly, including the ones that pass:

1. deprecated TLS version negotiated *(delegates to SEC-TLS-001; not re-derived)*
2. non-forward-secret key exchange
3. RSA key shorter than 2048 bits (NIST SP 800-57 Part 1 Rev. 5)
4. SHA-1 or MD5 certificate signature (RFC 9155; NIST SP 800-131A Rev. 2)
5. certificate expired **as at the capture timestamp**
6. certificate not yet valid as at the capture timestamp
7. self-signed leaf certificate presented for a public-facing mail service

**The checklist is closed.** Adding an item is a `RULES_VERSION` bump, not an edit. Items 3–7
return `NOT_OBSERVABLE` when no certificate is visible — never "pass".

**Anti-double-counting.** Item 1 delegates rather than re-deriving, because fusion groups on
`IssueClass`; emitting a second deprecated-version finding would inflate recurrence damping and
change the score for a condition already counted. Items 2–7 map to their own issue classes.

---

## 6. Versioning

| Constant | From | To | Why |
|---|---|---|---|
| `RULES_VERSION` | `1.0` | `1.1` | six new rules; SEC-TLS-003 narrowed |
| `analysis.ENGINE_VERSION` | `0.4.0` | `0.5.0` | new evidence consumed |
| `POSTURE_ENGINE_VERSION` | `0.7.0` | `0.8.0` | new issue classes participate in scoring |
| `POSTURE_SCHEMA_VERSION` | `1.0` | **`1.0`** | document *shape* is unchanged; only enum members are added |

New `IssueClass` members: `KEY_EXCHANGE_MECHANISM`, `FORWARD_SECRECY`,
`CERTIFICATE_EXTRACTION`, `CERTIFICATE_VALIDITY`, `CERTIFICATE_KEY_STRENGTH`,
`CERTIFICATE_SIGNATURE_ALGORITHM`, `CERTIFICATE_CHAIN_STRUCTURE`,
`INSECURE_CONFIGURATION` — mapped to the existing `CERTIFICATE_TRUST` and
`CRYPTO_CONFIGURATION` risk dimensions. No new dimension is invented.

**Named for the dimension, not the verdict.** One issue class carries both the compliant
and the failing finding for its condition, and the dashboard humanises the enum member
into a label. A verdict-shaped name therefore lies half the time: an early draft used
`FORWARD_SECRECY_ABSENT`, which rendered as *"Forward secrecy absent"* on sessions that
have forward secrecy. (`DEPRECATED_TLS_VERSION` has the same wart and is deliberately
left alone — renaming it would change the fusion identity of stored assessments.)

**Scoring weights are not touched.** Phase 11 adds conditions to the existing severity tiers; it
does not re-tune the scale. Changing both the inputs and the scale in one phase would make any
score movement uninterpretable.

---

## 7. Security posture of the new code

All certificate content is attacker-controlled: a subject CN, SAN or issuer DN is whatever the
server put on the wire. Every Phase-10 rule applies unchanged — no `innerHTML`, no
`insertAdjacentHTML`, no `document.write`, no `eval`, no class names built from untrusted
input, no API-controlled executable URLs.

Specific to this phase:

- **Unbounded strings.** DN and SAN values are length-capped at extraction, with truncation
  recorded rather than silent.
- **Certificate count.** A chain is bounded; a capture claiming thousands of certificates is a
  resource-exhaustion vector, so extraction stops at a declared cap and records that it did.
- **Homoglyph / RTL-override in DN text.** Rendered as inert text, never interpreted, and never
  used to construct an identifier.
- **OID values.** Unknown OIDs render as the numeric OID, never as a guessed name.

---

## 8. Forbidden inferences, restated for this phase

| Never turn | Into |
|---|---|
| certificate not visible | certificate invalid |
| no trust anchor available | certificate untrusted |
| chain incomplete in capture | chain broken |
| revocation unknown | certificate revoked |
| unknown cipher suite | weak cipher suite |
| no ServerHello observed | no forward secrecy |
| self-signed | malicious |

Each of these is asserted as a test, not only documented.
