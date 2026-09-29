# Phase 11 — 06. Final audit

**Date:** 2026-09-22 · **Branch:** `phase/11-requirement-closure`
**Base:** `v0.5.0-phase10` = `2d5594a8` · **Commits:** 13 · **Tests:** 1219 collected

---

## 1. Requirement closure

| Req | PS wording (verbatim) | Before | After |
|---|---|---|---|
| D-09 | *"Identification of key exchange mechanisms."* | ✗ | **✅ COMPLETE** |
| D-10 | *"Extraction of X.509 certificates."* | ✗ | **✅ where observable** |
| D-11 | *"Certificate chain validation."* | ✗ | **🟡 PARTIAL — not fully observable from passive PCAP alone** |
| D-12 | *"Certificate expiration analysis."* | ✗ | **✅ where observable** |
| D-13 | *"Public key algorithm and key length analysis."* | ✗ | **✅ where observable** |
| D-14 | *"Digital signature algorithm identification."* | ✗ | **✅ where observable** |
| D-16 | *"Identification of insecure protocol configurations."* | partial | **✅ bounded checklist** |
| D-17 | *"Forward Secrecy assessment."* | ✗ | **✅ COMPLETE** |
| A-02 | *"AI-assisted anomaly detection for suspicious TLS sessions."* | 🟡 | **🟡 unchanged — earned** |

**Seven requirements closed. One closed PARTIAL by necessity. One deliberately not moved.**

---

## 2. The two honest non-closures

### D-11 closes PARTIAL — not fully observable from passive PCAP alone

RFC 5280 §6 defines path validation over **trust anchors**. A PCAP contains none, so trust
cannot be established **from the capture alone**. This is a scope statement about passive
evidence, not a claim of permanent impossibility: supplying an operator-chosen trust store
would change the answer, and that option is exactly what **OQ-04** keeps open. The three
substitutes were considered and rejected (ADR-0023); bundling a public root store would mark
legitimate private-CA mail infrastructure "untrusted" — a systematic false positive on exactly
the population the PS targets. **OQ-04 remains open and is the explicit reason.**

SecureMailScope delivers chain *structure* and says, in the finding text, that trust and
revocation were not evaluated and what would be required. Tests assert no trust or revocation
verdict is ever emitted.

### A-02 stays PARTIAL

The decision rule was fixed **before** the evaluation ran. Measuring all 46 captures the
project holds:

- forward secrecy is `True` in 31 sessions and `False` in **zero** — a constant carries no
  information;
- certificate evidence exists in **1 of 46** captures;
- key exchange **fingerprints the generator** — genB and genC use disjoint suite sets, so the
  feature would worsen the 98.6 % leak ADR-0015 identified.

No bake-off was run, because training on a constant, a single sample and a generator signature
produces a number that is meaningless or favourable for the wrong reason. A test asserts no
Phase-11 change touches `ml/`.

---

## 3. Invariants verified

| Invariant | Result |
|---|---|
| `main` untouched | `2fd5f093…` unchanged |
| All five historical tags unmoved | verified byte-for-byte |
| `v0.6.0-phase11` **not** created | confirmed absent |
| No history rewritten, no force-push | commits appended to the branch only; base commit is an ancestor of HEAD |
| Core package zero-runtime-dependency | no third-party module imported by `crypto/`, `analysis/`, `session/`, `posture/` |
| Python 3.9 compatible | all new modules parse under 3.9 grammar |
| `PostureAssessment` remains the single truth | no downstream layer recomputes; reporting and dashboard needed **no changes** to surface the new findings |
| No wall-clock read in the certificate path | `datetime.now`/`time.time`/`utcnow` absent from `crypto/` and the certificate rules |
| Assessment identity deterministic | same PCAP → same `assessment_id` across independent runs |
| Six evidence states never collapsed | absence is `NOT_OBSERVABLE`/`UNKNOWN`, never a verdict |
| ML lane untouched | asserted structurally |
| Evidence contract untouched | asserted structurally |
| Hostile PCAP text inert | escaped in HTML; no `innerHTML`/`eval`/`document.write` anywhere |

---

## 4. Regression: nothing was re-rated

All ten real OQ-33r captures score **exactly** what they scored at `v0.5.0-phase10` — measured
by checking out the tag and running it, then recording the numbers, so the baseline is observed
rather than asserted.

| Capture | Phase 10 | Phase 11 |
|---|---|---|
| dovecot_imap_imaps_implicit_tls | STRONG 100.0 | STRONG 100.0 |
| dovecot_imap_plaintext_login | WEAK 60.0 | WEAK 60.0 |
| dovecot_imap_starttls_upgrade | ADEQUATE 88.0 | ADEQUATE 88.0 |
| dovecot_pop3_plaintext_login | WEAK 60.0 | WEAK 60.0 |
| dovecot_pop3_pop3s_implicit_tls | STRONG 100.0 | STRONG 100.0 |
| dovecot_pop3_stls_upgrade | STRONG 100.0 | STRONG 100.0 |
| postfix_smtp_client_declines | ADEQUATE 88.0 | ADEQUATE 88.0 |
| postfix_smtp_no_starttls_offered | ADEQUATE 85.0 | ADEQUATE 85.0 |
| postfix_smtp_plaintext_session | ADEQUATE 88.0 | ADEQUATE 88.0 |
| postfix_smtp_starttls_upgrade | ADEQUATE 88.0 | ADEQUATE 88.0 |

Every new finding on real traffic is INFO or COMPLIANT — not because the rules are toothless,
but because modern Postfix and Dovecot are correctly configured. The generated TLS 1.2 captures
show the rules firing: **100.0 STRONG** for a healthy chain, **88.0 ADEQUATE** for a self-signed
leaf, **44.0 CRITICAL** for RSA-1024 + SHA-1.

---

## 5. Defects found and fixed during this phase

Recorded because each was a real risk, not a tidy-up.

| # | Defect | Class | Resolution |
|---|---|---|---|
| 1 | `X509_NOT_AFTER` pointed at a `_1`-suffixed key tshark does not emit, falling through to the ASN.1 CHOICE selector `"0"` — expiry would have been computed from the string `"0"` | (A) production defect, latent | read the ordered `utcTime` list; pairing rule guarded and tested |
| 2 | Subject/issuer were claimed by reading the first and last DN component. Measured output is `[CN, O, CN, O]`, so the code reported `issuer = "SecureMailScope Probe"` — an Organization component | **(A) fabrication** | claim removed; identity reported only from `subjectAltName` |
| 3 | SAN entries index-paired across a chain. A leaf with two SANs in a two-certificate chain gave `len(san) == count` by coincidence, crediting the root CA — which has no SAN — with the leaf's second name | **(A) false attribution** | SANs attributed only for a single-certificate chain; matching cardinality is not correspondence |
| 4 | `signedCertificate_element` used as the count anchor; it is a bare `null` for one certificate, so its length is 0 exactly when one certificate is present | (A) production defect | serial numbers anchor the count (mandatory, one per certificate) |
| 5 | `EvidenceRef` dropped `Provenance`, so doc 01A's non-negotiable provenance rule survived only in prose | (A) contract gap | provenance carried and serialised on every evidence reference |
| 6 | `FORWARD_SECRECY_ABSENT` rendered as *"Forward secrecy absent"* on sessions that **have** forward secrecy | (A) misleading output | issue classes named for the dimension, not the verdict |
| 7 | `SEC-TLS-003` limitation *"certificate extraction is not implemented in this phase"* became false | (C) stale contract | rule **narrowed** to the trust/revocation boundary, id and IssueClass preserved |

### Two corrections to my own analysis

Recorded rather than deleted, because a confident correction of a correct statement is the
failure mode this project guards against.

1. An intermediate draft "corrected" the `notBefore`/`notAfter` field map by preferring the
   semantic keys. That correction was **wrong**: those keys are CHOICE selectors, not dates.
   The original positional reading was right.
2. Two of four hardcoded timestamp expectations in a new test were a day out; the hand-rolled
   parser was correct. The test now derives expectations from `calendar.timegm`, checking
   against an independent implementation rather than my arithmetic.

### Tests re-pointed, never weakened

Six assertions failed against deliberate changes. Each was classified and re-pointed to assert
the underlying property, and **strengthened while being touched**:

- four matched the engine's own denials — "untrusted" inside *"is not evidence of an absent,
  invalid or untrusted certificate"*, "malicious" inside *"not an indication of malicious
  activity"*, "weak" inside *"not treated as a weak one"*. Forbidden terms are now sought only
  in **affirmative** text, with sentence-level negation scope, plus a direct check on
  `conclusion`. Loosening them would have stopped catching the real thing.
- the Phase-7 freeze guard was re-pointed to an explicit ADR-linked allowlist, so an
  *undeclared* edit to a protected package still fails — and it immediately caught one.
- two new guards assert what must **not** move: the ML lane and the evidence contract.

---

## 6. What Phase 11 deliberately did not do

SPF · DKIM · DMARC · DNS security · active probing · OCSP/CRL fetching · Certificate
Transparency lookup · trust-store bundling · session-key decryption · attacker attribution ·
email-content intelligence · blockchain · SOC/SIEM · chatbots · LLM-generated verdicts · any
new runtime dependency · any change to scoring weights or the ML bound.

---

## 7. Open questions

| ID | Status |
|---|---|
| **OQ-04** trust store / enterprise internal CAs | **open** — the explicit reason D-11 is PARTIAL, and the route by which it could later widen |
| **OQ-45** does real multi-vendor traffic change the ML answer | **open, better characterised** — the corpus is 100 % TLS 1.3 and 100 % forward secret, so it cannot discriminate |
| **OQ-58** inherited provenance for TLS 1.2 resumption | deferred — no corpus to validate against |
| **OQ-59** is OCSP stapling visible and usable | **not measured, not claimed** |
| **OQ-60** can real TLS ≤1.2 mail traffic be obtained | open — stated as a limitation, asserted by a test |
| **OQ-61** would a varied-quality TLS 1.2 corpus give the ML lane real variance | deferred — building it would re-create the authorship leak |
| **AMB-06** which configurations count as "insecure" | **closed** — bounded, versioned 7-item checklist |

---

## 8. Release readiness

The branch is complete and self-consistent. **`v0.6.0-phase11` has deliberately not been
created**, no merge to `main` has been made, and no tag has been pushed — those await explicit
human approval.

**Recommended honest framing for review:** SecureMailScope now closes seven further PS
deliverables and reports two as partial *with measured reasons*. The partial results are the
strongest evidence that the rest are trustworthy.
