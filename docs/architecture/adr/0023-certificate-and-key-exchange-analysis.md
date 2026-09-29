# ADR-0023 — Certificate and key-exchange analysis ship as conditionally observable evidence
**Status:** Accepted 2026-09-22 · **Closes:** AMB-06 · **Leaves open:** OQ-04, OQ-58, OQ-59, OQ-60

**Context** Phase 11 closes the eight incomplete PS deliverables D-09…D-14, D-16 and D-17.
All of them depend on evidence the project has never extracted: the negotiated key
exchange and the X.509 chain.

**Problem** Five of the eight are certificate-dependent, and a passive capture cannot
always see a certificate. How do we satisfy a PS deliverable whose evidence is sometimes
structurally absent, without either under-delivering or fabricating?

**Evidence** (measured this phase, `research/experiments/p11cert/` and `p11ai/`;
corroborates `docs/research/01A-tls-visibility-validation.md` §4–5)
- All 10 real OQ-33r captures negotiate **TLS 1.3** and yield **zero** X.509 fields.
  RFC 8446 §2 sends Certificate under handshake-traffic keys — this is the protocol, not
  a tooling gap.
- A synthetic TLS 1.2 capture yields **38 distinct X.509 field names** (64 occurrences),
  decoded by the existing tshark dependency with **no new package**: `notBefore`,
  `notAfter`, RSA modulus and exponent, signature OID, SAN `dNSName`,
  `basicConstraints cA`, and Authority/Subject Key Identifiers.
- The negotiated group is present in ServerHello `key_share` (group 29, x25519) in every
  real capture, which is the only TLS 1.3 path to the key exchange — the suite does not
  encode it (`Kx=any`).
- tshark resolves suite names itself, so no new dependency is required to interpret them.

**Decision**
1. A new pure `crypto/` package holds reference data and factual derivation. Security
   *judgement* stays in `analysis/`; the layering (facts in `session/`, verdicts in
   `analysis/`) is preserved.
2. The cipher-suite table is **explicitly closed-world**: a miss returns `None`, which
   becomes `AMBIGUOUS` — never a default and never a guess.
3. Certificate evidence carries `Provenance`, and Phase 11 emits only
   `Provenance.OBSERVED`. The enum already existed unused since Phase 2.
4. Expiry is evaluated against the **capture timestamp**, never wall-clock.
5. D-11 ships **PARTIAL by construction**: chain structure is analysed; trust and
   revocation are reported `NOT_OBSERVABLE` with a statement of what would be required.
6. `SEC-TLS-003` is **narrowed** to the trust/revocation boundary rather than deleted;
   presence and absence move to `SEC-CERT-001`, which reports the specific reason.
7. D-16 is bounded to a declared, versioned seven-item checklist (closing AMB-06).

**Rejected**
- *Bundle a public CA root store.* Enterprise mail routinely uses private CAs; validating
  against Mozilla/system roots would mark legitimate internal deployments untrusted — a
  systematic false positive on exactly the PS's target population. It hides OQ-04 rather
  than resolving it.
- *Active certificate retrieval or OCSP/CRL fetch.* Breaks I-02 (passive), the one
  invariant the PS states in its own words, and answers a different question: the
  certificate *now*, not the certificate in the captured session.
- *Session-key decryption.* Requires material a forensic capture does not carry.
- *Add `cryptography`/`pyOpenSSL` to parse DER.* A runtime dependency in a
  zero-dependency core for data tshark already decodes.
- *Compare `notAfter` against wall-clock.* Manufactures expiry findings for old captures
  and destroys `assessment_id` determinism.
- *Treat an absent certificate as a finding.* The forbidden conversion this project
  exists to prevent.
- *Feed the new features to the ML lane.* Measured to carry no usable information and to
  fingerprint the generator (ADR-0024).

**Consequences** + five certificate-dependent deliverables become real where evidence
allows; + D-09 and D-17 close fully at every TLS version; + AMB-06 closes; + the latent
`X509_NOT_AFTER` ordering defect in `dissect/fields.py` is fixed before it could ever
mis-date a certificate. − D-11 closes **PARTIAL** — not fully observable from passive
PCAP alone — and the traceability entry says so; OQ-04 is the route by which that could
later widen. − the real corpus is 100 % TLS 1.3, so the whole certificate family is validated
only against captures synthesised in this phase (OQ-60). − `RULES_VERSION` 1.0 → 1.1 and
two engine versions move, so assessments across the boundary are not byte-comparable.

**Risks** The reader most likely to be misled is one who sees "Certificate chain
validation: PARTIAL" and assumes trust was checked → every such finding states in words
that no trust anchor exists in a packet capture, and the forbidden inferences
(not visible ↛ invalid, no anchor ↛ untrusted, revocation unknown ↛ revoked) are asserted
as tests rather than only documented.

**Open questions** AMB-06 **closed** (checklist declared and versioned). **OQ-04 remains
open** and is now the explicit reason D-11 is PARTIAL rather than COMPLETE. New: OQ-58
(inherited provenance for TLS 1.2 resumption — deferred, no corpus), OQ-59 (is OCSP
stapling visible and usable? not measured, not claimed), OQ-60 (can real TLS ≤1.2 mail
traffic be obtained to validate this family?).
