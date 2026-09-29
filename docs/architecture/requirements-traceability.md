# Requirements Traceability

**Status:** Live. **Date:** 2026-09-16 · Maps PS → system → component → implementation phase → test →
demo. Every confirmed PS requirement has a verification path.

Components: `ingest, evidence, sessions, rules, crosssession, mlanomaly, risk, report, dashboard,
analyst_ai` (01 §3). Phases per 35-implementation-roadmap. Regression scenarios per 07 §3.

| PS req | System requirement | Component | Phase | Test | Demo |
|---|---|---|---|---|---|
| D-01 PCAP ingest | hash + tshark ingest | ingest | 2 | unit+integration; malformed/huge (adv) | scene load |
| D-02 protocol ID | SMTP/IMAP/POP3 + implicit-TLS ID | evidence/sessions | 2–3 | P_* regression; non-standard port (adv) | all scenes |
| D-03 TCP reassembly | consume tshark reassembly | evidence | 2 | K_network_cond regression | — |
| D-04 STARTTLS detection | state machine, 3 protocols | sessions | 3 | A/B/J regression | inversion |
| D-05 STARTTLS validation | ✅ SEC-STLS-001/002 (ambiguity preserved) | `analysis/rules/starttls_rules` | 4 ✅ | B/I/J regression | inversion |
| D-06 handshake | TlsHandshake object | evidence | 2 | C regression | honesty |
| D-07 version | `supported_versions` read | evidence | 2 | TLS1.3 golden | honesty |
| D-08 cipher | cipher class map | evidence | 2 | unit | — |
| D-09 key exchange | ✅ **COMPLETE.** SEC-KEX-001. Suite name for TLS ≤1.2; ServerHello `key_share` group for TLS 1.3, which does not encode key exchange in the suite (RFC 8446 §4.2.8). Closed-world table: unknown suite ⇒ AMBIGUOUS, never a guess | `crypto/keyexchange`, `analysis/rules/keyexchange_rules` | 11 ✅ | 43 crypto + rule tests | findings |
| D-10 X.509 extraction | ✅ **COMPLETE where observable.** SEC-CERT-001 extracts the chain from a cleartext handshake, or names the specific reason none is visible (encrypted / not sent / truncated). Provenance `observed` only | `crypto/certificates`, `analysis/rules/certificate_rules` | 11 ✅ | fixture + attribution tests | findings |
| D-11 chain validation | 🟡 **PARTIAL — not fully observable from passive PCAP alone.** SEC-CERT-005 analyses structure — ordering, AKI↔SKI linkage, self-signed detection. **Trust and revocation are NOT_OBSERVABLE**: RFC 5280 §6 path validation needs trust anchors a PCAP does not contain (OQ-04 open), and OCSP/CRL are separate network transactions (RFC 6960). See §Phase 11 | `analysis/rules/certificate_rules` | 11 🟡 | trust/revocation refusal tests | honesty |
| D-12 expiry | ✅ **COMPLETE where observable.** SEC-CERT-002, evaluated against the **capture timestamp, never wall-clock** — a 2019 capture assessed today must not report certificates that were valid then as expired, and a wall-clock read would break content-addressed `assessment_id` | `analysis/rules/certificate_rules` | 11 ✅ | wall-clock + determinism tests | findings |
| D-13 key algorithm/length | ✅ **COMPLETE where observable.** SEC-CERT-003. Length derived from the modulus with ASN.1 sign padding stripped; NIST SP 800-57 Pt.1 Rev.5 minimum 2048 | `crypto/certificates` | 11 ✅ | key-length maths tests | findings |
| D-14 signature algorithm | ✅ **COMPLETE where observable.** SEC-CERT-004, OID → algorithm with RFC 9155 / NIST SP 800-131A deprecation. Unknown OID ⇒ unidentified, never weak | `crypto/oids` | 11 ✅ | OID + SHA-1 fixture tests | findings |
| D-15 weak/deprecated | ✅ SEC-TLS-001 bound to RFC 8996 + NIST SP 800-52r2 | `analysis/rules/tls_rules` | 4 ✅ | T_TLS10/11/12 golden | findings |
| D-16 insecure config | ✅ **COMPLETE, bounded.** SEC-CFG-001 evaluates a declared, versioned 7-item checklist (closes AMB-06). Items without evidence return NOT_OBSERVABLE, never "pass". Delegates to the dedicated rules rather than re-emitting findings, so fusion recurrence is not inflated | `analysis/rules/configuration_rules` | 11 ✅ | checklist coverage tests | findings |
| D-17 forward secrecy | ✅ **COMPLETE.** SEC-FS-001. TLS 1.3 ⇒ INFERRED True (RFC 8446 §1.2, App. D.5 removed static RSA/DH); TLS ≤1.2 from the suite. **Never False from an unobserved handshake** — static ECDH is distinguished from ephemeral ECDHE, which OpenSSL's own `Kx` column conflates | `crypto/keyexchange`, `analysis/rules/keyexchange_rules` | 11 ✅ | ECDH-vs-ECDHE + absent-evidence tests | findings |
| D-18 feature extraction | ✅ 44 governed, evidence-aware features → 164 columns (schema v1.0) | `ml/features`, `ml/encoding` | 6 ✅ | 23 feature tests | anomaly |
| A-01 risk classification | ✅ **COMPLETE.** 11 standards-bound rules + Phase-7 classification into 6 evidence-supported dimensions, with scope, recurrence and certainty | `analysis/`, `posture/risk` | 4 ✅ / 7 ✅ | 38 Phase-4 + 133 Phase-7 tests | findings |
| A-02 anomaly detection | 🟡 **capability ✅ / detection value ❌.** Real unsupervised model shipped, evaluated on generator-held-out data, reproducible and explainable — but **0 unique true detections on every held-out split**, so it ships as a *prioritisation signal only* (ADR-0015, doc 17) | `crosssession/` + `ml/` | 5 ✅ / 6 ✅ | 44 Phase-5 + 89 Phase-6 tests | anomaly scene (limitation stated) |
| A-03 posture scoring | ✅ **COMPLETE.** F2-group-damped, selected over two alternatives on 60 captures (ADR-0016); decomposable, duplicate-resistant, never rewards missing evidence | `posture/scoring` | 7 ✅ | score review + monotonicity/duplicate/coverage tests | honesty (coverage) |
| A-04 prioritisation | ✅ **COMPLETE.** Six deterministic factors per issue group; ML nudge bounded at 4.0 vs a 30-point tier gap so it cannot cross a severity tier | `posture/prioritise` | 7 ✅ | tier-integrity + monotonicity tests | findings |
| A-05 remediation | ✅ **COMPLETE** for implemented issue classes. Six rule-bound templates: observed, why, action, scope, verification, citations, limitations. No generic fallback; non-actionable classes listed explicitly | `posture/remediation` | 7 ✅ | remediation-mapping + hostile-text tests | remediation |
| R-01 prioritised findings | ✅ **COMPLETE.** `PostureAssessment.prioritised`, one ranked entry per issue group with affected-session scope | `posture/engine` | 7 ✅ | ordering tests | findings |
| R-02 posture assessment | ✅ **COMPLETE.** Canonical `PostureAssessment` with score, coverage, groups, abstentions, protocol posture, standards, remediation, provenance, limitations | `posture/model` | 7 ✅ | corpus + serialisation tests | honesty |
| R-03 JSON/PDF/HTML | ✅ **COMPLETE.** All three formats retrievable over HTTP. JSON byte-equal to the assessment endpoint; HTML standalone and offline; PDF real, paginated, text-extractable. Semantic equivalence across formats asserted | `posture/model` → `reporting/` → backend/api | 7 / 8 / 9 ✅ | cross-format equivalence + XSS + PDF-validity tests | export |
| R-04 dashboard | ✅ **COMPLETE.** Four analyst screens — History, Overview, Findings, Evidence — over the canonical assessment. Interactive navigation, 8 schema-verified filter facets, all 9 lifecycle states, report actions. Zero npm dependencies. Validated against 7 real captures with cross-surface agreement against HTML/PDF/JSON | `dashboard/` → backend API | 10 ✅ | 423 tests incl. real-PCAP, 125-case security matrix, browser visual QA | all scenes |
| R-05 forensic reports | ✅ **COMPLETE.** Rendered artefact carries capture SHA-256, assessment/run ids, analysis timestamp, engine and schema versions, frame references, standards basis, coverage, abstentions with resolution paths, limitations and ML role. Content-addressed by `report_sha256`, integrity-verified on access | `posture/engine` → `reporting/service` | 7 / 8 / 9 ✅ | integrity, tamper-detection and provenance tests | export |
| I-02 passive | no active/keys in core | (arch invariant) | all | scope test | — |
| I-03 forensic integrity | hash, versions, frame refs | ingest/report | 1,9 | reproducibility (04 §4) | load (hash shown) |

**Coverage:** every confirmed D/A/R requirement has a component, phase, and test. AMB-04/05/06 resolve
in `rules` (Phase 4) via versioned standards binding. No confirmed requirement is unmapped → Phase-11
§36 stop condition not triggered.

### A-02 after Phase 6 — read this before quoting the status

OQ-35 asked whether deterministic cross-session deviation could satisfy a requirement whose text says
*"Application of AI/ML techniques"*. Phase 6 answers it by building the real thing rather than arguing
the interpretation. The distinction the brief demands (§38) is therefore:

| Claim | Status |
|---|---|
| **AI/ML capability exists** | ✅ unsupervised anomaly model, fitted, thresholded on held-out validation data, integrated, explainable, reproducible, 89 tests |
| **AI/ML is empirically validated as a detector** | ❌ **no.** Zero unique true detections on SELECT, TEST_C and TEST_A |
| **AI/ML adds a usable prioritisation signal** | 🟡 ranks better than every gated alternative, but changes no verdict on the current corpus |

The blocker is the corpus, not the model: the feature space is 98.6 % separable by generator
(doc 17 §10), so the question cannot be settled on synthetic data at all. See OQ-45 / OQ-33r.

**Do not report A-02 as complete.** An ML library being installed, or a model producing scores, is
not the bar.

### Phase 7 status (2026-09-20)

A-01, A-03, A-04, A-05, R-01 and R-02 are **COMPLETE** — each has an implementation, an end-to-end
test over real captures, and documented limitations. They are marked complete because behaviour was
demonstrated, not because a data structure exists:

| Req | Demonstrated by |
|---|---|
| A-01 | 11 rules classified into 6 dimensions; risk summary asserted on OQ-28 and both Phase-6 generators |
| A-03 | score decomposability, monotonicity, duplicate resistance (delta 0.0) and the missing-evidence guard, all asserted; formula selected over two alternatives on 60 captures |
| A-04 | tier integrity asserted arithmetically (ML ceiling 4.0 < tier gap 30); priority monotonic in recurrence |
| A-05 | remediation traced to a citation on a real capture; hostile packet text proven unable to reach an action |
| R-01/R-02 | canonical assessment serialised and asserted over 19 real captures |

**A-02 is unchanged by Phase 7** and remains capability-yes / detection-value-no. The posture layer
consumes the ML signal as bounded prioritisation metadata only, and attaches the ADR-0015 limitation
to every AI-enabled assessment.

**Phase-7 hardening (2026-09-20)** did not change any requirement status. It fixed two
Phase-3 correctness defects (OQ-46, OQ-47) and added the first real-vendor validation
(OQ-33r, PASS WITH LIMITATIONS). Two requirements gained real-traffic evidence rather
than a new status:

| Req | New evidence |
|---|---|
| D-04/D-05 STARTTLS detection and validation | now exercised against real Postfix and Dovecot STARTTLS/STLS, including a server that genuinely does not advertise (correctly `AMBIGUOUS`) |
| D-07 TLS version | `supported_versions` handling validated against real OpenSSL TLS 1.3 handshakes for the first time |

**A-02 is unchanged.** The real-vendor corpus is far too small to revisit ML
generalisation, and no ML claim rests on it.

**Still incomplete:** D-09 (key exchange, no dedicated rule), D-10-14 (X.509, not implemented),
D-16 (bounded subset), D-17 (forward secrecy, derivable but no rule), R-03 and R-04 (Phase 9-10).
*(Superseded below: R-03 completed by Phase 9; R-04 completed by Phase 10.)*

---

## Phase 8 (2026-09-21) — backend, persistence, API

Phase 8 advances **delivery**, not detection. It adds no rule, no detection and no
security capability, so **no A- or D- requirement changes status**. Two R-requirements
gained delivery evidence while remaining PARTIAL:

| Req | Change | Evidence |
|---|---|---|
| R-03 JSON/PDF/HTML | **Still PARTIAL.** JSON is now retrievable over HTTP (`GET /api/v1/analyses/{run_id}/assessment`) and durably persisted, not only available in-process via `to_dict()`. PDF and HTML remain unimplemented, so the requirement is **not** satisfied | `test_assessment_is_the_canonical_document_verbatim`, `test_full_cycle` |
| R-05 forensic reports | **Still PARTIAL.** Provenance now survives storage and retrieval, and the chain PCAP → SHA-256 → `capture_id` → `assessment_id` is verified end to end with integrity re-checking. No rendered artefact exists, so the requirement is **not** satisfied | `test_capture_id_is_sha256_of_stored_artifact`, `test_document_round_trip_preserves_evidence_nuance`, `test_tampered_artifact_is_detected` |

**Explicitly not claimed.** An API endpoint returning a document is not a report.
R-03 and R-04 stay Phase 9-10 work. A-02 is unchanged: Phase 8 neither exercises nor
evaluates the ML lane, it only carries `model_summary` and its stated limitations
through to the client.

**New backend-level evidence** (doc 21 §17): the served assessment equals a direct
engine invocation across every canonical field; `--no-ai` equivalence holds through the
backend and no model is constructed when AI is disabled; an interrupted run is never
reported `COMPLETED`; and no Phase 1-7 source file differs from `v0.2.0-phase7`.

---

## Phase 9 (2026-09-21) — forensic reporting

Phase 9 renders the canonical assessment. It adds no rule and no detection, so **no A-
or D- requirement changes status**. Two R-requirements move to COMPLETE, each on
demonstrated behaviour rather than on the existence of a module:

| Req | Change | Evidence |
|---|---|---|
| R-03 JSON/PDF/HTML | 🟡 PARTIAL → ✅ **COMPLETE** | `test_semantic_equivalence_across_formats` (4 fixtures × 3 formats), `test_json_endpoint_equals_the_assessment_endpoint`, `test_output_is_a_real_pdf`, `test_pages_are_not_blank`, `test_no_external_resources_and_no_script` |
| R-05 forensic reports | 🟡 PARTIAL → ✅ **COMPLETE** | `test_report_sha256_is_the_report_identity`, `test_corrupted_report_is_regenerated_not_served`, `test_required_forensic_content_is_present`, `test_provenance_carries_the_forensic_chain` |

**A-02 is unchanged.** The report displays `model_summary.role` and the ADR-0015
limitations verbatim and makes no claim about ML detection value;
`test_ml_section_never_claims_detection` asserts the report cannot say otherwise.

**Still incomplete after Phase 9:** D-09, D-10–14 (X.509), D-16, D-17, and R-04
(dashboard, Phase 10). *(R-04 completed by Phase 10, below.)*

---

## Phase 10 (2026-09-22) — analyst dashboard

**R-04 moves to COMPLETE.** It is the only status change: Phase 10 adds no detection
capability, so no A- or D- requirement is affected.

| Req | Change | Evidence |
|---|---|---|
| R-04 dashboard | 🟡 → ✅ **COMPLETE** | `test_dashboard_real_pcap.py` (7 real captures, cross-surface agreement, three demo scenes), `test_dashboard_security_matrix.py` (125 cases), `test_dashboard_findings.py` (shipped filter module executed in Node), browser visual QA across 12 scenarios |

Each condition fixed in doc 23 §19 before implementation was met and is evidenced
there. A page existing was explicitly not the bar: the requirement demanded interactive
navigation and filtering, visualisation of posture, coverage, distributions, protocol
posture, findings and provenance, all nine lifecycle states, survival of the hostile
matrix, and validation against a real PCAP through the real API.

**Explicitly unchanged:** A-02 remains capability-yes / detection-value-no. The console
renders `model_summary.role` and the ADR-0015 limitations verbatim and a test asserts no
surface claims detection. D-09, D-10–14, D-16, D-17 are untouched — the dashboard adds
no detection.

**Still incomplete after Phase 10:** D-09 (key exchange, no dedicated rule), D-10–14
(X.509, not implemented), D-16 (bounded subset), D-17 (forward secrecy, derivable but
no rule).

---

## Phase 11 — requirement closure (ADR-0023, ADR-0024)

**Closed:** D-09, D-10, D-12, D-13, D-14, D-16, D-17. **Closed as PARTIAL:** D-11.
**Unchanged:** A-02, still capability-yes / detection-value-no.

Eight new rules (SEC-KEX-001, SEC-FS-001, SEC-CERT-001…005, SEC-CFG-001) on a new pure
`crypto/` package. `RULES_VERSION` 1.0 → 1.1, `analysis.ENGINE_VERSION` 0.4.0 → 0.5.0,
`POSTURE_ENGINE_VERSION` 0.7.0 → 0.8.0. `POSTURE_SCHEMA_VERSION` stays 1.0: only enum
members were added, the document shape is unchanged.

### Why D-11 closes PARTIAL — not fully observable from passive PCAP alone

The PS wording is *"Certificate chain validation."* SecureMailScope validates chain
**structure** and explicitly declines chain **trust**. That is a limit of passive evidence,
not an unfinished feature — and it is a scope statement, not a claim of permanent
impossibility:

* RFC 5280 §6 defines path validation over a set of **trust anchors**. A packet capture
  contains none.
* Bundling a public CA root store was considered and **rejected** (ADR-0023): enterprise
  mail routinely uses private CAs, so validating against Mozilla/system roots would mark
  legitimate internal deployments untrusted — a systematic false positive on exactly the
  population this PS targets. It hides **OQ-04** rather than resolving it.
* Revocation status is separately unavailable from the capture: OCSP (RFC 6960) and CRL
  retrieval are network transactions absent from a mail session. Whether OCSP *stapling*
  carries usable evidence inside a cleartext handshake was **not measured** this phase and
  is recorded as **OQ-59** rather than ruled out.

Every chain finding states this in words. A linked chain is never reported as a trusted
chain, and tests assert that no trust or revocation verdict is ever emitted.

### The evidence limitation, stated rather than hidden

**All ten real OQ-33r captures negotiate TLS 1.3, which encrypts the Certificate message
(RFC 8446 §2), so the real corpus yields zero X.509 fields and cannot exercise D-10–D-14
at all.** Those requirements are validated against three TLS 1.2 captures generated in
this phase (`research/experiments/p11cert/`): a self-signed RSA-2048 leaf, a root+leaf
chain, and an RSA-1024/SHA-1 certificate. This is recorded as **OQ-60**, and a test
asserts the limitation so it cannot quietly stop being true.

### Regression property

All ten real captures score **exactly** what they scored at `v0.5.0-phase10` — measured
against the tag, not assumed. Phase 11 enriches the assessment and re-rates nothing;
every new finding on real traffic is INFO or COMPLIANT.

### A-02 after Phase 11 — read this before quoting the status

**A-02 remains PARTIAL.** It was re-opened honestly, with a decision rule fixed *before*
the evaluation ran (`docs/phase11/03-scope-lock.md` §E-i), and the new features were
measured across all 46 captures the project holds:

* **forward secrecy is constant** — True in 31 sessions, `False` in **zero**;
* **certificate evidence exists in 1 of 46 captures** — the one generated to prove
  extraction works;
* **key exchange fingerprints the generator** — genB and genC use disjoint suite sets,
  so a suite-derived feature separates them perfectly, worsening the 98.6 % generator
  leak ADR-0015 identified.

No bake-off was run, because training on a constant, a single sample and a generator
signature yields a number that is meaningless or favourable for the wrong reason. The new
evidence flows to the **deterministic** rules, where it has demonstrable value, not to the
ML lane — asserted structurally by a test that fails if any Phase-11 change touches `ml/`.

**OQ-45 remains open, better characterised:** the real corpus is 100 % TLS 1.3 and 100 %
forward secret, so it cannot discriminate. Answering it needs real traffic containing
genuinely weak configurations, which modern mail infrastructure encouragingly does not
produce.

**Still incomplete after Phase 11:** D-11 (trust and revocation — not observable from
passive PCAP alone; see above) and A-02 (detection value). Both are honest limitations with
recorded reasons and open questions (OQ-04, OQ-59, OQ-45), not gaps.
