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
| D-09 key exchange | KEX/named-group | evidence | 2 | unit | — |
| D-10–14 X.509 | ⚠️ **NOT implemented**; SEC-TLS-003 reports NOT_OBSERVABLE with the boundary stated | `analysis/rules/tls_rules` | 4 ⚠️ | cert-boundary test | honesty |
| D-15 weak/deprecated | ✅ SEC-TLS-001 bound to RFC 8996 + NIST SP 800-52r2 | `analysis/rules/tls_rules` | 4 ✅ | T_TLS10/11/12 golden | findings |
| D-16 insecure config | bounded versioned checklist | rules | 4 | unit per rule | findings |
| D-17 forward secrecy | derive from suite/version | evidence/rules | 4 | unit | findings |
| D-18 feature extraction | ✅ 44 governed, evidence-aware features → 164 columns (schema v1.0) | `ml/features`, `ml/encoding` | 6 ✅ | 23 feature tests | anomaly |
| A-01 risk classification | ✅ **COMPLETE.** 11 standards-bound rules + Phase-7 classification into 6 evidence-supported dimensions, with scope, recurrence and certainty | `analysis/`, `posture/risk` | 4 ✅ / 7 ✅ | 38 Phase-4 + 133 Phase-7 tests | findings |
| A-02 anomaly detection | 🟡 **capability ✅ / detection value ❌.** Real unsupervised model shipped, evaluated on generator-held-out data, reproducible and explainable — but **0 unique true detections on every held-out split**, so it ships as a *prioritisation signal only* (ADR-0015, doc 17) | `crosssession/` + `ml/` | 5 ✅ / 6 ✅ | 44 Phase-5 + 89 Phase-6 tests | anomaly scene (limitation stated) |
| A-03 posture scoring | ✅ **COMPLETE.** F2-group-damped, selected over two alternatives on 60 captures (ADR-0016); decomposable, duplicate-resistant, never rewards missing evidence | `posture/scoring` | 7 ✅ | score review + monotonicity/duplicate/coverage tests | honesty (coverage) |
| A-04 prioritisation | ✅ **COMPLETE.** Six deterministic factors per issue group; ML nudge bounded at 4.0 vs a 30-point tier gap so it cannot cross a severity tier | `posture/prioritise` | 7 ✅ | tier-integrity + monotonicity tests | findings |
| A-05 remediation | ✅ **COMPLETE** for implemented issue classes. Six rule-bound templates: observed, why, action, scope, verification, citations, limitations. No generic fallback; non-actionable classes listed explicitly | `posture/remediation` | 7 ✅ | remediation-mapping + hostile-text tests | remediation |
| R-01 prioritised findings | ✅ **COMPLETE.** `PostureAssessment.prioritised`, one ranked entry per issue group with affected-session scope | `posture/engine` | 7 ✅ | ordering tests | findings |
| R-02 posture assessment | ✅ **COMPLETE.** Canonical `PostureAssessment` with score, coverage, groups, abstentions, protocol posture, standards, remediation, provenance, limitations | `posture/model` | 7 ✅ | corpus + serialisation tests | honesty |
| R-03 JSON/PDF/HTML | 🟡 **PARTIAL.** JSON complete via `to_dict()` on the canonical object; PDF and HTML renderers are Phase 9 | `posture/model` → report | 7 🟡 / 9 | serialisation tests incl. malformed Unicode | export |
| R-04 dashboard | analyst views | dashboard | 10 | e2e smoke | all scenes |
| R-05 forensic reports | 🟡 **PARTIAL.** Provenance, frames, rule ids, standards and all versions carried end to end on the assessment; no rendered artefact yet | `posture/engine` → report | 7 🟡 / 9 | provenance traceability test | export |
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
