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
| A-01 risk classification | ✅ deterministic, standards-bound (8 rules) | `analysis/` | 4 ✅ | 38 Phase-4 tests | findings |
| A-02 anomaly detection | 🟡 **capability ✅ / detection value ❌.** Real unsupervised model shipped, evaluated on generator-held-out data, reproducible and explainable — but **0 unique true detections on every held-out split**, so it ships as a *prioritisation signal only* (ADR-0015, doc 17) | `crosssession/` + `ml/` | 5 ✅ / 6 ✅ | 44 Phase-5 + 89 Phase-6 tests | anomaly scene (limitation stated) |
| A-03 posture scoring | coverage-aware deterministic | risk | 8 | unit | honesty (coverage) |
| A-04 prioritisation | severity×exposure×prevalence; ML via policy | risk | 8 | policy unit | findings |
| A-05 remediation | standards-cited templates | rules/report | 4,9 | unit | remediation |
| R-01 prioritised findings | Finding objects ordered | risk/report | 8–9 | integration | findings |
| R-02 posture assessment | PostureAssessment object | risk | 8 | unit | honesty |
| R-03 JSON/PDF/HTML | one canonical report, 3 renderers | report | 9 | render round-trip; XSS (adv) | export |
| R-04 dashboard | analyst views | dashboard | 10 | e2e smoke | all scenes |
| R-05 forensic reports | provenance + frames + versions | report | 9 | reproducibility | export |
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
