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
| D-18 feature extraction | evidence→features (obs-aware) | evidence/mlanomaly | 6 | feature-stability | anomaly |
| A-01 risk classification | ✅ deterministic, standards-bound (8 rules) | `analysis/` | 4 ✅ | 38 Phase-4 tests | findings |
| A-02 anomaly detection | **unsupervised ML, deviation features** | mlanomaly | 6–7 | ML suite (leakage/seed/held-out) | anomaly scene |
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
in `rules` (Phase 4) via versioned standards binding. OQ-35 addressed by shipping a real A-02 component
+ the `--no-ai` fallback. No confirmed requirement is unmapped → Phase-11 §36 stop condition not triggered.
