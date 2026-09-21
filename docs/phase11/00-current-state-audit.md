# Phase 11 — 00. Current state audit

**Date:** 2026-09-22 · **Base:** `v0.5.0-phase10` = `f8cbc0e` · **Branch:** `phase/11-requirement-closure`
**Environment:** Python 3.9.6 · tshark (Wireshark) 4.6.8 · Node v26.4.0 · OpenSSL 3.6.3 · Docker running
**Tests at base:** 1120 passed, 0 failed, 0 skipped, 0 xfail

> Labels used throughout Phase 11: **FACT** (verified in this repo or by measurement this
> phase), **OBSERVATION** (measured output), **INFERENCE** (reasoned from fact),
> **DESIGN DECISION**, **LIMITATION**, **UNRESOLVED**.

---

## A. Canonical evidence model — FACT

`EvidenceField` (`evidence/states.py`) wraps every value with state + basis + provenance +
frames. Six states, never collapsed:
`OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS · INCOMPLETE · NOT_OBSERVABLE`.
`Capture.capture_id` is the SHA-256 of the analysed bytes.

## B. Session reconstruction — FACT

`session/reconstruct.py` builds `SessionEvidence` per TCP stream via protocol state machines
for SMTP/IMAP/POP3 (`session/protocols.py`). TLS state is derived per stream
(`classify_tls`). Relevant existing TLS fields on `SessionEvidence`:
`tls_state`, `tls_transition`, `tls_negotiated_version`, `tls_cipher_suite`,
`starttls_{advertised,requested,accepted}`.

**OBSERVATION — the cipher suite is recorded, not interpreted.** `negotiated_cipher()`
(`session/base.py:341`) stores the raw ServerHello value as `"0x1302"`. Nothing in the
codebase maps that code to a key-exchange mechanism, an authentication method, or a
forward-secrecy property. Verified by grep: **zero** occurrences of `forward`, `ephemeral`,
`ECDHE`, `DHE`, `key_exchange`, `supported_group` or `named_group` anywhere in
`src/securemailscope/`.

## C. Deterministic rules — FACT

Eight rules, all standards-bound (`analysis/rules/`):

| Rule | Subject |
|---|---|
| `SEC-TLS-001` | deprecated TLS version (RFC 8996, NIST SP 800-52r2) |
| `SEC-TLS-002` | TLS handshake evidence |
| `SEC-TLS-003` | **certificate observability boundary** — reports `NOT_OBSERVABLE` |
| `SEC-STLS-001/002/003` | STARTTLS upgrade failure · advertisement · implicit TLS |
| `SEC-PLAIN-001/002` | plaintext auth exposure · no TLS protection |

## D. Cross-session reasoning — FACT

`crosssession/` builds baselines (≥5 comparable sessions), contrasts, and 3 rules
(`CS-STARTTLS-001/002`, `CS-TLS-001`). **LIMITATION (carried):** never exercised on real
traffic — real captures carry 1–2 sessions.

## E. ML anomaly lane — FACT

`ml/` — 44 governed features → 164 columns (schema v1.0), `robust-z-sum` retained.
ADR-0015 records **Outcome D: zero unique true detections on every held-out split**;
feature space 98.6 % separable by generator. Bounded to `MAX_ML_ADJUSTMENT = 4.0`
against a narrowest tier gap of 30.

## F. Evidence fusion → G. PostureAssessment — FACT

`posture/` fuses the three lanes into the canonical `PostureAssessment`
(`POSTURE_SCHEMA_VERSION = "1.0"`, `POSTURE_ENGINE_VERSION = "0.7.0"`). Scoring is
`F2-group-damped`; only `OBSERVED_ISSUE` penalises; the band is withheld below 50 %
coverage. Three separations are structural: severity / certainty / observability;
base issue / deviation / anomaly; penalising / compliant / abstention.

## H–J. Persistence, reporting, dashboard — FACT

Phase 8 (`backend/`): SQLite catalog storing the assessment as a document, job lifecycle,
content-addressed artifact store, FastAPI `/api/v1`.
Phase 9 (`reporting/`): one `ReportDocument` → HTML (zero-dep) + PDF (ReportLab), byte
deterministic, `report_sha256` identity.
Phase 10 (`dashboard/`): Python projection → view model → zero-dependency ES modules;
History / Overview / Findings / Evidence.

## K. Provenance and integrity — FACT

PCAP SHA-256 → `capture_id` → `assessment_id` (content-addressed) → `report_sha256`.
Artifacts are re-hashed on access. Every finding carries frames, rule id and standard.

## L. Existing real-PCAP validation — FACT

10 captures (OQ-33r): Postfix + Dovecot, SMTP/IMAP/POP3, cleartext / STARTTLS / implicit /
none. Verdict **PASS WITH LIMITATIONS**.

**OBSERVATION (measured this phase, `research/experiments/p11cert/results/observability.json`):
every TLS session in the real corpus negotiates TLS 1.3.** `supported_version` contains
`772`; `key_share_group` is `29` (x25519); handshake types observed are ClientHello and
ServerHello **only**; X.509 field count is **0** in all real captures.

## M. Current requirement coverage — FACT

COMPLETE: D-01…D-08, D-15, D-18, A-01, A-03, A-04, A-05, R-01…R-05.
PARTIAL: A-02 (capability yes / detection value no).
INCOMPLETE: **D-09, D-10, D-11, D-12, D-13, D-14, D-16, D-17**.

## Note on a path in the Phase-11 brief

The brief refers to `docs/requirements-traceability.md`. The file is at
**`docs/architecture/requirements-traceability.md`**; there is no file at the shorter path.
Phase 11 updates the real one.
