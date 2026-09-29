# 12 — Deterministic Security Analysis (Phase 4)

**Status:** Implemented. **Date:** 2026-09-18 · **ADR:** 0013 · **Code:** `src/securemailscope/analysis/`

    SessionEvidence[]  ->  SecurityAnalysisEngine  ->  SecurityFinding[]

Per-session, deterministic, standards-bound. No cross-session reasoning (Phase 5), no ML
(Phase 6), no reporting/UI. Same evidence + same rules version => same findings.

## Input contract
Consumes Phase-3 `SessionEvidence` only. Phase 4 never re-parses packets, never
reassembles TCP, never rediscovers STARTTLS. Where it needed a fact Phase 3 did not
expose, the fix was a **minimal Phase-3 extension**, not re-parsing — see §Evidence
extension below.

## Three orthogonal axes
Collapsing these is how a forensic tool starts lying, so they are separate fields:

| Axis | Meaning |
|---|---|
| **Severity** | impact *if* the condition holds (INFO/LOW/MEDIUM/HIGH/CRITICAL) |
| **Evidence state** | how well the capture supports it (Phase-3 states, carried verbatim) |
| **FindingStatus** | the analytic outcome |

`FindingStatus` ∈ OBSERVED_ISSUE · COMPLIANT · INFORMATIONAL · AMBIGUOUS ·
INSUFFICIENT_EVIDENCE · NOT_OBSERVABLE. The engine is never forced into PASS/FAIL; it
can say *we do not know*.

**Enforced invariant:** only `OBSERVED_ISSUE` may carry severity above INFO, and it must
cite a standards basis. Violations raise at construction — see `SecurityFinding.__post_init__`.

## Evidence extension made in Phase 3 (justified)
`SessionEvidence` carried no negotiated TLS version or cipher, which the RFC 8996 /
NIST rules require. Added `tls_negotiated_version` and `tls_cipher_suite`, derived in
Phase 3 from evidence Phase 2 already normalizes.

The version is read from the **ServerHello's `supported_versions` extension first**,
falling back to the handshake version. Reading `legacy_version`/`record_version` would
report every TLS 1.3 session as TLS 1.2, because TLS 1.3 pins those to 0x0303
(RFC 8446 §4.1.3/§4.2.1; doc 01A). Our corpus confirms it: `supported_version=772`
while `handshake_version=771` on the same ServerHello.

## Provenance
Every finding carries `EvidenceRef`s built directly from the Phase-3 `EvidenceField` —
field name, observed value, evidence state, causing frames and basis, verbatim. Rules
never restate evidence by hand. Chain:

    Finding -> rule_id -> SessionEvidence field -> evidence state + frames -> capture sha256

Finding ids are a hash of (rule, capture, stream, status), so they are stable across runs.

## Failure behaviour
A rule that raises is caught; the failure is recorded in `AnalysisReport.rule_errors`
and **no finding is emitted**. A broken or confused rule can never produce a confident
security conclusion.

## Limitations (stated, not hidden)
- **No certificate validation.** SEC-TLS-003 reports `NOT_OBSERVABLE`. Under TLS 1.3 the
  Certificate message is encrypted; resumed sessions omit it at any version.
- **No EMS (RFC 7627) or renegotiation (RFC 5746) rules.** tshark can dissect these, but
  the normalized contract does not carry them and the corpus does not contain them.
- **No cipher-suite strength grading.** The value is observed, but a partial IANA
  strength table would mislabel unknown suites.
- **Stripping is not detectable per-session.** By design — see the rule catalog.
