# 03 — Canonical Evidence & Data Model

**Status:** Draft for approval. **Date:** 2026-09-16 · **Pairs with:** 04 (provenance), ADR-0002.

One canonical internal representation. Every field carries an **evidence state** (04) and, where
relevant, a **provenance tag**. Types below are conceptual (Python dataclass / Pydantic), not a schema
commitment.

---

## 1. Object hierarchy

```
Capture (1) ─┬─ NetworkFlow (N) ── TcpStream (N)
             └─ EmailSession (N) ─┬─ StartTlsState (0..1)
                                  ├─ TlsHandshake (0..1) ── Certificate (0..N)
                                  └─ Finding (0..N)
Baseline (N, per key)         AnomalyScore (per EmailSession)
Report (1) ── PostureAssessment (1)
```

## 2. Evidence-field wrapper

Every non-structural field is not a bare value but:

```
EvidenceField<T> {
  value:        T | null
  state:        OBSERVED | INFERRED | UNKNOWN | AMBIGUOUS | INCOMPLETE | NOT_OBSERVABLE
  basis:        str            # why this state (human + machine readable)
  provenance:   observed | inherited | historical | retrieved | decrypted   # for cert-class facts
  frames:       [int]          # supporting frame numbers
}
```

This wrapper is the mechanism that makes the forbidden silent conversions (04) *structurally
impossible* — a consumer must read `.state`, not just `.value`.

## 3. Core objects (fields abbreviated; all non-structural fields are EvidenceField)

**Capture** — `capture_id`, `sha256`, `filename`, `bytes`, `packet_count`, `first_ts`, `last_ts`,
`link_type`, `truncated`, `analysis_version`, `tool_versions{tshark}`.

**NetworkFlow / TcpStream** — `stream_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `transport`,
`syn`, `synack`, `fin`, `rst`, `retransmits`, `had_gap`, `first_frame`, `last_frame`.

**EmailSession** — `session_id`, `protocol{smtp|imap|pop3}`, `implicit_tls:bool`, `client`, `server`,
`server_port`, `banner`, `capture_complete`, `first_frame`, `last_frame`, links to StartTlsState /
TlsHandshake / Findings.

**StartTlsState** — `advertised`, `command_seen`, `response` {ACCEPT|REJECT|null}, `upgrade_attempted`,
`upgrade_established`, `plaintext_continuation`, `plaintext_credentials`, `ehlo_reissued`. *(This is
the object competitors reduce to one boolean — 01B/01D.)*

**TlsHandshake** — `negotiated_version` (from `supported_versions`, not `legacy_version`),
`cipher_suite`, `key_exchange`, `named_group`, `sni`, `alpn`, `resumed`, `psk`, `early_data`,
`handshake_status` {COMPLETE|FAILED|INCOMPLETE}, `forward_secrecy`.

**Certificate** — `subject`, `issuer`, `not_before`, `not_after`, `public_key_algo`, `public_key_bits`,
`signature_algo`, `chain_position`, `chain_status`, `verification_state`. All default to
`NOT_OBSERVABLE` for TLS 1.3 / resumed sessions (01A). `expiry` evaluated against **capture time**,
never wall-clock (01 §6.4).

**Finding** — `finding_id`, `rule_id`, `rule_version`, `title`, `severity`, `verdict`
{SECURE|WEAK|DEVIATION|NOT_OBSERVABLE|...}, `standards[]`, `session_ids[]`, `observed_facts`,
`inferred_facts`, `evidence_confidence`, `baseline_context`, `limitations[]`, `supporting_frames[]`,
`remediation`. **Immutable once produced.** (This is exactly the grounding contract the AI layer
consumes — 10B §5.)

**Baseline** — `key` (server / client / pair / pair+proto / temporal window), `n_sessions`,
`tls_rate`, `first_seen`, `last_seen`. Time-aware (prior-history), per 02A §6.

**AnomalyScore** — `session_id`, `anomaly_score`, `anomaly_band` {normal|elevated|high},
`feature_contributions[]`, `model_version`, `training_context`. **Never a verdict.** Lives in a
separate table, joined only at prioritisation.

**PostureAssessment** — `overall`, `coverage` (how much was observable — the coverage-aware score,
AMB-07), `by_dimension`, `finding_counts`, `abstentions`, `not_observable_counts`.

## 4. Coverage-aware posture (AMB-07 resolved here)

The posture score reports **both** a security grade and a **coverage figure**: e.g. *"assessed 13 of
18 properties; 5 NOT_OBSERVABLE (TLS 1.3 encrypted certificate)."* A clean-looking report can never
silently mean "we saw nothing" (01A §7.2). This is deterministic, not learned.

## 5. Persistence

SQLite tables mirror these objects; EvidenceField serialises to `(value, state, basis, provenance,
frames_json)`. Artifacts (PCAP, rendered reports) on filesystem keyed by `capture_id`. Full schema is
an implementation task (Phase 1), not committed here.
