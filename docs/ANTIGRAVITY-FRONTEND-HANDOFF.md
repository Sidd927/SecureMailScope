# SecureMailScope — Frontend Handoff to Google Antigravity

**Status:** Backend, security engine, analysis pipeline, and API are FROZEN. This document is
the complete technical contract for a ground-up frontend rebuild. Every field, enum value, and
constant below was read directly from the source in this repository at commit `84c7d51`
(branch `frontend/antigravity-rebuild`, based on `phase/dashboard-god-mode`) or from a live
response of the running backend at that same commit. Nothing here is invented. Where a field or
capability does not exist, this document says so explicitly rather than describing a workaround.

---

## A. Project

```
SecureMailScope
SIH26159
NTRO
AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications
```

## B. Current architecture

```
PCAP
 ↓
TShark / reconstruction        (src/securemailscope/dissect, session)
 ↓
security analysis              (src/securemailscope/analysis — deterministic rules)
 ↓
evidence                       (src/securemailscope/evidence — EvidenceField/EvidenceState)
 ↓
findings                       (SecurityFinding, one per rule × session)
 ↓
cross-session reasoning        (src/securemailscope/crosssession)
 ↓
posture/scoring                (src/securemailscope/posture — fusion, scoring, prioritisation)
 ↓
assessment/report              (src/securemailscope/reporting)
 ↓
FastAPI                        (src/securemailscope/backend)
 ↓
frontend                        ← Antigravity owns this layer only
```

The frontend is the last, thin, presentation-only layer. It reads one canonical document (the
assessment, or its `dashboard` projection) and renders it. It computes no security fact.

## C. Backend entry point

```bash
PYTHONPATH=src python3 -m securemailscope.backend [--host 127.0.0.1] [--port 8000] [--data-dir ./securemailscope-data]
```

Source: `src/securemailscope/backend/__main__.py`. Binds to `127.0.0.1` by default — **there is
no authentication layer** (ADR-0011). Do not bind it to a non-loopback address without adding
one first; that is a backend decision, out of scope for the frontend rebuild.

The demo bundle's equivalent convenience script is `demo/commands/start_demo.sh <port>`, which
launches the same `create_app()` and additionally serves the legacy dashboard at
`/dashboard/` — Antigravity's new frontend does not need to reuse that mount point or convention
at all; it is free to be served however its own tooling (Vite, etc.) prefers, hitting the same
`/api/v1/*` origin.

## D. API endpoints — verified against the live OpenAPI schema and real responses

Base path `/api/v1`. Confirmed exhaustive path list from `GET /openapi.json` at the frozen
commit:

```
GET  /api/v1/health
POST /api/v1/analyses
GET  /api/v1/analyses
GET  /api/v1/analyses/{run_id}
GET  /api/v1/analyses/{run_id}/assessment
GET  /api/v1/analyses/{run_id}/artifacts
GET  /api/v1/analyses/{run_id}/dashboard
GET  /api/v1/analyses/{run_id}/reports
GET  /api/v1/analyses/{run_id}/reports/{fmt}
GET  /api/v1/analyses/{run_id}/sessions
```

There is no other endpoint. There is no packet/byte-content endpoint, no per-session-finding
endpoint, no confidence/compliance/risk-percentage field anywhere in this API.

### `GET /api/v1/health`

Real response, verified live:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "backend_schema_version": "1.0",
  "posture_schema_version": "1.0",
  "posture_engine_version": "0.8.0",
  "database": "ok",
  "artifact_count": 3,
  "artifact_bytes": 19672,
  "limits": {
    "max_upload_bytes": 268435456,
    "max_concurrent_analyses": 1,
    "max_queued_jobs": 8,
    "max_analysis_seconds": 600,
    "max_page_size": 100,
    "default_page_size": 20,
    "max_json_bytes": 65536
  },
  "tshark": "available"
}
```

### `POST /api/v1/analyses` — upload

- **Method:** `POST`. **Endpoint:** `/api/v1/analyses`.
- **Multipart field name:** `file` (also accepts `capture`) — form field, `multipart/form-data`.
  Raw `application/octet-stream` / `application/vnd.tcpdump.pcap` body is also accepted.
- **Query parameters:** `ai` (bool, default `false` — enables the ML lane), `force` (bool —
  re-run even if this exact capture+ai+formula combination already completed), `formula`
  (optional scoring-formula id string, e.g. `F2-group-damped`).
- **Response:** `201`, a `RunResponse` (see below). **Idempotent by content:** resubmitting
  byte-identical content with the same `ai`/`formula` returns the prior completed run with
  `"replayed": true` instead of re-analysing.
- **Processing behaviour:** the call is **synchronous** — it blocks until the pipeline finishes
  (or fails) and returns the completed/failed run directly. There is no job-polling pattern for
  a single submission; the frontend must handle a long-blocking `POST`, not a queue+poll UX,
  unless it chooses to build one against `GET /analyses` polling for the row's `state` — which
  is what the old frontend's Home screen did (see §K below).
- **Error behaviour:** every error is `{"error": {"code", "message", "detail": {}, "run_id"}}`.
  A bounded semaphore (`max_concurrent_analyses`) and admission limit
  (`max_queued_jobs`, both from `/health.limits`) reject over-capacity submissions with a
  `ResourceLimitExceeded`-shaped error rather than queuing indefinitely.

### `GET /api/v1/analyses` — list

Query: `limit`, `offset`, `state` (a `JobState` string filter), `capture_id` (64-hex filter).
Response `{"total", "limit", "offset", "items": [RunResponse, ...]}`.

**`RunResponse`**, verified live field-for-field:

```json
{
  "run_id": "3c8fb71873d7418aadaa733ab0272e7d",
  "state": "COMPLETED",
  "capture_id": "ce5377348e22ad92c33d705e31388944bad8224534d478c38b57a75d3ba4a501",
  "assessment_id": "645090e0bc44ba9d",
  "ai_enabled": false,
  "formula_id": null,
  "created_at": "2026-09-24T11:33:30Z",
  "started_at": "2026-09-24T11:33:30Z",
  "completed_at": "2026-09-24T11:33:30Z",
  "duration_ms": 117,
  "ingest_status": "COMPLETED",
  "error_code": null,
  "error_message": null,
  "source_filename": "backup_weak_certificate.pcap",
  "backend_version": "0.1.0",
  "replayed": false,
  "stages": null,
  "overall_posture": "CRITICAL",
  "score_value": 44.0
}
```

`state` (`JobState`) observed values include `CREATED, VALIDATING, QUEUED, RUNNING,
FINALIZING, COMPLETED, FAILED, CANCELLED, RECOVERY_REQUIRED` (source:
`src/securemailscope/backend/lifecycle.py` — read that file directly before hard-coding this
list; it is reproduced here from the prior frontend's own verified usage, not re-derived fresh
this pass). `overall_posture`/`score_value` are **listing projections** — cheap denormalisations
for sorting the table, not the authority; the assessment endpoint is the authority. `stages` was
`null` on every run observed live in this instance (an ordered `[{stage, ms}]` timing array is
documented in the backend's own model but did not appear populated on any of the 3 real stored
runs at the time of this audit — verify against a fresh run before depending on it).

### `GET /api/v1/analyses/{run_id}` — one run's backend metadata

Same `RunResponse` shape as above, single object.

### `GET /api/v1/analyses/{run_id}/assessment` — the canonical document

Verified live (`run_id=3c8fb71873d7418aadaa733ab0272e7d`), top-level shape:

```json
{
  "run_id": "...",
  "assessment_id": "645090e0bc44ba9d",
  "capture_id": "...",
  "overall_posture": "CRITICAL",
  "coverage": { "...": "EvidenceCoverage, see below" },
  "limitations": [
    "passive analysis: conclusions describe what the capture shows, not the server's configuration",
    "no attacker, intent or attribution is or can be established from a packet capture",
    "certificate chain, expiry and key strength are not observable for TLS 1.3 or resumed sessions (RFC 8446 §2, §2.2)",
    "absence of a STARTTLS advertisement is ambiguous: stripping and genuine non-support are byte-identical at the application layer",
    "SecureMailScope cannot confirm that any remediation was applied or effective"
  ],
  "assessment": { "...": "the full PostureAssessment.to_dict(), see §E below" }
}
```

This is **the only place the full, unprojected assessment lives.** `dashboard` (below) is a
presentation re-projection of it and drops nothing but reorganises; if a field is missing from
`dashboard`, check `assessment` before concluding it does not exist.

### `GET /api/v1/analyses/{run_id}/dashboard` — the presentation view-model

Verified live top-level keys, exhaustive:

```
identity, posture, coverage, distributions, protocols, findings, issue_groups,
abstentions, standards, remediation, ml, provenance, limitations, filters,
notices, unavailable
```

This is a **pure, stateless re-projection**, recomputed on every request from the stored
assessment — never a second stored copy. It performs zero new security calculation. Its own
`unavailable` field is a literal, self-documenting list of things this dashboard view cannot
show (see §E.9). Read `src/securemailscope/dashboard/model.py` for the exhaustive dataclass
definitions (`Identity`, `Posture`, `Coverage`, `Bar`, `Distribution`, `ProtocolRow`, `Citation`,
`Remediation`, `FindingRow`, `IssueGroupRow`, `AbstentionRow`, `StandardRow`, `MLPanel`,
`Provenance`, `FilterOption`, `Filters`) — every field on every one of those dataclasses is a
real, live field on this endpoint's JSON.

### `GET /api/v1/analyses/{run_id}/sessions` — per-session detail

**Re-derived live from the stored PCAP artifact on every call — not persisted, not cached.**
Response: `{"run_id", "capture_id", "total", "items": [SessionEvidence, ...]}`.

Verified live shape of one item (`SessionEvidence.to_dict()`), field-for-field — **note the
nesting**, which the previous frontend build initially got wrong by assuming flat fields:

```json
{
  "stream_key": "ce5377...501:0",
  "capture_id": "ce5377...501",
  "tcp_stream_id": 0,
  "protocol": "smtp",
  "client": { "ip": "127.0.0.1", "port": 36568 },
  "server": { "ip": "127.0.0.1", "port": 465 },
  "endpoint_basis": "well-known mail port 465 (no greeting observed)",
  "timing": {
    "first_frame": 1, "last_frame": 14,
    "start_epoch": 1790034546.615724, "end_epoch": 1790034546.618086,
    "packet_count": 14
  },
  "transport_flags": ["SETUP_OBSERVED", "TEARDOWN_OBSERVED"],
  "completeness": "COMPLETE",
  "app_state": "IMPLICIT_TLS",
  "tls_state": "SERVER_HELLO_OBSERVED",
  "implicit_tls": true,
  "evidence": {
    "starttls_advertised": { "value": null, "state": "NOT_OBSERVABLE", "basis": "...", "provenance": "none", "frames": [] },
    "starttls_requested": { "...": "same EvidenceField shape" },
    "starttls_accepted": { "...": "..." },
    "tls_transition": { "...": "..." },
    "tls_negotiated_version": { "value": "TLS1.2", "state": "OBSERVED", "basis": "ServerHello handshake version (no supported_versions extension)", "provenance": "observed", "frames": [6] },
    "tls_cipher_suite": { "value": "0xc030", "state": "OBSERVED", "...": "..." },
    "tls_cipher_suite_name": { "value": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "state": "OBSERVED" },
    "tls_key_exchange": { "value": "ECDHE", "state": "OBSERVED" },
    "tls_named_group": { "value": null, "state": "UNKNOWN", "basis": "no key_share group observed in the ServerHello" },
    "tls_forward_secrecy": { "value": true, "state": "OBSERVED" },
    "tls_certificate_chain": { "value": 1, "state": "OBSERVED" },
    "plaintext_continuation": { "value": false, "state": "OBSERVED" },
    "auth_activity": { "value": null, "state": "NOT_OBSERVABLE", "basis": "authentication occurs inside TLS and is not passively observable" }
  },
  "certificates": [
    {
      "index": 0, "serial": "76:e5:...", "version": "2",
      "not_before": "2026-09-21 23:38:06 (UTC)", "not_after": "2027-09-21 23:38:06 (UTC)",
      "public_key_algorithm": "RSA", "key_bits": 1024,
      "subject_key_id": "7e:89:...", "authority_key_id": "df:b2:...",
      "self_signed": false, "san_dns_names": []
    }
  ],
  "certificate_notes": ["distinguished names could not be attributed to a specific certificate", "..."],
  "transitions": [
    {
      "from_state": "CONNECTED", "event": "implicit_tls", "to_state": "IMPLICIT_TLS",
      "evidence_frames": [4, 6, 8, 9, 10, 12], "evidence_state": "OBSERVED",
      "timestamp_epoch": null, "basis": "connection opened on an implicit-TLS port with TLS records"
    }
  ],
  "events": [],
  "notes": []
}
```

Every field under `evidence.*` is an `EvidenceField`: `{value, state, basis, provenance,
frames}`. **`value` is `null` whenever `state` is `UNKNOWN`, `INCOMPLETE`, or
`NOT_OBSERVABLE`** — that is an enforced invariant (`EvidenceField.__post_init__`), not a gap to
fill in on the frontend. Never coerce a `null` value + non-conclusive state into a falsy
display; render the state, not a guessed value. `transitions[].timestamp_epoch` was observed
`null` on the one real session inspected — do not assume every transition carries a real
timestamp; check before building time-scrubbing UI on the assumption that it always will.

There is **no packet-content or byte-content endpoint**. `frames`/`evidence_frames` are integer
frame-number pointers back into the original PCAP; there is no API that returns the bytes of
those frames. **NOT AVAILABLE FROM CURRENT API.**

### `GET /api/v1/analyses/{run_id}/artifacts`

Query: `verify` (bool — re-hashes on disk, reports `integrity: "OK"|"MISMATCH"`).

```json
{
  "run_id": "3c8fb71873d7418aadaa733ab0272e7d",
  "items": [{
    "artifact_id": "2a65570e2db1475fbc5829f94a444b42",
    "run_id": "3c8fb71873d7418aadaa733ab0272e7d",
    "kind": "pcap",
    "sha256": "ce5377348e22ad92c33d705e31388944bad8224534d478c38b57a75d3ba4a501",
    "size_bytes": 3122,
    "created_at": "2026-09-24T11:33:30Z",
    "original_filename": "backup_weak_certificate.pcap",
    "integrity": null
  }]
}
```

`integrity` is `null` unless `?verify=true` was passed.

### `GET /api/v1/analyses/{run_id}/reports`

```json
{
  "run_id": "...",
  "items": [
    {
      "format": "html", "media_type": "text/html; charset=utf-8",
      "filename": "securemailscope-645090e0bc44ba9d.html",
      "renderer_available": true, "report_schema_version": "1.0", "renderer_version": "0.9.0",
      "generated": false, "artifact_id": null, "report_sha256": null,
      "size_bytes": null, "created_at": null, "current": null, "integrity": null
    },
    { "format": "pdf", "...": "same shape, media_type application/pdf" },
    { "format": "json", "...": "same shape, media_type application/json" }
  ]
}
```

`generated: false` and the artifact fields being `null` means the rendered file has not been
produced *yet* for this exact schema/renderer version combination — it renders (and is then
cached as an artifact) on first `GET` of `/reports/{fmt}`, not eagerly. Do not read `generated:
false` as an error state; it is normal for a run whose report was never fetched.

### `GET /api/v1/analyses/{run_id}/reports/{fmt}`

`fmt` ∈ `{html, pdf, json}` — a fixed allowlist, never taken from data. Query: `download` (bool;
PDF always forces download). Returns raw bytes with `Content-Type` and headers
`X-Assessment-Id`, `X-Report-Schema-Version`, `X-Renderer-Version`, `X-Report-Sha256`,
`Cache-Control: private, max-age=86400` (a report is a pure function of an immutable assessment,
so it is safe to cache indefinitely once rendered).

## E. Data model detail

### E.1 Session — see the full verified JSON in §D above. Nothing further to add.

### E.2 Finding — as served by `dashboard.findings[]` (`FindingRow`)

Every field on `dashboard/model.py`'s `FindingRow` is real. The ones most relevant to the
frontend, verified against live data:

- `rank`, `priority_score`, `ml_adjustment`, `affected_sessions`, `affected_stream_keys[]`
- `severity` (canonical) + `severity_label` + `severity_marker` + `severity_tone` +
  `severity_known` — severity is `INFO|LOW|MEDIUM|HIGH|CRITICAL` (`Severity` enum,
  `src/securemailscope/analysis/model.py`), display-ordered strongest first.
- `status` + `status_label`, `certainty` + `certainty_label`, `observability` +
  `observability_label` — see §G for the exact enum values of each; these are three
  **different, non-interchangeable** axes.
- `issue_class` + `issue_class_label`, `fact_kind` + `fact_kind_label`, `dimension` +
  `dimension_label`
- `protocol` (**nullable** — a real anomaly-signal row was observed with `protocol: null**;
  never coerce to a string), `protocol_key` (never null, use this for filter logic),
  `protocol_label`
- `title`, `conclusion`, `explanation`, `penalising` (bool — only `true` findings lowered the
  score)
- `stream_key`, `tcp_stream_id`, `frames[]`, `frames_text`, `source_rule_ids[]`
- `citations[]` — each `{standard, section, reason, text}` — `text` is the verbatim clause text;
  render it, do not summarise it.
- `remediation` — `{observed, why_it_matters, recommended_action, affected_scope, verification,
  citations[], limitations[]}` or `null`.
- `contradictions[]`, `limitations[]`, `factors{}` (a dict of named numeric contributors to
  `priority_score` — real example verified this session:
  `{actionable:2, certainty:6, fact_kind:5, recurrence:5.1699, severity:70, standards_backed:3}`
  → `priority_score: 91.1699`), `explanation_priority`

**Findings are grouped by issue class, not one row per session.** `recurrence`/
`affected_sessions` tells you how many sessions shared one condition; there is no endpoint that
returns "this session's own finding list" directly — filter `findings[]` by
`affected_stream_keys.includes(session.stream_key)` client-side, as a derived view, and label it
as such if you show it as if it were a first-class list.

**There is no numeric confidence, compliance, or risk percentage anywhere in this system.** The
`dashboard`'s own `unavailable[]` field states this about itself. Do not build a "confidence
meter" or any percentage-based trust gauge; the enums (`certainty`, `observability`) are the
entire vocabulary that exists for this.

### E.3 Evidence

The atomic unit is `EvidenceField` (§D). There are **no raw packet bytes or PEM blobs exposed
via the API** — evidence is always a structured fact with frame-number provenance, never a byte
dump. Certificate fields are the *parsed* representation only.

### E.4 Cross-session — see §H, verified against source, not re-derived from memory this pass.

### E.5 Posture / score

`dashboard.posture` (`Posture` dataclass): `value` (canonical `PostureBand`), `label`, `tone`,
`known` (bool), `withheld` (bool — **a real, distinct fact**: Phase-7 withholds the band below a
coverage floor; this is not a presentation choice), `withheld_note`, `score_value`, `score_text`,
`formula_id`, `starting_value`, `total_penalty`, `basis` (a real, plain-English sentence — verified
live: `"100 minus 56.00 across 2 issue group(s) under F2-group-damped"`), `components[]`
(`ScoreComponentRow`: `issue_class`, `issue_class_label`, `severity`, `severity_label`,
`recurrence`, `base_weight`, `recurrence_multiplier`, `penalty`, `explanation` — a real,
human-readable sentence per component, e.g. `"HIGH weight 28 x recurrence multiplier 1.00 for 1
affected session(s)"`).

`PostureBand` values (verify against `src/securemailscope/posture/model.py` before hard-coding):
`STRONG, ADEQUATE, WEAK, CRITICAL, INSUFFICIENT_EVIDENCE`. The last is a real band — refusing to
grade is not the same as grading zero, and must not be styled or worded like a failure.

### E.6 Coverage

`dashboard.coverage` (`Coverage`): `sessions_total`, `sessions_assessed`, `sessions_abstained`,
`assessed_fraction`, `percent_text`, `summary_text`, `observation_counts{}` (keyed by
`EvidenceState`, §G), `observation_fractions{}` (same keys, 0–1 floats), `completeness_counts{}`,
`protocol_counts{}`, `present` (bool). Verified live example:
`observation_fractions: {AMBIGUOUS: 0.125, NOT_OBSERVABLE: 0.5, OBSERVED: 0.375}`.

### E.7 Standards

`dashboard.standards` (`Standards`): `standards[]` (`{standard, sections[]}`),
`distinct_standards`, `unmapped_citations[]` (citations the rule engine emitted that are not yet
in the standards registry — **a real, self-reported gap the engine surfaces about itself; show
it, do not hide it**), `note`, `present`.

### E.8 AI/ML panel

See §I.

### E.9 What the dashboard explicitly says it cannot show

`dashboard.unavailable[]` is a real, literal list produced by
`src/securemailscope/dashboard/projection.py`. As documented by the code itself, it states at
minimum: no per-session finding rows (issue-group granularity only), no packet/byte-level
drill-down, and no attack-probability/confidence/compliance/risk percentage of any kind. Read
that field live rather than trusting this summary to be exhaustive by the time you build against
it.

## F. Frontend responsibilities

**The frontend is responsible for:** navigation, visualisation, interaction, filtering, session
exploration, evidence exploration, findings presentation, cross-session presentation, posture
presentation, report access/export, capture upload, responsive layout, accessibility, visual
hierarchy.

**The frontend is NOT responsible for, and must never do:** security decisions, scoring
calculations, evidence inference, cryptographic interpretation, AI inference, modifying PCAPs,
modifying backend results, or inventing a field/metric the API does not provide.

## G. Evidence vocabulary — exact, non-negotiable, verified against source this pass

### G.1 `EvidenceState` (`src/securemailscope/evidence/states.py`)

```
OBSERVED         — directly present in captured bytes
INFERRED         — deduced from observed facts (a `basis` is required)
UNKNOWN          — insufficient evidence to decide
AMBIGUOUS        — evidence supports more than one reading
INCOMPLETE       — capture truncated at the relevant point
NOT_OBSERVABLE   — structurally impossible to observe passively
```

Do **not** substitute `CONFIRMED`, `UNAVAILABLE`, `NOT_APPLICABLE`, or `INSUFFICIENT_EVIDENCE`
for any of these six — those words belong to the other, separate vocabularies below. Mixing them
was a real, previously-documented error in this project's history (`docs/sih-pitch-deck/DO-NOT-CLAIM.md`
Part II) — do not repeat it.

### G.2 `FindingStatus` (`src/securemailscope/analysis/model.py`)

```
OBSERVED_ISSUE          — positive evidence of a problem
COMPLIANT               — positive evidence of a good state
INFORMATIONAL           — neutral, notable observation
AMBIGUOUS               — evidence supports more than one reading
INSUFFICIENT_EVIDENCE   — capture cannot decide
NOT_OBSERVABLE          — structurally unobservable here
```

### G.3 `BaselineStatus` (`src/securemailscope/crosssession/baseline.py`)

```
ESTABLISHED
INSUFFICIENT_HISTORY
NOT_APPLICABLE   — subject not comparable at all
```

### G.4 `Deviation` (`src/securemailscope/crosssession/model.py`)

```
NONE                    — behaviour matches the baseline
DEVIATION               — differs from a consistent baseline
SUSPICIOUS_DEVIATION    — differs AND contrast supports concern
NOT_ASSESSED            — no usable baseline / not comparable
```

### G.5 `Comparability` (`src/securemailscope/crosssession/comparability.py`)

```
COMPARABLE
NOT_COMPARABLE
INSUFFICIENT_EVIDENCE
AMBIGUOUS
```

### G.6 `ContrastState` (`src/securemailscope/crosssession/contrast.py`)

```
CONTRAST_SUPPORTED
CONTRAST_INSUFFICIENT
CONTRAST_NOT_APPLICABLE
CONTRAST_AMBIGUOUS
```

### G.7 Evidence certainty (derived, shown on findings — `posture/model.py`)

```
CONFIRMED       — derived from OBSERVED evidence
PROBABLE        — derived from INFERRED evidence
UNCERTAIN       — derived from AMBIGUOUS/INCOMPLETE evidence
UNDETERMINED
```

**These seven enums are seven different concepts.** A UI that collapses any two of them into one
visual treatment (one badge shape, one color family) will misrepresent the assessment. The prior
frontend's rule — evidence-state gets a neutral icon+pattern family, severity gets hue, posture
band gets its own distinct treatment, job/run lifecycle state gets a third — is a reasonable
starting constraint, not a prescription; Antigravity should solve this its own way but must keep
the seven concepts visually distinguishable.

## H. Cross-session semantics — verified against source, not simplified

**`DEFAULT_MIN_HISTORY = 5`, `DEFAULT_MAX_HISTORY = 50`** — confirmed live in
`src/securemailscope/crosssession/baseline.py`. These are configuration constants, not
hard-coded architecture; state the number in the UI, do not hide it, and re-check it against
source before hard-coding it into frontend copy in case it changes.

**Comparability is client-scoped, not just endpoint-scoped.** The real `ComparabilityKey`
(`src/securemailscope/crosssession/comparability.py`) is:

```
(client_ip, server_ip, server_port, protocol, implicit_tls)
```

I.e. one specific client talking to one specific service endpoint, over one protocol, in one TLS
mode (implicit vs. explicit TLS are **never** pooled together). This is a deliberate, documented
design decision (`OQ-25`): pooling every client of a server into one baseline was found to mix
heterogeneous-but-legitimate client populations and destroy the value of a control-endpoint
contrast. Do not simplify the UI copy to "sessions to the same server" — it is specifically
*this client* to that server/protocol/TLS-mode combination.

**Baseline** is built only from sessions that strictly *precede* the subject in time (never
future sessions, never whole-capture pooling), tracks five features (`starttls_advertised,
starttls_requested, tls_established, tls_version, auth_activity`), and reports `status`
(§G.3), `sample_count`, a `window {start_epoch, end_epoch}`, `features{}`, and `members[]` — a
list of **concrete `SessionRef` pointers**, never "a baseline" cited abstractly. If the frontend
shows a baseline, show which real sessions constitute it.

**Contrast** (control-endpoint comparison) additionally finds sessions to the *same* server from
a *different* client and checks whether they upgraded to TLS, producing one of the four
`ContrastState` values (§G.6). `CONTRAST_SUPPORTED` vs `CONTRAST_NOT_APPLICABLE` changes whether
a deviation is analytically "suspicious" or merely "different" — collapsing this distinction in
the UI would misrepresent confidence.

**Output:** a `CrossSessionFinding` per subject×rule carries `deviation` (§G.4) plus its
comparability/baseline/contrast provenance as three separate sub-documents. Known rule IDs
observed: `CS-STARTTLS-001`, `CS-STARTTLS-002`, `CS-TLS-001`.

**The engine's own required framing, verbatim from its docstrings — reuse this, do not
paraphrase it into something stronger:** *"a difference is not an attack."* A `DEVIATION` or
`SUSPICIOUS_DEVIATION` is a statement about behaviour relative to comparable history, never an
attribution and never a claim that an attack occurred. When history is insufficient, the correct
UI framing is a dignified, explicit abstention stating the exact count found vs. required — not
an error and not a blank screen.

## I. AI/ML semantics — verified against source

- Runs only when `ai=true` on submission (`POST /analyses?ai=true`). Default model:
  `RobustZScoreModel` (`src/securemailscope/ml/models.py`), fit **per-capture** on that capture's
  own session rows — not a pre-trained corpus model. Threshold: the 0.95 quantile of the
  capture's own scores (`ML_THRESHOLD_QUANTILE = 0.95`, `src/securemailscope/backend/pipeline.py`).
- Output type `MLAnomalyResult` is **not a security finding** — no severity, no standards, no
  status vocabulary. Fields: `anomaly_score`, `threshold`, `band` (`NORMAL | BORDERLINE |
  ANOMALOUS | NOT_SCORED`), `top_features[]` (feature/contribution/direction), `basis` (a
  plain-language sentence explicitly framed as *association, not causation* — e.g. "score is
  most associated with X (above_normal) ... not a security verdict").
- **It does not create findings and does not change severity.** Its only effect on the
  assessment is `ml_adjustment`, a small numeric nudge to a finding's *ranking order* within its
  existing severity tier. `MAX_ML_ADJUSTMENT = 4.0` (`src/securemailscope/posture/prioritise.py`)
  — verified far smaller than the ≥12-point gap between adjacent severity-tier base weights, so
  it is structurally incapable of moving a finding across a severity boundary.
- **`--no-ai` / `ai=false` equivalence:** with AI disabled, `ml_adjustment` is `0.0` for every
  finding, and every security conclusion is designed to be — and is tested to be — identical to
  the AI-enabled run. Demo scene C (`scene_c_no_ai_equivalence.pcap`, §K) exists specifically to
  demonstrate this.
- **Empirical result, source-cited (`docs/sih-pitch-deck/DO-NOT-CLAIM.md`, ADR-0015):** zero
  unique true detections on every held-out evaluation split. This is reported as a negative
  result, not hidden.
- **Known limitation, verified live in this instance:** `model_summary.ai_enabled` was `false`
  and `provenance.source_counts.ml_results` was `0` on every real stored run inspected — the AI
  lane exists and is fully wired, but this instance's current data does not currently exercise a
  populated ML result. Design the UI to support the full shape above; do not assume you will see
  a populated example without submitting a capture with `ai=true` yourself.
- **Firewall rule for the UI:** the AI/ML panel must never be the dominant visual element on any
  screen, and copy must never imply "AI detected/found/identified" a security issue. The correct
  frame is: deterministic, standards-cited rules produce every finding; AI only reorders.

## J. Provenance

Real chain, as actually implemented (not "chain of custody" — that is a legal-process term this
project does not claim):

```
PCAP SHA-256 (artifact-layer content address, re-verifiable via GET /artifacts?verify=true)
      ↓
capture_id  (= that SHA-256)
      ↓
frame number / TCP stream id / timestamp  (SessionEvidence identity + EvidenceField.frames[])
      ↓
evidence + its own provenance field (observed | inherited | historical | retrieved | decrypted | none)
      ↓
finding  (SecurityFinding / FusedFinding, carrying EvidenceRef back to the exact frames)
      ↓
rule id / standard citation  (source_rule_ids[], citations[])
      ↓
posture  (PostureAssessment.provenance: rule_ids[], source_counts{}, duplicate_sources_merged, contradictions_recorded)
      ↓
assessment_id
      ↓
report SHA-256  (X-Report-Sha256 header, cached artifact)
```

The frontend may visualise this chain. **Call it a forensic trace, never "chain of custody"** —
that specific phrase is on the forbidden list (§L) because it implies a certified legal
process this project does not perform.

## K. Real demo data — exact locations, verified live

Source of truth: `demo/README.md`. Captures are **symlinks** into `research/experiments/` (one
source of truth, not copies) — verified live paths:

| Scene | Path (relative to repo root) | Verified posture / score |
|---|---|---|
| A.1 — benign STARTTLS decline | `demo/captures/scene_a_1_benign_decline.pcap` → `research/experiments/oq33r/out/postfix_smtp_client_declines.pcap` | ADEQUATE / 88.0 |
| A.2 — genuine STARTTLS non-support | `demo/captures/scene_a_2_genuine_nonsupport.pcap` → `.../postfix_smtp_no_starttls_offered.pcap` | ADEQUATE / 85.0 |
| B — certificate/evidence honesty (TLS 1.3) | `demo/captures/scene_b_certificate_honesty.pcap` → `.../dovecot_imap_imaps_implicit_tls.pcap` | STRONG / 100.0 |
| C — `--no-ai` equivalence | `demo/captures/scene_c_no_ai_equivalence.pcap` → `.../postfix_smtp_starttls_upgrade.pcap` | ADEQUATE / 88.0 (identical AI on/off) |
| Backup — weak certificate | `demo/captures/backup_weak_certificate.pcap` → `research/experiments/p11cert/out/smtps_tls12_weak_sha1_rsa1024.pcap` | CRITICAL / 44.0 |
| Backup — self-signed certificate | `demo/captures/backup_selfsigned_certificate.pcap` → `.../smtps_tls12_selfsigned_rsa2048.pcap` | ADEQUATE / 88.0 |
| Backup — healthy chain (negative control) | `demo/captures/backup_healthy_chain.pcap` → `.../smtps_tls12_chain_rsa2048.pcap` | STRONG / 100.0 |
| Deep-dive — cross-session, control endpoint present | `demo/captures/deepdive_cross_session_control_endpoint.pcap` → `research/experiments/oq28/pcaps/G_control_endpoint.pcap` | CRITICAL / 22.15 |
| Deep-dive — cross-session, no control (honest negative) | `demo/captures/deepdive_cross_session_no_control.pcap` → `.../H_no_control.pcap` | CRITICAL / 34.15 |

Pre-rendered reports (HTML/JSON/PDF) already exist for four scenes at `demo/reports/` —
`backup_weak_certificate.*`, `scene_a_1_benign_decline.*`, `scene_b_certificate_honesty.*`,
`scene_c_no_ai_equivalence.*`. Machine-generated expected-value manifests (real posture, score,
issue classes, abstentions, coverage) are at `demo/expected/*.json`, one per scene plus
`all_scenes.json`. SHA-256 of every capture: `demo/hashes/SHA256SUMS.txt`.

**Suggested screen ↔ data mapping** (a suggestion for exercising the UI while building it, not a
requirement):

- **Home:** submit any capture above through `POST /analyses`; the STRONG/CRITICAL contrast
  between the healthy-chain and weak-certificate backups is the clearest before/after pair.
- **Overview:** `backup_weak_certificate.pcap` (CRITICAL, 2 real findings, real score
  decomposition) or `scene_b_certificate_honesty.pcap` (STRONG, TLS 1.3, exercises
  `NOT_OBSERVABLE` honestly).
- **Session detail:** any of the above — all are single-session captures except the two
  deep-dive cross-session ones, which are the ones to use for multi-session exploration.
- **Finding detail:** `backup_weak_certificate.pcap` — its two findings (weak RSA key, deprecated
  signature hash) have real standards citations and a real score contribution each.
- **Evidence:** `scene_b_certificate_honesty.pcap` — a real `NOT_OBSERVABLE` case (TLS 1.3
  encrypting the certificate message) alongside real `OBSERVED` evidence in the same session.
- **Cross-session:** `deepdive_cross_session_control_endpoint.pcap` (a populated,
  contrast-supported deviation) and `deepdive_cross_session_no_control.pcap` (the honest
  abstention/no-control case) — use both; they are the two different real outcomes this feature
  produces.
- **Report:** open `GET /analyses/{run_id}/reports/html` for any completed run, or read the
  pre-rendered files in `demo/reports/` directly for a static reference.

**Do not invent placeholder findings, scores, or AI explanations.** Every screen should be
designed and screenshotted against one of the real captures above.

## L. Claims firewall

Source: `docs/sih-pitch-deck/DO-NOT-CLAIM.md` (read it in full before writing any UI copy that
makes a factual claim). Forbidden claims the frontend's copy, tooltips, and empty/error states
must never make, with the correct alternative:

| Never say | Say instead |
|---|---|
| "AI detects attacks/attackers" / "AI-powered threat detection" | Deterministic, standards-cited rules produce every finding; AI only reorders within a severity tier |
| "We validate certificates" / "complete certificate validation" | Certificate chain **structure** is validated; trust and revocation are not observable from passive capture alone (see D-11, below) |
| "TLS 1.3 certificates are visible" | TLS 1.3 encrypts the certificate message; report `NOT_OBSERVABLE` with the reason, never blank or "untrusted" |
| "We detect every STARTTLS stripping attack" / any flat "we detect stripping" claim | "We report a deviation from comparable endpoints at the same server" — only where cross-session evidence exists |
| "Zero false positives" / "100% detection" / any detection-rate percentage | Delete the claim outright — never measured |
| "We are the first / unique / no existing tool can do this" | "Our source-code audit of five competing implementations found none performing cross-session reasoning" (audit-scoped, defensible) |
| "Real-time monitoring" | "Sub-second per-capture analysis" (batch-over-PCAP, not real-time) |
| "Scales to enterprise volumes" / any capture-per-hour throughput number | Delete — untested, unmeasured |
| Any market size, ROI, ₹-figure, "protects N mailboxes", "used by N organisations" | Delete outright — no verified data exists, this is a research prototype |
| "Chain of custody" / "court-admissible" | "Forensic trace" — every finding traces to specific frames; chain-of-custody is a certified legal process this tool does not perform |
| "We decrypt encrypted email" | "We analyse transport metadata and handshakes — nothing is decrypted, no keys are used" |
| Any claim that a tracked requirement is fully complete when it is documented as PARTIAL | State it as PARTIAL, per the two items below |

**Two requirements are formally, permanently PARTIAL for this project cycle** (source:
`docs/finalization/08-open-requirements.md`, `docs/architecture/requirements-traceability.md`)
— the frontend must not imply either is fully solved:

- **D-11 — certificate chain validation:** chain *structure* (ordering, AKI/SKI linkage,
  self-signed detection) is fully validated and tested. Chain **trust** and **revocation** are
  explicitly not validated and cannot be from passive-capture evidence alone (no trust anchors,
  no OCSP/CRL network access — the latter would violate the project's passive/offline
  commitment). This is a scoped, permanent limitation, not a bug to hide.
- **A-02 — AI-assisted anomaly detection:** the model is real and runs, but has demonstrated
  **no detection value** on held-out evaluation (zero unique true detections). It is shipped as
  a transparency-first, bounded secondary signal specifically *because* of this negative result,
  not despite it.

## M. Frontend rebuild philosophy

The new frontend is a **complete rebuild**, not an iteration on the Workbench experiment
preserved at `frontend/workbench-redesign` (checkpoint commit `e3f3787`). That branch is
reference material only — useful for seeing one prior attempt's component ideas (a session
explorer, a protocol timeline, a score "waterfall") and one prior attempt's real, verified
mistakes (assuming a flat session-field shape when the real API nests `client`/`server`/
`evidence`; a CSS specificity bug where an author `display` rule silently defeated the `hidden`
attribute) — not a foundation to extend.

Antigravity should build the new architecture from the API contract in this document and the
product requirements in §N–§O, using real components, real state management, real routing, real
CSS, real responsive layout, real accessibility, real browser interaction — a proper application
architecture (React/TypeScript/Vite or an equivalently sensible modern stack), not a small number
of static HTML files with vanilla DOM manipulation. The old frontend's "no framework, zero npm
dependencies" constraint (ADR-0022) was a decision specific to that implementation, not a
constraint on the new one — Antigravity is free to bring a real toolchain.

## N. Target UX

The product should feel like a serious **cybersecurity forensic investigation workstation** —
not a generic SaaS dashboard. Conceptual information architecture (this describes *relationships
between screens*, not layout):

```
HOME
 │
 ├── New Analysis
 │
 └── Recent Analyses
        │
        ▼
     ANALYSIS
        │
        ├── Overview
        ├── Sessions
        ├── Findings
        ├── Evidence
        ├── Cross-session
        └── Report
```

The exact visual implementation — layout, navigation pattern, whether these six are tabs, panes,
routes, or something else entirely — is intentionally left to Antigravity. This document
deliberately does not prescribe CSS, a three-column layout, cards, or any specific design
system.

## O. Visual direction — quality requirements, not implementation instructions

The interface should be: sophisticated, modern, professional, technical, trustworthy,
minimalist, information-dense where appropriate, highly readable, light theme, excellent
typography, strong hierarchy, polished spacing, responsive, fast, accessible.

Avoid, as **quality constraints, not an absolute prohibition on any specific UI pattern** — a
card, a rounded corner, or a chart is fine when it is the genuinely best solution to a real
problem; the constraint is against reaching for these as unconsidered defaults:

- generic AI-SaaS-dashboard aesthetics; template-looking admin dashboards
- excessive cards or excessive rounded containers used as the default answer to every layout
  question
- gradients everywhere; glassmorphism; neon cyberpunk; hacker/fake-terminal clichés
- decorative charts with no analytical purpose

## P. Real-data-first workflow (before writing UI code)

1. Launch the backend (§C).
2. Inspect the live OpenAPI schema at `/openapi.json` (or `/docs`).
3. Load real analysis results via the endpoints in §D — use the demo captures in §K.
4. Inspect real sessions, real findings, real evidence, real cross-session results, real
   reports.
5. Design the UI around those actual structures.

No invented backend contract. No fake metrics, findings, AI explanations, or progress bars —
the upload call is synchronous (§D); do not build a fake incremental progress bar for it, since
the backend has no per-stage progress event to drive one honestly (the `stages` timing array, if
populated on a given run, is available only *after* completion, as a retrospective breakdown).

## Q. Browser validation — required before calling any screen done

Minimum viewports: **1280×800, 1440×900, 1600×1000**, plus at least one narrower viewport. For
each: no horizontal overflow, no clipped content, no broken navigation, no console errors, no
failed API calls, no fake loading states, upload works, analysis opens, session selection works,
findings open, evidence opens, cross-session works, report links work, refresh/deep-link
navigation works, keyboard navigation works, focus is visible, labels are accessible, layout
responds sensibly.

## R. Performance

Audit JS bundle size, dependency count, DOM size, re-render cost, API call count (avoid
redundant re-fetching of the same assessment across screens — cache it per run), image/font
loading strategy, and layout shift. The product should feel immediate.

## S. Frontend security requirements

No `innerHTML`/`dangerouslySetInnerHTML` with untrusted (API-derived, ultimately
capture-derived) data. Safely escape/render every API value — a capture is attacker-controlled
input all the way through to every string that reaches the screen. No arbitrary script
injection. No dangerous URL construction from API data (report/export URLs must come from a
fixed format allowlist, never a string the API supplied). No secrets or credentials embedded in
the frontend. No client-side security decisions. No modification of backend security semantics.

## T. Test baseline at handoff

Full suite, run at the frozen base commit (`84c7d51`, branch `frontend/antigravity-rebuild`):

```
tests:   1233
passed:  1233
failed:  0
skipped: 0
```

This includes the full backend/security/analysis regression suite plus the **original**
tab-per-screen frontend's own test files (`test_dashboard_{findings,evidence,overview,history,
accessibility,security,security_matrix}.py`), which are intact at this commit — they describe
the old frontend that ships as historical reference on `frontend/workbench-redesign`, not this
clean base. **Do not delete these tests merely because a new frontend is being built.** If a
future frontend rebuild on top of *this* branch replaces frontend files those tests reference,
document and retire the specific obsolete assertions rather than silently deleting them — the
same discipline this handoff itself was produced under.

## U. Out of scope — restated plainly

Antigravity must not modify: the security/analysis engine, PCAP ingestion, TShark-based
dissection, SMTP/IMAP/POP3 reconstruction, the STARTTLS/STLS state machine, TLS analysis,
certificate extraction, cryptographic posture analysis, evidence states, findings, scoring,
cross-session reasoning, baseline logic, AI/ML anomaly analysis, provenance, hashing/forensic
integrity, report generation (JSON/HTML/PDF), existing API semantics, or any security/analysis
test. If the new frontend needs data the current API does not expose, the correct action is to
say so explicitly and propose a minimal, additive API change for separate review — never to
fabricate the field on the frontend, and never to change backend behavior unilaterally to make
the UI easier to build.
