# 21 — Backend, Persistence and API (Phase 8)

**Status:** Implemented · **Date:** 2026-09-21 · **Decisions:** ADR-0017, ADR-0018
**Builds on:** ADR-0011 (modular monolith) · **Consumes:** `PostureAssessment` (ADR-0016)
**Baseline:** `v0.2.0-phase7` = `9b3e6e4`, 443 tests passing

> Status discipline: sections are labelled `IMPLEMENTED`, `VERIFIED` or `MEASURED`.
> §17 carries the test evidence and §17a the measurements; they are the only places a
> claim of verification rests on something other than reading the code.

---

## 1. Purpose

Phase 7 produces one canonical object and stops. Phase 8 makes that object reachable:

```
POST a capture → run the existing pipeline → persist → GET the same conclusion back
```

It adds **no security capability whatsoever**. Every severity, score, band, citation,
remediation string and ML statement in a Phase-8 response was produced by Phase 4–7 code
and passed through unaltered. If Phase 8 ever appears to produce a security fact, that is
a defect.

## 2. Scope

**In:** analysis orchestration, job lifecycle, SQLite persistence, artifact store with
integrity verification, FastAPI `/api/v1`, request/error schemas, status and listing,
resource limits, restart recovery, idempotency, structured logging, JSON retrieval.

**Out (deliberately):** dashboard/frontend, PDF/HTML rendering, LLM or RAG, new ML
models, new detections, certificate-analysis expansion, SPF/DKIM/DMARC/DNS, attacker
attribution, active scanning, live monitoring, cloud/Kubernetes, authentication beyond
what a local single-analyst prototype needs. Phases 9+ own these.

## 3. Architecture — IMPLEMENTED

```
                 HTTP client
                      │
                      ▼
        ┌─────────────────────────────┐
        │  api.py      FastAPI /api/v1│  transport only
        │  schemas.py  pydantic       │
        └──────────────┬──────────────┘
                       ▼
        ┌─────────────────────────────┐
        │  service.py  AnalysisService│  the only orchestrator
        └──┬────────┬────────┬────────┘
           │        │        │
           ▼        ▼        ▼
     lifecycle  artifacts  pipeline.py ──► Phase 2–7 engines (unmodified)
           │        │        │                      │
           └────────┴────────┴──────────────────────┘
                       ▼                  PostureAssessment
        ┌─────────────────────────────┐            │
        │  repository.py / db.py      │ ◄──────────┘
        │  SQLite catalog             │   stored as a document
        └─────────────────────────────┘
```

Package `src/securemailscope/backend/`:

| Module | Responsibility |
|---|---|
| `errors.py` | error taxonomy; stable codes; HTTP mapping |
| `limits.py` | resource limits, layered over `config.Config` |
| `db.py` | connection, pragmas, schema, migration, transactions |
| `repository.py` | runs / assessments / artifacts / events CRUD |
| `lifecycle.py` | `JobState` + validated transition table |
| `artifacts.py` | content-addressed store, SHA-256, integrity re-verification |
| `pipeline.py` | PCAP → `PostureAssessment`; composition only |
| `service.py` | validate → run → persist → complete; recovery; idempotency |
| `schemas.py` | pydantic transport models |
| `api.py` | routes |

**Dependency rule.** `backend/` may import from every earlier package. **No earlier
package may import `backend/`.** Phase 8 is a leaf. Asserted by test (§17), matching the
AST tests that already separate `posture/` from `ml/`.

## 4. The orchestration gap this phase closes — IMPLEMENTED

Audited at `0eeb6f1`: **no production callable goes from a PCAP to a `PostureAssessment`.**
`analyze_capture()` stops at normalized frames and explicitly produces no verdicts. The
only end-to-end composition in the repository is the `pipeline()` helper inside
`tests/test_posture_corpora.py` — a test fixture.

`backend/pipeline.py` promotes that sequence into production code **verbatim in
ordering and configuration**:

```
analyze_capture                     → AnalysisRun, FrameEvidence[]
reconstruct_sessions                → SessionEvidence[]
SecurityAnalysisEngine().analyse    → SecurityFinding[]
CrossSessionEngine().analyse        → CrossSessionFinding[]
[AnomalyEngine, only when ai=True]  → MLAnomalyResult[]
PostureEngine(PostureConfig).assess → PostureAssessment
```

This is composition, not reimplementation. No engine is subclassed, no parameter is
re-tuned, no intermediate result is edited. The ML lane keeps the exact fit/threshold
procedure the Phase-7 tests use (`fit(rows)`, `set_threshold(rows, 0.95)` on the same
capture's rows) — reproducing it rather than improving it is the point, because §28 of
the Phase-8 brief requires the backend and a direct invocation to agree.

`ai_enabled` defaults to **False**, matching `PostureConfig`.

## 5. Persistence model — IMPLEMENTED

ADR-0017 supersedes ADR-0007's per-run databases. One catalog:

```sql
schema_meta(key TEXT PRIMARY KEY, value TEXT)

runs(run_id TEXT PRIMARY KEY,
     capture_id TEXT, state TEXT, previous_state TEXT,
     created_at, started_at, completed_at,
     ai_enabled INT, formula_id TEXT,
     assessment_id TEXT REFERENCES assessments(assessment_id),
     ingest_status TEXT,              -- Phase-2 RunStatus, verbatim
     error_code TEXT, error_message TEXT,
     source_filename TEXT,            -- display only, never a path
     duration_ms INT, backend_version TEXT)

assessments(assessment_id TEXT PRIMARY KEY,
            content_sha256 TEXT NOT NULL,
            capture_id TEXT NOT NULL,
            document TEXT NOT NULL,       -- to_dict(), canonical JSON
            overall_posture TEXT, score_value REAL,   -- projections, listing only
            ai_enabled INT, schema_version TEXT, engine_version TEXT,
            sessions_total INT, sessions_assessed INT,
            generated_at TEXT, stored_at TEXT)

artifacts(artifact_id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(run_id),
          kind TEXT, sha256 TEXT, size_bytes INT,
          relative_path TEXT, created_at TEXT, original_filename TEXT)

run_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,
           run_id TEXT REFERENCES runs(run_id),
           from_state TEXT, to_state TEXT, at TEXT, detail TEXT)
```

**The database holds no security logic.** There is no `findings` table, no `severity`
column, no `risk` column. `overall_posture` and `score_value` are projections written
from the document inside the same transaction, used for listing and filtering only, and
**never read back as an authority** — retrieval always returns `document`. A future
contributor adding a findings table would recreate the second representation ADR-0017
exists to prevent.

Pragmas: `journal_mode=WAL`, `foreign_keys=ON`, `synchronous=FULL` (durability over
throughput — this is a forensic store). `schema_meta` carries
`BACKEND_SCHEMA_VERSION`; a database written by a newer schema is refused rather than
silently upgraded.

## 6. Job lifecycle — IMPLEMENTED

```
CREATED ──► VALIDATING ──► QUEUED ──► RUNNING ──► FINALIZING ──► COMPLETED
   │            │             │          │             │
   └────────────┴─────────────┴──────────┴─────────────┴──────► FAILED
   └────────────┴─────────────┴──────────┴─────────────┴──────► CANCELLED

   any non-terminal state observed at startup ──► RECOVERY_REQUIRED ──► FAILED
```

Terminal: `COMPLETED`, `FAILED`, `CANCELLED`. Non-terminal: everything else.

Transitions are an explicit table. Anything absent from it raises `InvalidTransition`;
`COMPLETED → RUNNING` is rejected, not silently accepted. Every transition writes a
`run_events` row with both endpoints and a timestamp, so a failed run can be
reconstructed after the fact.

This enum is **separate from Phase 2's `RunStatus`**, which stays untouched and is stored
alongside as `ingest_status`. ADR-0018 Decision 1 records why conflating evidence quality
with job scheduling is a mistake.

## 7. Identity — VERIFIED

Three identities, deliberately distinct:

| Identity | Meaning | Source |
|---|---|---|
| `capture_id` | the bytes analysed | SHA-256 of the PCAP (Phase 1) |
| `run_id` | one execution attempt | uuid4 per run |
| `assessment_id` | the conclusion reached | content-addressed (Phase 7) |

Measured at `0eeb6f1` on `postfix_smtp_plaintext_session.pcap` rather than inferred:

| Probe | Result |
|---|---|
| `capture_id == sha256(file)` | true |
| two runs, same content, different `run_id`/`generated_at` | `7209908f07f69abf` twice — stable |
| `ai_enabled=True` | `3bee22038adfbb2d` — differs |
| score and band, ai vs no-ai | identical |
| full document, ai vs no-ai | differs (`model_summary`, `limitations` 5 → 8) |

`assessment_id` hashes `capture_id`, `POSTURE_SCHEMA_VERSION` and each group's
`(issue_class, fact_kind, severity, recurrence)`. It excludes `run_id` and timestamps
**by design**, which is what makes it reproducible.

`content_sha256` is therefore computed over the document **minus `run_id` and
`generated_at`** (`repository.RUNTIME_FIELDS`). Hashing the whole document would make a
legitimate re-run of one capture — which produces the same conclusion with a new run id
and a new timestamp — indistinguishable from a genuine divergence. The guard uses the
same notion of "content" the canonical id uses, so it stays silent on run-varying
metadata and sensitive to a differing `model_summary` or `limitations`. Both directions
are asserted by test.

**Consequence:** when a second run reproduces an existing assessment, the **first**
document is retained and its embedded `run_id` names the run that produced it. That is
correct — the assessment is content-addressed and run-independent — but a client
fetching run B's assessment sees run A inside the document. The response envelope
carries the requested `run_id`, so the association is never ambiguous. Recorded in §19.

The AI-enabled run differed only because the ML lane emitted an extra `ANOMALY` group.
That is an observed consequence, not a contract guarantee: a model flagging nothing would
collide. Storage therefore keeps `content_sha256` and **fails closed** on divergence
(ADR-0017 Decision 4) rather than assuming the id is sufficient. **No Phase-7 change is
required or made.**

## 8. Artifact store — IMPLEMENTED

```
<data_dir>/
    securemailscope.db
    artifacts/<capture_id[:2]>/<capture_id>/<artifact_id>.pcap
```

Paths are built from **generated internal identifiers only**. The client filename is
stored as `original_filename` for display and never touches the filesystem — no
traversal, no `..`, no absolute path, no symlink target, no NUL, no shell character can
reach a path. Every artifact records `artifact_id`, `kind`, `sha256`, `size_bytes`,
`relative_path`, `created_at`, `original_filename`.

`verify(artifact)` re-hashes on demand and returns a mismatch as
`ArtifactIntegrityError`. An artifact altered after persistence is surfaced, never
silently accepted. Forensic identity is the hash; the filename is a label.

## 9. API — IMPLEMENTED

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | liveness, versions, database reachability |
| POST | `/api/v1/analyses` | submit a capture, run it, return the run |
| GET | `/api/v1/analyses` | list runs, paginated, newest first |
| GET | `/api/v1/analyses/{run_id}` | run status and metadata |
| GET | `/api/v1/analyses/{run_id}/assessment` | the canonical document |
| GET | `/api/v1/analyses/{run_id}/artifacts` | artifact metadata |

Submission accepts `multipart/form-data` (browser/`curl -F`) and
`application/octet-stream` (scripted, no multipart parser involved). Both are bounded by
`Content-Length` **before** the body is read.

The assessment response returns `to_dict()` **verbatim**. No field is renamed, removed,
flattened or recomputed. `coverage`, `limitations` and `model_summary` are required.
`INSUFFICIENT_EVIDENCE` is never mapped to `UNKNOWN` or to a success value, and
`NOT_OBSERVABLE` / `AMBIGUOUS` / `INSUFFICIENT_EVIDENCE` are never collapsed together.

Pydantic models exist for requests, errors and list items — things the backend owns. The
assessment schema is **not** re-declared in pydantic; that would create the second
contract ADR-0018 Decision 3 rejects.

## 10. Error model — IMPLEMENTED

One envelope:

```json
{"error": {"code": "CAPTURE_TOO_LARGE", "message": "...",
           "detail": {...}, "run_id": null}}
```

| Code | HTTP |
|---|---|
| `INVALID_REQUEST` | 400 |
| `UNSUPPORTED_INPUT` | 415 |
| `CAPTURE_VALIDATION_FAILED` | 422 |
| `CAPTURE_TOO_LARGE` | 413 |
| `RESOURCE_LIMIT_EXCEEDED` | 429 |
| `NOT_FOUND` | 404 |
| `INVALID_LIFECYCLE_TRANSITION` | 409 |
| `ASSESSMENT_IDENTITY_CONFLICT` | 409 |
| `ARTIFACT_INTEGRITY_ERROR` | 500 |
| `ANALYSIS_FAILED` | 500 |
| `PERSISTENCE_FAILED` | 500 |
| `TSHARK_UNAVAILABLE` | 503 |
| `INTERNAL_ERROR` | 500 |

No stack trace, no filesystem path and no SQL ever reaches a client. Failures are logged,
persisted onto the run where one exists, and returned through this envelope.

## 11. Resource limits — IMPLEMENTED

Existing Phase-2 limits are **reused, not replaced**: `max_capture_bytes` (2 GiB),
`max_frames` (2 000 000), `tshark_timeout_s` (300). Phase 8 adds only what HTTP
introduces:

| Limit | Default | Rationale |
|---|---|---|
| `max_upload_bytes` | `min(256 MiB, max_capture_bytes)` | an HTTP body is buffered; the 2 GiB file ceiling is for on-disk captures. Never raises the Phase-2 ceiling. |
| `max_concurrent_analyses` | 1 | ADR-0018: one writer. Explicit invariant, not an accident. |
| `max_queued_jobs` | 8 | bounds memory under burst; rejected with `429`, not dropped. |
| `max_analysis_seconds` | 600 | ≥ `tshark_timeout_s`, bounds the whole pipeline. |
| `max_page_size` | 100 | bounds listing responses. |

All are environment-overridable (`SMS_*`) like `Config`. None silently weakens a
previously established safety limit; `max_upload_bytes` is clamped to `max_capture_bytes`
so raising one cannot bypass the other.

## 12. Concurrency — IMPLEMENTED

One serialized writer, guarded by a process-level lock; SQLite WAL permits concurrent
readers throughout. Listing and retrieval never block behind an analysis.

`max_concurrent_analyses = 1` is a **documented invariant**, stated here because the
Phase-8 brief requires the distinction between an intentional constraint and an
accidental one. Submissions beyond the limit queue; beyond `max_queued_jobs` they are
refused with `RESOURCE_LIMIT_EXCEEDED`.

## 13. Recovery — VERIFIED

On startup the service sweeps every run in a non-terminal state. Nothing but an
interrupted process can leave a run there, so each is moved
`→ RECOVERY_REQUIRED → FAILED` with `error_code = ANALYSIS_INTERRUPTED`, recorded in
`run_events`.

**No interrupted run is ever reported `COMPLETED`.** `COMPLETED` and the assessment row
are written in one transaction (ADR-0018 Decision 2), so a crash before commit leaves
no assessment and no completion; a crash after commit leaves both. There is no window
in which one exists without the other.

Interrupted analyses are not resumed. The capture is content-addressed and the pipeline
deterministic, so re-submission is cheap and produces the same `assessment_id`.

## 14. Idempotency — IMPLEMENTED

Default: same `capture_id` + same `(ai_enabled, formula_id)` returns the existing
completed run, flagged as a replay. `?force=true` runs an independent analysis against the
same capture. Deduplication keys on `capture_id` — never on the attacker-controlled
filename. Rationale and rejected alternatives: ADR-0018 Decision 4.

## 15. AI boundary — VERIFIED

The backend passes `ai_enabled` into `PostureConfig` and does nothing else with ML. It
does not read, interpret, threshold, re-band, re-weight or store an ML conclusion
separately; it does not touch `MAX_ML_ADJUSTMENT`; it adds no model. `model_summary` and
the ML limitations travel through to the API untouched.

`ai_enabled=False` is the default. §17 records the equivalence check.

## 16. Security considerations — IMPLEMENTED

Uploads and every identifier are untrusted input.

| Vector | Control |
|---|---|
| path traversal / absolute / NUL in filename | filenames never build paths; internal ids only |
| symlink artifact target | artifacts written to generated paths under the data dir |
| oversized body | `Content-Length` checked before reading; streamed to disk |
| malformed multipart | parser errors → `INVALID_REQUEST`, never a 500 |
| malformed / oversized JSON | bounded body, pydantic validation |
| invalid `run_id` | format-validated before any query; parameterised SQL only |
| SQL injection | parameterised statements exclusively |
| resource exhaustion | §11 limits |
| hostile PCAP **content** | treated as data end-to-end; never executed, never interpreted as instruction |
| injected text in captured mail | Phase 7 already guarantees every analyst-visible string originates in a rule, a standard registry entry or a remediation template — never from a capture |

Logging records `run_id`, `capture_id`, `assessment_id`, transitions, durations and
failure classes. It records **no** payloads, credentials, mail contents or filesystem
paths. Logs must not become a second copy of the sensitive material the tool analyses.

## 17. Test evidence — VERIFIED

**549 passed, 0 failed, 0 skipped, 0 xfail.** Phase-7 baseline of 443 preserved intact;
Phase 8 adds 106. Real Postfix and Dovecot captures from OQ-33r drive the end-to-end
tests; they skip cleanly when tshark or the captures are absent.

| File | Count | Covers |
|---|---:|---|
| `test_backend_persistence.py` | 40 | lifecycle table, transitions and rejections, schema, repository CRUD, identity discipline, limits |
| `test_backend_pipeline.py` | 25 | artifacts, integrity, service lifecycle, orchestration, recovery, idempotency, equivalence |
| `test_backend_api.py` | 30 | HTTP surface, error mapping, security matrix |
| `test_backend_architecture.py` | 11 | structural boundaries |

**Load-bearing results:**

- `test_backend_matches_direct_invocation` — the document served through the backend
  equals a direct engine invocation across `assessment_id`, `score`, `coverage`,
  `risk_summary`, `issue_groups`, `prioritised`, `abstentions`, `protocol_posture`,
  `standards_summary`, `remediation_summary`, `model_summary`, `provenance`,
  `limitations`, `versions`, `ai_enabled`. **§28 of the Phase-8 brief is satisfied.**
- `test_no_ai_equivalence_through_backend` — identical score, band, standards,
  remediation and penalising groups with the ML lane on and off.
- `test_no_ai_run_never_touches_ml_engine` — spies on `AnomalyEngine.__init__` and
  asserts zero calls; `--no-ai` is honoured by not taking the branch, not merely by
  discarding a result.
- `test_interrupted_run_is_never_reported_completed` — a run is stranded in `RUNNING`,
  the database is reopened, and the run is `FAILED` with `ANALYSIS_INTERRUPTED`, no
  assessment, and zero completed runs.
- `test_completion_and_assessment_commit_atomically` — a crash inside the commit leaves
  the run `FINALIZING` and no stored assessment.
- `test_capture_id_is_sha256_of_stored_artifact` — the forensic chain holds end to end.
- `test_tampered_artifact_is_detected` — a byte-level edit after persistence surfaces.
- `test_hostile_filename_never_reaches_disk` — uploading as
  `../../../../tmp/pwned.pcap` creates no such file; the name survives as a label.
- `test_hostile_pcap_text_is_data_not_instruction` — injected instruction text never
  appears in a served assessment.
- `test_phase_seven_source_is_untouched` — `git diff v0.2.0-phase7 HEAD` shows no change
  under any Phase 1–7 source directory.

**Not verified / not attempted:** behaviour under real concurrent multi-process access,
databases beyond a few dozen runs, captures near the 256 MiB upload ceiling, recovery
from a corrupted database file, and any deployment property beyond a local prototype.

## 17a. Performance — MEASURED

Median of repeated runs on `postfix_smtp_plaintext_session.pcap` (1 session, 14 KB
assessment), macOS, Python 3.9.6, 16 runs in the catalog. Measured, not estimated.

| Operation | Median |
|---|---:|
| Direct pipeline, no backend | 115.4 ms |
| Backend submit (validate + artifact + pipeline + persist) | 119.7 ms |
| **Backend overhead** | **4.3 ms (3.7 %)** |
| Assessment persist | 0.3 ms |
| Assessment retrieve | 39 µs |
| List 20 runs | 19 µs |
| Artifact integrity verify | 34 µs |

The Phase-7 analysis cost dominates by roughly 27×; the backend adds single-digit
milliseconds. `synchronous=FULL` was chosen over throughput and costs well under a
millisecond per commit at this size, so the durability guarantee is effectively free
here. These figures are a sanity check on a small capture, **not** a benchmark: they say
the architecture does not degrade Phase-7 performance, and nothing about behaviour at
gigabyte scale (OQ-52).

## 18. Requirements touched

Phase 8 advances delivery, not detection. Expected effect: **R-03** JSON retrieval moves
from library-only to served over HTTP (PDF/HTML remain Phase 9, so R-03 stays PARTIAL);
**R-05** gains durable, retrievable, integrity-checked storage but still renders no
artefact, so it stays PARTIAL. **A-01 through A-05 are unchanged** — Phase 8 adds no
detection capability and must not alter their status. `requirements-traceability.md` is
updated only for what is verified.

## 19. Limitations

1. One analysis at a time; throughput is not a design goal.
2. Interrupted analyses fail rather than resume.
3. No authentication or authorization — a local single-analyst prototype (ADR-0011).
4. No SQL querying inside an assessment document (ADR-0017 Decision 1).
5. Artifact integrity is verified on demand, not continuously.
6. Assessment retention and pruning are unimplemented; the catalog grows unbounded.
7. `assessment_id` collision across differing ai-modes is handled by failing closed, not
   by a richer identity — deliberately, because Phase 7 is frozen.
8. A stored assessment keeps the `run_id` of the run that **first** produced it. A later
   run reproducing the same conclusion references it rather than storing a second copy
   (§7). The envelope carries the requested run id, so nothing is ambiguous, but the two
   values inside and outside the document can differ.

## 20. What Phase 8 can and cannot claim

**Can:** that a capture submitted over HTTP is analysed by the existing engines, that the
resulting canonical assessment is stored durably and returned unaltered, that job state
is explicit and crash-safe, and that the backend adds no security interpretation.

**Cannot:** any new detection capability, any improvement in posture accuracy, any
validation of the ML lane, production-readiness, or security of a deployment beyond the
local prototype ADR-0011 describes.
