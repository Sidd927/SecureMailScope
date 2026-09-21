# ADR-0017 — One catalog database, canonical assessment stored as a document
**Status:** Accepted 2026-09-21 · **Supersedes:** ADR-0007 · **Detail:** `docs/architecture/21`

**Context** ADR-0007 was accepted on 2026-09-16, during research, three phases before
`PostureAssessment` existed. It specified **one SQLite database per analysis run, keyed
by capture hash**, holding *"structured evidence/sessions/findings/baselines/anomaly
scores"*. Phase 7 then established a single canonical output object and the rule that
every later layer consumes it and recomputes nothing (ADR-0016, `docs/architecture/19`).
Phase 8 has to store results, so the two decisions now meet.

**Problem** Implementing ADR-0007 literally today would contradict ADR-0016.

---

## Decision 1 — Findings are not shredded into tables

The canonical assessment is persisted as its **JSON document** (`to_dict()`), with only
a narrow band of metadata lifted into indexed columns.

**Rejected: normalising findings, severities, groups and anomaly scores into relational
tables** — the literal ADR-0007 reading. A `findings` table with a `severity` column is a
second, independently-writable representation of a security conclusion. It invites a
future `SELECT ... WHERE severity='HIGH'` that disagrees with `issue_groups`, and a
migration that silently re-derives a verdict. ADR-0016 forbids recomputation; the surest
way to honour that is to make recomputation structurally impossible by never
decomposing the conclusion in the first place.

**Consequence** The database cannot express a security opinion. It stores bytes produced
by the posture engine and hands them back unaltered. The cost is that SQL cannot query
*inside* an assessment; §3 addresses the queries that actually matter.

## Decision 2 — One catalog database, not one database per run

**Rejected: one SQLite file per run.** It was a reasonable default when a "run" was a
single-analyst one-shot, but it cannot answer `GET /api/v1/analyses` without scanning a
directory and opening every file, it has no transactional boundary spanning runs, and
idempotency (§21 of the Phase-8 brief) would require reading N databases to discover
that a capture was already analysed. Listing and deduplication are both first-class
Phase-8 requirements; per-run files make both accidental.

**Selected** one `securemailscope.db` containing `schema_meta`, `runs`, `assessments`,
`artifacts`, `run_events`. WAL mode, `foreign_keys=ON`, one serialized writer.

**Retained from ADR-0007** SQLite over PostgreSQL (no server dependency, offline,
single workstation); PCAPs and future rendered reports on the filesystem, never as
blobs in the database. Those parts of ADR-0007 were correct and are unchanged.

## Decision 3 — Indexed metadata is chosen, not exhaustive

Lifted into columns: `capture_id`, `assessment_id`, `content_sha256`, `overall_posture`,
`score_value`, `ai_enabled`, `schema_version`, `engine_version`, `generated_at`,
`sessions_total`, `sessions_assessed`.

**Rejected: indexing every nested field** because it is possible. Thirty tables to
support queries nobody has asked for is the over-engineering the Phase-8 brief warns
against, and every extra projection is another chance for the copy to drift from the
document. These eleven exist because listing, filtering and idempotency need them.

`overall_posture` and `score_value` are **projections for listing only**. They are
written from the document in the same transaction and are never read back as an
authority — retrieval always returns the stored document.

## Decision 4 — `assessment_id` is the canonical key; `content_sha256` is the guard

`assessment_id` is the primary key of `assessments`, unchanged and uninterpreted.
Verified empirically before adopting it (`docs/architecture/21` §7): identical content
across two runs with different `run_id` and `generated_at` produced
`7209908f07f69abf` both times, and an `ai_enabled=True` run produced a different id.

Every row also stores `content_sha256`, the SHA-256 of the canonical JSON.

**Rejected: trusting `assessment_id` alone to imply identical content.** The id hashes
`capture_id`, the schema version and each group's
`(issue_class, fact_kind, severity, recurrence)`. It deliberately excludes `model_summary`
and `limitations`, which *do* differ between an AI-enabled and an AI-disabled run. In the
observed case the ML lane added an `ANOMALY` group and the ids diverged anyway — but that
is a consequence of the ML lane happening to emit a group, not a guarantee the contract
makes. A model that flagged nothing would collide.

**Rejected: changing the hash to include `ai_enabled`.** Phase 7 is frozen, the exclusion
of run-varying inputs is deliberate and load-bearing for reproducibility, and this is a
storage concern that storage can solve.

**Selected: fail closed.** Re-persisting content whose `content_sha256` matches is an
idempotent no-op. Re-persisting *different* content under an existing `assessment_id`
raises `AssessmentIdentityConflict`; the run is recorded `FAILED` with that reason. The
backend never silently overwrites a stored conclusion, and never fabricates a second
contradictory one.

---

**Consequences** + one queryable catalog; + the stored conclusion is byte-recoverable;
+ the database is structurally incapable of duplicating the security engine;
+ listing and idempotency are cheap. − no SQL querying inside an assessment;
− one writer at a time (§19 of the brief, an accepted documented invariant, not an
accident); − an `assessment_id` collision surfaces as an error an operator must read
rather than being auto-resolved.

**Risks** A future contributor adds a `findings` table "for the dashboard" and
reintroduces the second representation this ADR exists to prevent → the schema is
asserted by test, and `docs/architecture/21` §5 states the prohibition where a schema
author will encounter it.

**Open questions** OQ-51: does the document-plus-projection model still hold when
Phase 9 needs cross-capture trend queries, or does that justify a derived read-model
rebuilt from documents (never written independently)?
