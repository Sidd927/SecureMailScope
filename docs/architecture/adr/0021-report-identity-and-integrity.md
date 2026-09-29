# ADR-0021 — A report is a pure function of its assessment
**Status:** Accepted 2026-09-21 · **Detail:** `docs/architecture/22` ·
**Builds on:** ADR-0017 (artifact integrity), ADR-0020 (byte determinism)

**Context** Phase 8 established content-addressed identity for captures (`capture_id` =
SHA-256 of the bytes) and assessments (`assessment_id`, content-derived and
run-independent). Phase 9 produces a third artefact class that an analyst may cite,
email or archive, so it needs an identity of the same quality.

**Problem** What identifies a report, and how does anyone verify that the PDF in their
hands is the one the system produced?

---

## Decision 1 — The report carries no wall-clock time of its own

`ReportDocument.generated_at` is taken from `assessment["generated_at"]`. The renderer
never calls `datetime.now()`.

**Rejected: stamping the report with its own generation time.** It is the obvious thing
to do and it destroys the property everything else here depends on: with a live
timestamp the same assessment renders to different bytes every time, so the report can
no longer be content-addressed and two archived copies of one conclusion cannot be shown
to be the same document.

The analysis time is already the forensically meaningful one — it is when the evidence
was interpreted. When a report was printed is not a fact about the evidence. Where
generation metadata genuinely matters (renderer version, schema version) it is recorded
as *metadata* in the artifact row, outside the rendered bytes.

**Consequence** The report is a pure function of the canonical assessment. Same
assessment in, same bytes out, on any machine, at any time.

## Decision 2 — `report_sha256` is the report identity

```
capture_id     = SHA-256 of the PCAP bytes            (Phase 1)
assessment_id  = content-derived, run-independent      (Phase 7)
report_sha256  = SHA-256 of the rendered report bytes  (Phase 9)
artifact_id    = storage handle                        (Phase 8)
```

Four identities, none of which is the others.

**Rejected: a random UUID as the report's only identity.** It would say which row a
report came from and nothing about what the report contains — two renders of one
assessment would look like two different documents, and a tampered file would keep its
id. **Rejected: reusing `assessment_id` as the report id** — one assessment yields
several artefacts (HTML, PDF), so the id would not be unique and the formats could not
be distinguished.

`assessment_id` is untouched. Phase 7 remains frozen; this adds an identity beside it.

## Decision 3 — Integrity reuses the Phase-8 artifact store

Reports are stored through `ArtifactStore` with `kind` of `html` or `pdf`, gaining the
existing streamed hashing, the `artifacts` table, `verify()` re-reading and re-hashing,
and the `?verify=true` reporting path. The store was already kind-parameterised and
carried a comment reserving this use.

**Rejected: a separate report store.** Two artifact stores would mean two integrity
models, and the weaker one would eventually be the one someone trusted.

A report whose bytes no longer hash to the recorded value is reported as
`ARTIFACT_INTEGRITY_ERROR`. The API does not claim an artefact is intact without
re-reading it.

## Decision 4 — Version metadata makes incompatibility explicit

Every artifact row records `REPORT_SCHEMA_VERSION`, the renderer version, and the
assessment's own `schema`/`engine` versions. A report is regenerated rather than served
when the stored artefact is missing, fails verification, or was produced under a
different report schema or renderer version.

**Rejected: serving whatever is on disk.** A report produced by an older renderer, served
under a newer schema's assumptions, is precisely the kind of silent misreading the
project refuses elsewhere (ADR-0017 refuses a newer database schema rather than guessing
at it). Report version and posture-engine version are recorded as distinct fields so
neither can be mistaken for the other.

---

**Consequences** + a report can be cited by hash; + two renders of one assessment are
provably the same document; + tampering is detectable; + no new integrity machinery.
− the rendered document does not show when it was printed, which may surprise a reader
expecting a print timestamp, so doc 22 §11 states plainly that the shown time is the
analysis time.

**Risks** A future renderer change silently alters bytes for an unchanged assessment →
renderer version is recorded per artefact and participates in the regeneration decision.

**Open questions** OQ-56: should reports be detached-signed once a key-management story
exists, so integrity survives leaving this system? Out of scope now — the project does
not claim cryptographic integrity it cannot demonstrate.
