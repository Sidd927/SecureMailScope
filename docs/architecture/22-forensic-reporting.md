# 22 — Forensic Reporting (Phase 9)

**Status:** Design · **Date:** 2026-09-21 · **Decisions:** ADR-0019, ADR-0020, ADR-0021
**Implements:** ADR-0009 (one canonical object, three renderers) · **Closes:** OQ-40
**Consumes:** `PostureAssessment` (ADR-0016) via the Phase-8 API (doc 21)
**Baseline:** `v0.3.0-phase8` = `a46781a`, 549 tests passing
**Satisfies:** R-03 (JSON/PDF/HTML), R-05 (forensic reports)

> Status discipline: sections are labelled `IMPLEMENTED`, `VERIFIED` or `MEASURED`.
> §17 carries test evidence, §18 visual QA, §19 measurements. Nothing is claimed
> complete on the strength of the code reading correctly.

---

## 1. Purpose

Phase 8 made the canonical assessment retrievable as JSON. An analyst cannot hand JSON
to a reviewer. Phase 9 renders the same conclusion as a forensic document:

```
PostureAssessment → projection → ReportDocument → { HTML, PDF }
                                       ↓
                        content-addressed artifacts → API
```

It adds **no security capability**. Every severity, score, band, citation, remediation
string and ML statement in a report was produced by Phase 4–7 code. The report is the
most quotable artefact the system produces, which is exactly why it is the last place
allowed an opinion of its own.

## 2. Scope

**In:** report projection, canonical report document model, HTML renderer, PDF renderer,
report artifacts and integrity, report API, design system, accessibility, security
(escaping, safe filenames), determinism, tests.

**Out (deliberately):** LLM or generative summarisation of any kind, dashboards, new
detections, new metrics, charts unsupported by canonical data, certificate conclusions,
attacker attribution.

## 3. Architecture — IMPLEMENTED

```
                 PostureAssessment.to_dict()      ← the only input
                             │
                             ▼
                   projection.py   (reorders, labels, formats — never reinterprets)
                             │
                             ▼
                   model.ReportDocument           ← canonical report structure
                       │             │
            ┌──────────┘             └──────────┐
            ▼                                   ▼
         html.py  (stdlib only)            pdf.py  (ReportLab, optional)
            │                                   │
            └──────────────┬────────────────────┘
                           ▼
                  service.py → Phase-8 ArtifactStore (kind=html|pdf)
                           ▼
                        api.py → /api/v1/analyses/{run_id}/reports
```

Package `src/securemailscope/reporting/`:

| Module | Responsibility |
|---|---|
| `model.py` | `ReportDocument` + sections; `REPORT_SCHEMA_VERSION` |
| `projection.py` | canonical dict → `ReportDocument` |
| `styles.py` | design tokens; severity/evidence label vocabulary |
| `html.py` | standalone HTML; escaping; print CSS |
| `pdf.py` | ReportLab composition from the same model |
| `service.py` | render, hash, persist, verify, regenerate |
| `errors.py` | report-specific error codes |

**Dependency rule.** `reporting/` imports from `posture/` and `backend/` contracts.
**No earlier package imports `reporting/`.** `posture ↛ reporting`, `analysis ↛
reporting`, `ml ↛ reporting`. The security engine never depends on its presentation
layer. Asserted by test, extending the Phase-8 AST tests.

## 4. The projection — IMPLEMENTED

The projection may **reorder, group, label and format**. It may not **reinterpret**.

Sections: `ReportMetadata · ExecutiveSummary · ScopeSection · PostureSection ·
CoverageSection · ProtocolSection · PrioritisationSection · FindingsSection ·
StandardsSection · RemediationSection · ModelTransparencySection · AbstentionSection ·
LimitationsSection · ProvenanceSection · MethodologySection · IntegritySection`.

A section whose canonical data is absent is **omitted**, except where omission would
hide a limitation — coverage, limitations, abstentions and ML transparency are always
rendered, stating the absence explicitly rather than disappearing.

## 5. No recomputation — IMPLEMENTED

Forbidden in `reporting/`: computing a score, band, severity, risk, certainty,
observability, recurrence, priority order, anomaly conclusion or remediation text.

Severity, band, certainty and observability cross the boundary as **strings**. No
arithmetic is performed on any of them. The prioritised list is rendered in the order
the assessment supplies; no sort key is applied. Architecture tests assert that
`reporting/` performs no comparison or arithmetic on severity values and defines no
score constants.

**`fused_findings` is not in `to_dict()`.** The report therefore renders issue groups
and the prioritised representatives, and **fabricates no per-session finding rows**.
`IssueGroup.recurrence` and `affected_stream_keys` carry the true scope.

## 6. Vocabulary preserved — IMPLEMENTED

| Canonical | Rendered as | Never rendered as |
|---|---|---|
| `INSUFFICIENT_EVIDENCE` | `INSUFFICIENT EVIDENCE` | Unknown · Safe · Pass |
| `NOT_OBSERVABLE` | `NOT OBSERVABLE` | Pass · Fail · N/A |
| `AMBIGUOUS` | `AMBIGUOUS` | resolved either way |
| `UNCERTAIN` / `UNDETERMINED` | as written | Low risk |
| `COMPLIANT` | `COMPLIANT` (no score credit) | Secure |

Certainty (`CONFIRMED · PROBABLE · UNCERTAIN · UNDETERMINED`) and observability
(`OBSERVABLE · PARTIALLY_OBSERVABLE · NOT_OBSERVABLE`) are separate columns. Severity is
never reduced because certainty is low — the three-dimension separation Phase 7 enforces
structurally is preserved visually.

## 7. Coverage is never separated from posture — IMPLEMENTED

The executive summary renders `overall_posture` and `coverage` **in the same block**.
There is no layout in which a band appears without its assessed fraction. Below the
Phase-7 floor the band is already withheld as `INSUFFICIENT_EVIDENCE`; the report states
why and shows the fraction that caused it. This is the hazard ADR-0016 §4 identified and
doc 21 §20 flagged as Phase 9's to carry.

## 8. Metrics discipline — IMPLEMENTED

Rendered only if present in the canonical document. **Never invented:** packets
analysed, affected hosts, attack probability, confidence percentage, compliance
percentage, risk percentage, detection rate, remediation completion.

The only percentage in the report is `coverage.assessed_fraction`, which the assessment
supplies. Charts are limited to data the assessment already contains (severity
distribution across issue groups, coverage) and are rendered as accessible bar
representations with their numbers shown as text beside them — a chart that cannot be
read as a table is decoration.

## 9. HTML strategy — IMPLEMENTED

Zero dependencies (`html.escape` + composition, no template engine — ADR-0019
Decision 2). Single standalone file: inline CSS, no CDN, no webfont, no script, no
external image. Opens from disk with no server. Semantic elements (`<main>`, `<section>`,
`<h1>`–`<h3>`, `<table>` with `<caption>`, `<th scope>`), print CSS with
`break-inside: avoid` on findings and `@page` margins.

**Escaping is applied at every interpolation.** All assessment-derived text — protocol
names, banners, evidence strings, filenames, identifiers, rule ids — is untrusted PCAP
provenance and treated as data, never markup.

## 10. PDF strategy — IMPLEMENTED

ReportLab, composed from the same `ReportDocument` (ADR-0020, resolves OQ-40). Pure
Python, offline, no system libraries, Python 3.9. `invariant=1` for byte determinism.
A4, page numbers, running footer carrying the assessment id, table splitting across
pages, explicit wrapping for long evidence strings.

Optional: `pip install 'securemailscope[reporting-pdf]'`. Absent ReportLab yields a
structured `REPORT_RENDERER_UNAVAILABLE`; HTML and JSON are unaffected.

## 11. Identity and determinism — IMPLEMENTED

The report is a **pure function of the assessment** (ADR-0021). `generated_at` comes
from the assessment; the renderer never reads the clock. Same assessment → identical
bytes → stable `report_sha256`.

The timestamp shown in the report is therefore the **analysis** time, not a print time.
Stated in the report itself so no reader infers otherwise.

## 12. Artifacts and integrity — IMPLEMENTED

Stored through the Phase-8 `ArtifactStore` with `kind` `html` / `pdf`. Recorded:
`artifact_id`, `run_id`, `kind`, `sha256`, `size_bytes`, `created_at`. Report metadata
(`report_schema_version`, `renderer_version`, `assessment_id`) travels in the API
response. `verify()` re-reads and re-hashes; a mismatch is surfaced, never assumed away.

**Regeneration** when the artefact is missing, fails verification, or was produced under
a different report schema or renderer version. A report from an incompatible renderer is
never silently served.

## 13. Failure isolation — IMPLEMENTED

```
analysis COMPLETED + assessment persisted + PDF renderer failed
    →  run stays COMPLETED
    →  report artifact reported as failed, with a code
    →  no fabricated artefact row
```

HTML failure does not affect the assessment. PDF failure does not affect HTML. Report
generation is never part of the analysis transaction (ADR-0019 Decision 4).

## 14. API — IMPLEMENTED

| Method | Path | Returns |
|---|---|---|
| GET | `/api/v1/analyses/{run_id}/reports` | available reports + integrity metadata |
| GET | `/api/v1/analyses/{run_id}/reports/html` | `text/html` |
| GET | `/api/v1/analyses/{run_id}/reports/pdf` | `application/pdf`, attachment |
| GET | `/api/v1/analyses/{run_id}/reports/json` | `application/json` — the canonical document |

`.../reports/json` returns exactly what `.../assessment` returns. The assessment
endpoint remains the canonical JSON contract; the report endpoints are consumers of it
and reconstruct nothing.

Download filenames are generated from internal ids —
`securemailscope-<assessment_id>.<ext>` — never from the uploaded PCAP name. An unknown
format is a structured 400 listing the supported formats.

## 15. Resource limits — IMPLEMENTED

Phase-8 limits are reused. Report-specific additions, each with a stated reason:

| Limit | Default | Rationale |
|---|---|---|
| `max_report_findings` | 500 | bounds page count and render time; excess is truncated **visibly**, never silently |
| `max_evidence_chars` | 2000 | one pathological evidence string cannot dominate a page; truncation is marked |
| `max_report_bytes` | 32 MiB | bounds artifact growth |
| `max_pdf_seconds` | 120 | bounds a runaway render |

Truncation is always disclosed in the document. A report that quietly dropped findings
would be worse than one that failed.

## 16. Security — IMPLEMENTED

| Vector | Control |
|---|---|
| XSS via assessment-derived text | `html.escape(..., quote=True)` at every interpolation; no raw sinks |
| script/style injection | no script or style content is ever interpolated; CSS is a literal |
| path traversal in download name | filenames generated from `assessment_id`, sanitised |
| artifact path traversal | Phase-8 store: paths from generated ids only |
| artifact overwrite | new `artifact_id` per render; never writes over an existing path |
| MIME confusion | content type fixed per format, not derived from any name |
| corrupted artifact | re-hash on access; `ARTIFACT_INTEGRITY_ERROR` |
| malformed assessment | projection validates required keys and refuses rather than guessing |
| oversized evidence | §15 limits |

**Trust boundary:** PCAP-derived text is data, never an instruction, and never a
template, HTML, shell or SQL fragment. Phase 7 already guarantees every analyst-visible
string originates in a rule, a standards entry or a remediation template; Phase 9 escapes
regardless, because defence in depth is cheaper than the assumption.

## 17. Test evidence — PENDING

## 18. Visual QA — PENDING

## 19. Performance — PENDING

## 20. Requirements

R-03 and R-05 may move to COMPLETE **only** when JSON, HTML and PDF all exist, are
retrievable, are integrity-verified, and carry the canonical evidence and provenance.
Architecture alone does not qualify. Assessed honestly in §20 once §17–§19 are filled.

## 21. Limitations — PENDING

## 22. What Phase 9 can and cannot claim

**Can:** that the rendered artefacts carry the same security semantics as the canonical
assessment, that they are reproducible and integrity-verifiable, and that the reporting
layer adds no interpretation.

**Cannot:** any new detection, any improvement in accuracy, any validation of the ML
lane, certificate conclusions, attacker attribution, or that a report has been reviewed
by a human.
