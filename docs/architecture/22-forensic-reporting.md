# 22 — Forensic Reporting (Phase 9)

**Status:** Implemented · **Date:** 2026-09-21 · **Decisions:** ADR-0019, ADR-0020, ADR-0021
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

**Dependency rule.** The security engine never depends on its presentation layer:
`posture ↛ reporting`, `analysis ↛ reporting`, `ml ↛ reporting`, and likewise for
`session`, `evidence`, `dissect` and `ingest`.

`reporting/` imports **nothing from `backend/` at runtime** either. The artifact store
and repository are injected and their types referenced only under `TYPE_CHECKING`, so
the dependency runs one way — `backend/api.py` composes `reporting/`, not the reverse.
An import cycle between the two would otherwise be real, and a lazy import hiding it
would be worse than not having one. Both claims are asserted by test: structurally by
the AST walker (which skips `TYPE_CHECKING` blocks, because it must distinguish an
annotation from a dependency) and directly by a subprocess that inspects `sys.modules`.

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

## 17. Test evidence — VERIFIED

**697 passed, 0 failed, 0 skipped, 0 xfail.** Phase 1–8 baseline of 549 preserved
intact; Phase 9 adds 148.

| File | Count | Covers |
|---|---:|---|
| `test_reporting_projection.py` | 38 | projection, vocabulary, always-present sections, limits |
| `test_reporting_html.py` | 36 | structure, offline standalone, escaping/XSS, semantics, determinism |
| `test_reporting_pdf.py` | 32 | PDF validity, content, determinism, escaping, layout regressions |
| `test_reporting_api.py` | 35 | artifacts, integrity, endpoints, failure isolation, cross-format equivalence |
| `test_backend_architecture.py` | +7 | reporting boundaries |

**Load-bearing results:**

- `test_semantic_equivalence_across_formats` — four fixtures, each rendered three ways;
  assessment id, capture id, posture word, score, coverage percentage, issue identity
  and severity, standards, limitations, ML role and abstentions agree across HTML text,
  extracted PDF text and canonical JSON. **§46 satisfied**, and this is the mitigation
  ADR-0020 promised for composing the PDF from the model rather than from the HTML.
- `test_json_endpoint_equals_the_assessment_endpoint` — `.../reports/json` is
  byte-equal to `.../assessment`. The report layer reconstructs nothing.
- `test_hostile_payloads_are_escaped` — eight XSS payloads through issue titles,
  conclusions and limitations; asserted against the **parsed tree** (no `script`/`img`/
  `svg` element, no attribute beginning `on`), each surviving as readable text.
- `test_no_attribute_carries_assessment_text` — every attribute in the hostile document
  is checked for `<`, `>` and `alert`.
- `test_pdf_failure_leaves_assessment_and_html_intact` — with `render_pdf` raising, the
  PDF endpoint is 503, the run stays `COMPLETED` with null `error_code`, HTML and the
  assessment still return 200, and no `pdf` artefact was fabricated.
- `test_corrupted_report_is_regenerated_not_served` — a stored report overwritten with
  `TAMPERED` is regenerated; the served bytes equal the original.
- `test_pdf_rendering_is_byte_deterministic` / `test_rendering_is_byte_deterministic` —
  identical bytes across a 1.1 s gap a wall-clock timestamp would not survive.
- `test_insufficient_evidence_is_never_softened_in_pdf` / `..._never_reads_as_a_pass` —
  the withheld band reaches both formats as `INSUFFICIENT EVIDENCE` with `Not scored`.
- `test_security_engine_never_imports_reporting` — `posture`, `analysis`,
  `crosssession`, `ml`, `session`, `evidence`, `dissect`, `ingest` import no reporting
  module.
- `test_reporting_html_and_projection_need_no_third_party_package` — subprocess asserts
  `reportlab`, `fastapi`, `pydantic`, `jinja2`, `markupsafe`, `pypdf` are all absent
  from `sys.modules` after importing the projection and HTML renderer.

**End-to-end on a real capture:** a Postfix PCAP submitted to a live uvicorn server with
`ai=true` produced all three formats with correct content types, a `%PDF-` magic, and
`pcap`, `html` and `pdf` artefacts all verifying `OK`.

**Not verified / not attempted:** rendering fidelity in browsers other than the one used
for QA, printed output on physical paper, assessments larger than ~300 issue groups,
screen-reader behaviour with an actual assistive technology, and any locale or
right-to-left rendering.

## 18. Visual QA — VERIFIED

Rasterised with PyMuPDF at 105–110 dpi and inspected page by page; HTML inspected in a
browser. Fixtures covered: clean/no-findings, typical, high-severity with
contradictions, low-coverage/withheld-band, many-findings, abstention-heavy,
AI-enabled, and a real Postfix capture.

**Two defects were found by looking and are fixed:**

1. **Table headers broke mid-word.** `PROTOCOL` rendered as "PROTO COL", `ADEQUATE` as
   "ADEQU ATE", `ABSTENTIONS` as "ABSTEN TIONS" — a purely proportional column split
   squeezed short columns below the width of a single word. Columns now claim their
   longest word first and only the surplus is distributed by weight. Two regression
   tests lock it in.
2. **Bar-chart counts drifted to the page edge**, detached from the bars they labelled.
   Meter column narrowed so the number sits beside its bar.

Checked and found clean after the fixes: page breaks, repeated table headers across
pages, no blank pages, no clipping or overflow on the 10-column findings table, footer
and page numbers on every page, long evidence strings wrapping rather than widening a
column, and the withheld-band treatment rendering in its own hue with its notice.

**Limitation stated honestly:** this was rasterised inspection by the author, not a
review by a print professional or an accessibility audit with assistive technology.

## 19. Performance — MEASURED

Median of repeated runs, Python 3.9.6, macOS. Measured, not estimated.

| Stage | Typical (2 groups, 1 abstention) | Large (120 groups, 80 abstentions) |
|---|---:|---:|
| Projection | 0.1 ms | 1.0 ms |
| HTML render | 0.1 ms | 1.4 ms |
| PDF render | 26.0 ms | 305.4 ms |
| HTML size | 19.9 KB | 156 KB |
| PDF size | 17.4 KB | 77.6 KB |
| PDF pages | 7 | 33 |

Projection and HTML are effectively free. PDF composition dominates and scales roughly
linearly with content, which is why PDF is generated on request and cached by content
hash while HTML is cheap enough to render any time. These are measurements on two
assessments, **not** a benchmark, and say nothing about pathological inputs beyond the
§15 limits.

## 20. Requirements — assessed

**R-03 (JSON / PDF / HTML): COMPLETE.** All three formats exist, are retrievable over
HTTP, and carry the canonical content. JSON is byte-equal to the assessment endpoint;
HTML is a standalone offline document; PDF is a real, parseable, paginated document with
extractable text. Semantic equivalence across the three is asserted.

**R-05 (forensic reports): COMPLETE.** A rendered artefact exists and carries capture
SHA-256, assessment id, run id, analysis timestamp, engine and schema versions, frame
references, standards basis, evidence coverage, abstentions with their resolution paths,
limitations and ML role. Artefacts are content-addressed by `report_sha256`, stored
through the Phase-8 store, and integrity-verified on access.

**No A- or D- requirement changes.** Phase 9 adds no detection. **A-02 is unchanged:**
the report displays `model_summary.role` and the ADR-0015 limitations and makes no
claim about ML detection value.

## 21. Limitations

1. The report shows the **analysis** time, not a print time (ADR-0021 Decision 1). Stated
   in the report itself.
2. A stored assessment keeps the `run_id` of the run that first produced it (doc 21
   §19), so a report for a replayed run shows the originating run id inside the
   document.
3. HTML and PDF are styled twice from shared design tokens; ReportLab's layout
   vocabulary is not CSS. Divergence is guarded by semantic equivalence, not by identical
   styling.
4. Visual QA was rasterised inspection by the author — not a print-professional review
   and not an accessibility audit with assistive technology.
5. PDF requires the optional `reporting-pdf` extra. Without it the endpoint returns a
   structured 503; JSON and HTML are unaffected.
6. Report artefacts are never pruned; like the Phase-8 catalog, storage grows unbounded.
7. Truncation limits (§15) are engineering choices bounding page count and render time,
   not measurements. Truncation is always disclosed.
8. Charts are limited to severity distribution and coverage, both rendered with their
   numbers as text. No derived metric is computed for display.

## 22. What Phase 9 can and cannot claim

**Can:** that the rendered artefacts carry the same security semantics as the canonical
assessment, that they are reproducible and integrity-verifiable, and that the reporting
layer adds no interpretation.

**Cannot:** any new detection, any improvement in accuracy, any validation of the ML
lane, certificate conclusions, attacker attribution, or that a report has been reviewed
by a human.
