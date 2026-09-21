# 23 — Analyst Dashboard (Phase 10)

**Status:** Design · **Date:** 2026-09-21 · **Decisions:** ADR-0022, ADR-0010 (Accepted)
**Closes:** OQ-41 · **Consumes:** `PostureAssessment` (ADR-0016) via the Phase-8 API
**Baseline:** `v0.4.0-phase9` = `0019c6f`, 697 tests passing
**Satisfies:** R-04

> Status discipline: sections are labelled `DESIGN` until implemented, then
> `IMPLEMENTED`, `VERIFIED` or `MEASURED`. §16–§18 carry test evidence, visual QA and
> measurements and are the only places a completion claim may rest.

---

## 1. Purpose and requirement grounding

R-04, quoted from the authoritative verification
(`docs/research/19-authoritative-ps-verification.md` §91):

> R-04 dashboard | Yes — **"Interactive visualization dashboard"** | CONFIRMED

`requirements-traceability.md` maps it to *"analyst views"*, phase 10, verified by an
*"e2e smoke"* across *"all scenes"*.

Phase 9 made the assessment readable as a document. A document is something an analyst
reads once. Phase 10 makes it **navigable**: filterable findings, per-protocol posture,
and a path from a capture in a list to the evidence behind a single conclusion.

It adds **no security capability**. Every severity, band, score, citation, remediation
string and ML statement shown was produced by Phase 4–7 code.

## 2. Scope

**In:** dashboard projection, view model, four screens, client-side filtering, lifecycle
and error states, static serving, one additive list-projection API field, accessibility,
security boundary, tests, visual QA.

**Out (deliberately):** authentication, user accounts, RBAC, multi-tenancy, live capture,
SIEM integration, SPF/DKIM/DMARC, new ML, LLM/RAG, attacker attribution, threat-intel
enrichment, packet-level drill-down (§6 records why), and any new detection.

**No authentication is implemented.** This remains a local single-analyst prototype
(ADR-0011). The dashboard binds to loopback with the API and must not be exposed on a
network interface. Stated here because an unstated absence reads as an oversight.

## 3. Architecture — DESIGN

```
   PostureAssessment.to_dict()          ← the sole security authority
              │
              ▼
   dashboard/projection.py              Python. Reorders, labels, groups, counts what
              │                         already exists. Never reinterprets.
              ▼
   DashboardViewModel  (JSON)
              │
              ▼
   dashboard/static/  ES modules        textContent + createElement only
   ┌──────────┬───────────┬─────────────┬──────────┐
   │ History  │ Overview  │  Findings   │ Evidence │
   └──────────┴───────────┴─────────────┴──────────┘
              │
              ▼
   existing Phase-8/9 API               no new per-analysis endpoint
```

```
src/securemailscope/dashboard/
    __init__.py
    projection.py     assessment dict -> DashboardViewModel
    model.py          view-model dataclasses; DASHBOARD_SCHEMA_VERSION
    vocabulary.py     canonical enum -> label/marker, shared with reporting's vocabulary
    static/
        index.html    app shell
        app.js        router + API client
        views/*.js    history · overview · findings · evidence
        style.css     tokens mirrored from reporting/styles.py
```

**Dependency rule.** `dashboard/` consumes the canonical dict. **No earlier package
imports `dashboard/`**: not `posture`, `analysis`, `crosssession`, `ml`, `session`,
`evidence`, `dissect`, `ingest`, and not `reporting`. `backend/api.py` composes it, as
it composes `reporting/`. Asserted by extending the existing AST tests.

**The dashboard never touches a PCAP**, never runs tshark, never reconstructs a session,
never reads the database directly, and never executes the security engine. Its only
input is HTTP JSON.

## 4. The data contract — DESIGN

Three categories, kept explicitly separate because conflating them is how a viewer
starts inventing facts.

### 4a. Canonical security data — displayed, never altered

Carried through as strings and already-decided numbers:

`overall_posture` · `score.{value,band,formula_id,starting_value,total_penalty,components[],basis}` ·
`coverage.{sessions_total,sessions_assessed,sessions_abstained,assessed_fraction,observation_counts,observation_fractions,completeness_counts,protocol_counts}` ·
`issue_groups[].{issue_class,fact_kind,dimension,severity,title,certainty,recurrence,affected_stream_keys,protocols[],penalising,citations[],remediation,finding_count}` ·
`prioritised[].{rank,priority_score,affected_sessions,factors,ml_adjustment,explanation,representative_finding{...}}` ·
`abstentions[].{reason,issue_class,what_could_not_be_concluded,why,resolved_by,rule_id,stream_key,protocol,frames}` ·
`protocol_posture[].{protocol,sessions,score,issue_classes,dimensions_assessed,dimensions_not_observable,abstentions}` ·
`risk_summary.{by_severity,by_dimension,by_fact_kind,highest_severity,affected_sessions,anomaly_signals,behavioural_deviations,issue_groups,abstentions{total,by_reason,by_issue_class,how_to_resolve}}` ·
`standards_summary.{standards,distinct_standards,unmapped_citations,note}` ·
`remediation_summary[]` · `model_summary` · `provenance.{rule_ids,source_counts,...}` ·
`limitations[]` · `versions` · `ai_enabled` · identities.

### 4b. Presentation-only transformations — permitted

Underscores to spaces (`INSUFFICIENT_EVIDENCE` → `INSUFFICIENT EVIDENCE`); a text
severity marker so severity survives greyscale and screen readers; grouping existing
counts into bar rows; building filter option lists from values **actually present**;
sorting rows by a user-chosen canonical column; formatting a stored fraction as a
percentage.

Each is reversible and changes no meaning.

### 4c. Unavailable — must never be manufactured

| Not available | Why |
|---|---|
| Per-session finding rows | `fused_findings` is not in `to_dict()`; only groups and prioritised representatives are |
| Packet/byte-level drill-down | the API exposes no packet endpoint; the dashboard has no PCAP access |
| Per-finding timestamps | not in the contract |
| Attack probability, confidence %, compliance %, risk %, detection rate, affected hosts, packets analysed | never computed by any phase |
| A "health" or "security" percentage | the only percentage in the system is `coverage.assessed_fraction` |

Where a screen would naturally want one of these, it states the absence (§9) rather than
approximating it.

## 5. No recomputation — DESIGN

Forbidden in `dashboard/`: computing or altering a score, band, severity, risk,
certainty, observability, recurrence, priority order, anomaly conclusion, remediation
text or standards mapping.

`prioritised[]` renders in the order the assessment supplies. A user may re-sort the
view; the underlying data is untouched and the default is always canonical rank. No
threshold anywhere decides that something "is an attack", "is safe", or "needs
attention" — the assessment already decided, using `penalising`, `severity` and
`status`.

Architecture tests assert `dashboard/` defines no score constants, performs no severity
arithmetic, and imports no posture engine internals.

## 6. API: planned change vs not planned — DESIGN

**Canonical detail source, unchanged:**
`GET /api/v1/analyses/{run_id}/assessment` is and remains the authority for everything
a screen reasons about. Overview, Findings and Evidence read only from it.

**One additive change — the history list gap.**

Measured at `0019c6f`: a list item carries `run_id, state, capture_id, assessment_id,
ai_enabled, formula_id, created_at, started_at, completed_at, duration_ms,
ingest_status, error_code, error_message, source_filename, backend_version, replayed`
— and **no posture, no score**. Meanwhile the same assessment's row already stores
`overall_posture="ADEQUATE"` and `score_value=88.0`.

Those columns exist because **ADR-0017 Decision 3 created them "used for listing and
filtering only"**. The API simply never joined them. Phase 10 adds two optional fields
to `RunResponse`:

```
overall_posture: Optional[str]   # from assessments.overall_posture
score_value:     Optional[float] # from assessments.score_value
```

Read from storage, not computed. Additive and backwards compatible: every existing field
keeps its name, type and meaning, so the Phase-8/9 baseline tests stay valid unchanged.
ADR-0017's constraint still binds — these are a listing projection, **never an
authority**; the detail screens ignore them and read the document.

**One view-model endpoint — corrected at Milestone 4.**
`GET /api/v1/analyses/{run_id}/dashboard` returns `DashboardViewModel.to_dict()`.

This section originally said "no `/dashboard` endpoint". That was **wrong, and it
contradicted ADR-0022 Decision 2**, which fixes the data path as
`to_dict() → projection.py → DashboardViewModel → JSON → ES modules`. A projection
written in Python cannot reach a browser without a transport, so either the endpoint
exists or the projection moves into JavaScript — and moving it would put it beyond the
AST tests that stop a presentation layer growing a severity table, which is the whole
reason Decision 2 chose Python. The ADR is the binding decision; this paragraph was the
error and is corrected rather than quietly satisfied.

The concern behind the original wording still stands and is met: the endpoint is **not**
a second place where "what the dashboard shows" is decided. It serves the output of the
one projection, which is tested to be semantically lossless against the canonical
document. It introduces no field the assessment does not already contain, and
`GET /api/v1/analyses/{run_id}/assessment` remains the canonical authority — the view
model is derived from it on every request and is never stored.

**Still not planned:** no packet endpoint, no aggregate-statistics endpoint, no search
endpoint, no auth endpoints.

**Static serving:** the shell is mounted read-only from a fixed package directory. No
path is built from user input; no repository source, database or artifact directory is
reachable through it.

## 7. Information architecture — DESIGN

### Screen 1 — History (`#/`)
> *Which analyses exist, and what happened to each?*

From `GET /api/v1/analyses` (one request): `source_filename`, `state`, `overall_posture`,
`score_value`, `capture_id`, `created_at`, `duration_ms`, `ai_enabled`. Filter by state.
Row → Overview. Non-`COMPLETED` rows show their lifecycle state and never a posture.

### Screen 2 — Overview (`#/run/{run_id}`)
> *What is the posture, and how much of the traffic supports it?*

Posture **and coverage in one block**, never separable (the ADR-0016 §4 hazard, carried
forward from doc 21 §20 and doc 22 §7). Then: per-protocol posture with
`dimensions_not_observable` shown beside `dimensions_assessed`; severity, dimension and
fact-kind distributions from `risk_summary`; top prioritised findings; the ML panel; and
report actions.

### Screen 3 — Findings (`#/run/{run_id}/findings`)
> *What requires attention, and on what basis?*

Prioritised table in canonical rank order, expandable to conclusion, explanation,
citations, remediation, frames and rule ids. **Severity, priority and ML adjustment are
three labelled columns**, never merged into one "risk" number.

**Filters — only fields verified present in the canonical schema.** Inspected on a real
capture before specifying:

| Filter | Source | Note |
|---|---|---|
| Severity | `representative_finding.severity` | present on every entry |
| Status | `representative_finding.status` | present |
| Certainty | `representative_finding.certainty` | present; observed values include `CONFIRMED`, `UNDETERMINED` |
| Observability | `representative_finding.observability` | present on the finding, **absent from `issue_groups`** |
| Fact kind | `representative_finding.key.fact_kind` | nested under `key`, not top-level |
| Issue class | `representative_finding.key.issue_class` | nested under `key` |
| Dimension | `representative_finding.dimension` | present |
| Protocol | `representative_finding.session.protocol` | **nullable — see below** |

**Protocol is nullable and that matters.** It is not a top-level field; it lives at
`session.protocol`, and on a real capture the `ANOMALY` entry carried `protocol: None`
while the base issue carried `"smtp"`. A naive protocol filter would silently drop
findings that are not attributed to one protocol. The filter therefore renders an
explicit **"not attributed to a protocol"** option rather than omitting those rows.

`frames` may legitimately be `[]`; the UI shows "no frame references recorded", not an
empty cell.

**No free-text search** is offered: the contract has no searchable evidence corpus
beyond these fields, and a box that searched only titles would imply otherwise.

### Screen 4 — Evidence & provenance (`#/run/{run_id}/evidence`)
> *Why does SecureMailScope say this, and what could it not determine?*

Abstentions with `why` and `resolved_by`, plus `risk_summary.abstentions.how_to_resolve`;
`limitations`; `standards_summary` **including `unmapped_citations`** — a real gap the
engine reports about itself and the dashboard surfaces rather than hides; `provenance`
with `rule_ids` and `source_counts`; identities and versions; artifact integrity from
`GET .../artifacts?verify=true`.

It also states plainly what is **not** available: no packet-level drill-down, and
per-session findings are not part of the contract.

### Analyst workflow

```
submit PCAP (API/CLI)
   → History: run appears with its lifecycle state
   → run completes → Overview: posture + coverage together
   → Findings: filter to what matters, read severity/certainty/standard/remediation
   → Evidence: what was abstained from, what is not observable, which rules ran
   → Reports: HTML / PDF / JSON for the same assessment_id
```

## 8. Relationship to the Phase-9 reporting layer — DESIGN

Two presentations of one assessment, deliberately different: the report is a **fixed,
citable, content-addressed artefact**; the dashboard is a **navigable view**.

The dashboard **links to** `GET /api/v1/analyses/{run_id}/reports` and
`.../reports/{html|pdf|json}`. It **never** renders a report itself, never duplicates
the projection in `reporting/`, and never stores an artefact. `dashboard/` does not
import `reporting/`. If the two ever disagree, the assessment is the tiebreaker and one
of them has a defect.

## 9. States — DESIGN

| State | Shown as |
|---|---|
| Loading | explicit in-progress indicator; never an empty screen implying "nothing found" |
| Empty catalog | "no analyses yet", with how to submit one |
| Non-terminal run (`CREATED`/`VALIDATING`/`QUEUED`/`RUNNING`/`FINALIZING`) | the state itself, no posture, **no invented percentage** — the API exposes no progress fraction |
| `COMPLETED` | full dashboard |
| `FAILED` | `error_code` and `error_message` from the API envelope; never a stack trace or path |
| `CANCELLED` | stated, with the superseding run where recorded |
| `RECOVERY_REQUIRED` | stated as interrupted |
| `INSUFFICIENT_EVIDENCE` | **its own treatment** — not a failure, not a pass; the withheld band, the coverage that caused it, and the statement that a withheld band is not a passing result |
| Unknown run | "no such analysis" |
| Malformed assessment | explicit schema-violation state; the dashboard refuses rather than guessing |
| API/network failure | distinct from "no data"; retry offered |

Six failure modes, six distinct messages. *"Something went wrong"* is not acceptable in
a forensic tool.

**Data freshness:** manual refresh by default. Non-terminal runs poll at a fixed, slow
interval with a bounded attempt count; polling stops the moment a run reaches a terminal
state. No unbounded loop.

## 10. Forensic honesty in the UI — DESIGN

These must remain visually distinct and are never merged into one red/green chip:

`OBSERVED_ISSUE` · `COMPLIANT` · `AMBIGUOUS` · `NOT_OBSERVABLE` · `INSUFFICIENT_EVIDENCE`
· abstention · `BASE_SECURITY_ISSUE` vs `BEHAVIOURAL_DEVIATION` vs `ANOMALY_SIGNAL` vs
`POSITIVE_EVIDENCE` · `CONFIRMED`/`PROBABLE`/`UNCERTAIN`/`UNDETERMINED` ·
`OBSERVABLE`/`PARTIALLY_OBSERVABLE`/`NOT_OBSERVABLE`.

**Absence of an observed issue is never rendered as "secure".** A protocol with no
findings shows what was assessed and what was not observable.

**ML presentation.** `model_summary.role` verbatim, its `limitations` verbatim, and a
plain statement that the lane contributes a bounded ordering adjustment and cannot set a
severity, create a finding or change the score. Forbidden phrasings — "AI detected an
attack", "AI found malicious traffic", "AI confirmed an intrusion", "AI detected TLS
stripping" — are asserted absent by test, as they are in the report.

## 11. Security boundary — DESIGN

Everything the API returns derives from a capture; a capture is hostile input.

| Rule | Enforcement |
|---|---|
| No `innerHTML` / `outerHTML` / `insertAdjacentHTML` | structural test greps shipped JS |
| No `eval` / `new Function` / `document.write` | same test |
| No `href`/`src` from API data | only same-origin report URLs from a validated `run_id` + fixed format allowlist |
| `javascript:` / `data:` URLs | impossible: no URL is ever taken from data |
| Text insertion only | `textContent` / `createElement` |
| CSS injection | no style string is built from data; severity maps to a fixed class name from a known vocabulary |
| Unknown enum values | rendered as raw text; never mapped to a default, never crash |
| Malformed / wrong-typed JSON | explicit error state |
| Oversized responses | bounded rendering; pagination uses existing API limits |
| Path traversal via static mount | fixed package directory, no user input in paths |
| Client-side validation as security | never — the API remains the boundary |

`run_id` is validated client-side against the same 32-hex shape the API enforces, so a
malformed id never reaches a request URL. This is defence in depth, not the boundary.

## 12. Accessibility — DESIGN

Semantic landmarks and heading order; keyboard reachability for every control with a
visible focus ring; `<table>` with `<caption>` and `<th scope>`; labelled inputs;
accessible names on icon-only controls; status conveyed by **text plus** colour, never
colour alone (severity carries a text marker, as in the report); `aria-live` for
filter-result counts; contrast checked against WCAG 2.1 AA ratios.

**Claims will be bounded by what is actually tested.** Automated structural checks and
manual keyboard walkthrough are planned; a full WCAG audit with assistive technology is
not, and §17 will say so rather than claiming compliance.

## 13. Responsive — DESIGN

Desktop/laptop first: this is an analyst workstation tool. Verified down to a narrower
browser width without breaking tables. Known pressure points to check: long issue
titles, 64-char capture ids, long remediation text, the wide findings table.

## 14. Dependencies — DESIGN

**Zero npm packages. Zero new Python runtime dependencies.**

| Considered | Verdict |
|---|---|
| React / Vue / Svelte + build tooling | rejected — ADR-0022 Decision 1 |
| Jinja2 templates | rejected — installed but undeclared; adds a runtime dep for no gain |
| Chart.js / D3 | rejected — five bar rows; a chart that cannot be read as a table is decoration |
| A CSS framework | rejected — the design derives from the Phase-9 vocabulary |
| A state library | rejected — one fetched document and a filter object |

FastAPI's `StaticFiles` (already a backend dependency) mounts the shell.

## 15. Performance — DESIGN

To be measured, not asserted: assessment payload size, projection time, initial render,
filter latency, and behaviour on a large assessment (many issue groups and prioritised
entries). Targets are deliberately not stated in advance; §18 will report measurements.

Avoided by design: refetching the assessment per screen (fetched once per run and held
in memory), and re-rendering the whole table on each filter keystroke.

## 16. Test evidence — PENDING

## 17. Visual QA and accessibility verification — PENDING

## 18. Performance — PENDING

## 19. Requirements

R-04 may move to COMPLETE **only** when the four screens exist, are driven by a real
assessment produced from a real PCAP through the real API, handle the lifecycle and
error states in §9, survive the hostile-content matrix in §11, and have been visually
inspected. A page existing does not qualify.

## 20. Limitations — PENDING

## 21. What Phase 10 can and cannot claim

**Can:** that the dashboard displays the canonical assessment without reinterpreting it,
that it distinguishes the evidence states the project is built to distinguish, and that
it adds no security capability.

**Cannot:** any new detection, any improvement in accuracy, any validation of the ML
lane, WCAG conformance beyond what was tested, multi-user or authenticated operation, or
packet-level forensic drill-down.
