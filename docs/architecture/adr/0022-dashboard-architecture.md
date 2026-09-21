# ADR-0022 — Zero-dependency ES-module dashboard, projected in Python
**Status:** Accepted 2026-09-21 · **Closes:** OQ-41 · **Resolves:** ADR-0010 (now Accepted)
**Detail:** `docs/architecture/23` · **Consumes:** `PostureAssessment` (ADR-0016)

**Context** R-04 — *"Interactive visualization dashboard"*, confirmed against the live
portal in `docs/research/19-authoritative-ps-verification.md` §91 — is the last
confirmed requirement outstanding. ADR-0010 proposed *"a static SPA built to static
assets, served by the same FastAPI app"* in 2026-09-16 and left **OQ-41 — SPA framework,
pick at Phase 10 (lean: minimal deps)** open. Phase 10 has to answer it with a decision,
not a preference.

**Problem** Which frontend stack, where does the dashboard's data come from, and what
stops a presentation layer from quietly becoming a second security engine?

---

## Decision 1 — Vanilla ES modules, no framework, no build step

**Selected:** plain ES modules (`import`/`export`), `fetch`, DOM APIs, one CSS file.
**Zero npm packages. Zero new Python runtime dependencies. No build artefact.**

**Rejected: React + TypeScript + Vite.** It is the default answer and it is the wrong
one here. It introduces a `node_modules` tree of several hundred transitive packages
into a project whose core has been deliberately zero-dependency since Phase 1 (ADR-0011,
offline/air-gapped), and a build step whose output must either be committed as generated
artefacts or rebuilt by every evaluator. Doc 08 §2 makes demo reliability paramount and
§4 already names the failure mode — *"Dashboard JS error → reports viewable directly"*.
A toolchain is one more thing that can be broken on demo day, and it buys reactivity
that a read-mostly forensic viewer does not need. The dashboard's entire job is: fetch
one JSON document, render tables and panels, filter client-side. That is comfortably
within the platform.

**Rejected: server-rendered Jinja templates.** Jinja is installed in this environment
but undeclared, and adding it as a runtime dependency to render pages the API can
already serve as JSON trades the zero-dependency property for nothing. It also weakens
the client-side filtering R-04's *"interactive"* implies.

**Rejected: a charting library.** The only honest visual quantities are small integer
counts — `risk_summary.by_severity`, `by_dimension`, `by_fact_kind`,
`abstentions.by_reason`. Those are bar rows with their numbers printed beside them
(doc 22 §8 established that a chart which cannot be read as a table is decoration).
Importing a charting runtime to draw five bars would be dependency sprawl.

**Consequence:** no framework escaping. Every insertion is manual, so the security
boundary is a discipline the code must hold rather than a default it inherits — which is
why Decision 4 makes it a structural test rather than a convention.

**OQ-41 is closed.** ADR-0010's intent — a static SPA served by the same FastAPI app,
reading the existing API, offline, single deployable — is preserved exactly; only the
framework question it deferred is now answered, with "none".

## Decision 2 — The projection is Python, not JavaScript

`PostureAssessment.to_dict()` → `dashboard/projection.py` → `DashboardViewModel` → JSON
→ ES modules render it.

**Rejected: projecting in JavaScript.** The projection is where a presentation layer is
most tempted to reinterpret — to bucket severities, to decide what counts as "healthy",
to collapse three flavours of not-knowing into one grey chip. In Python it is guarded by
the same AST architecture tests that already keep `backend/` and `reporting/` from
growing a severity table, and its contract tests run inside the existing pytest suite
rather than needing a second test runner and a second CI story.

This mirrors Phase 9 exactly: one projection, walked by renderers that contain no logic.

## Decision 3 — The history list gets the projection that already exists

`GET /api/v1/analyses` currently returns no posture and no score, so a history screen
would need one request per row. But `assessments` already stores `overall_posture` and
`score_value` as indexed columns that **ADR-0017 Decision 3 created for exactly this**:
*"used for listing and filtering only"*.

**Selected:** join those stored columns into the list response as
`overall_posture` and `score_value`.

**Rejected: computing them in the API.** They are written from the document inside the
assessment's own transaction. Nothing is recomputed; a value that already exists is
being returned.

**Rejected: N+1 fetches from the browser.** Twenty rows would mean twenty assessment
documents — tens of kilobytes each — fetched to display one word per row.

**Rejected: adding a bespoke `/dashboard` endpoint.** The dashboard needs no data the
API lacks. A convenience endpoint would become a second place where "what the dashboard
shows" is decided.

The constraint ADR-0017 attached to those columns still holds: they are a **listing
projection and never an authority**. `GET /api/v1/analyses/{run_id}/assessment` remains
the canonical source for anything a screen actually reasons about, and the detail views
read only from it.

## Decision 4 — API data is untrusted, enforced structurally

Everything the API returns ultimately derives from a capture, and a capture is hostile
input. The dashboard therefore uses `textContent` and `createElement` only.

**Forbidden in `dashboard/static/`, asserted by a test that greps the shipped JS:**
`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`,
`new Function`, and `href`/`src` assigned from API data.

**Rejected: sanitising on insertion.** Sanitisers are a denylist in disguise; the safe
property is never constructing markup from data at all. The only `href` values in the
dashboard are same-origin report URLs built from a validated `run_id` and a fixed format
allowlist — never a string the API supplied.

**Rejected: relying on a framework's escaping.** There is no framework (Decision 1), and
Phase 9 already found the alternative reasoning sound: explicit escaping at every call
site beats an autoescape setting a later edit can switch off (ADR-0019 Decision 2).

Unknown enum values render as their raw text rather than crashing or being mapped to a
default — a future severity the dashboard has never heard of must not silently become
`INFO`.

---

**Consequences** + no build step, no npm tree, no new runtime dependency; + one
deployable, offline, demo-stable; + the projection is testable in the existing suite;
+ the history list costs one request. − no framework ergonomics, so DOM code is manual
and its safety rests on a structural test; − no component library, so the design system
is hand-built from the Phase-9 `reporting/styles.py` vocabulary.

**Risks** A contributor reaches for `innerHTML` for convenience → the structural test
fails the build. A future screen needs data the API lacks → the answer is a justified
additive backend change, documented, not a client-side derivation (doc 23 §6).

**Open questions** OQ-57: if a future phase needs per-session or per-packet drill-down,
that is a backend capability question (`fused_findings` is absent from `to_dict()`), not
a dashboard one — should the assessment contract expose it, or should the dashboard link
into a report instead?
