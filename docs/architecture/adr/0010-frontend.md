# ADR-0010 — Dashboard: static SPA served by the backend
**Status:** **Accepted 2026-09-21** (was Proposed 2026-09-16) · **OQ-41 closed by [ADR-0022](0022-dashboard-architecture.md)**

> Accepted unchanged in intent. The static SPA served by the same FastAPI app, reading
> the existing API, offline and single-deployable, is what Phase 10 implements. The one
> question this ADR deferred — **OQ-41, which SPA framework** — is answered by ADR-0022
> with **none**: vanilla ES modules, zero npm packages, no build step. The "lean:
> minimal deps" instruction below is therefore taken to its limit rather than
> reinterpreted. The view list below (overview, session explorer, finding detail,
> infrastructure, anomaly) predates Phases 7-9; the delivered information architecture
> is History / Overview / Findings / Evidence, and doc 23 §7 records why — notably that
> a session explorer cannot be built honestly because `fused_findings` is absent from
> the canonical `to_dict()`.
**Context** R-04 interactive dashboard; offline; demo reliability paramount.
**Options** (a) static SPA (React/Svelte) served by FastAPI; (b) server-rendered templates; (c) desktop app.
**Decision** (a) static SPA built to static assets, served by the same FastAPI app, reads the evidence/
report API. Views per 21 (overview, session explorer, finding detail, infrastructure, anomaly).
**Rejected** (c) desktop framework (heavier, no need); (b) alone (weaker interactivity for infra/anomaly views) — though HTML report is a server-rendered fallback (08 §4).
**Consequences** + single deployable, offline, demo-stable. − build step.
**Risks** JS error on demo day → HTML/JSON reports viewable directly (08 §4).
**Open questions** OQ-41 SPA framework — pick at Phase 10 (lean: minimal deps).
