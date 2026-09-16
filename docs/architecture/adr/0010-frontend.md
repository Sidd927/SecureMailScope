# ADR-0010 — Dashboard: static SPA served by the backend
**Status:** Proposed 2026-09-16
**Context** R-04 interactive dashboard; offline; demo reliability paramount.
**Options** (a) static SPA (React/Svelte) served by FastAPI; (b) server-rendered templates; (c) desktop app.
**Decision** (a) static SPA built to static assets, served by the same FastAPI app, reads the evidence/
report API. Views per 21 (overview, session explorer, finding detail, infrastructure, anomaly).
**Rejected** (c) desktop framework (heavier, no need); (b) alone (weaker interactivity for infra/anomaly views) — though HTML report is a server-rendered fallback (08 §4).
**Consequences** + single deployable, offline, demo-stable. − build step.
**Risks** JS error on demo day → HTML/JSON reports viewable directly (08 §4).
**Open questions** OQ-41 SPA framework — pick at Phase 10 (lean: minimal deps).
