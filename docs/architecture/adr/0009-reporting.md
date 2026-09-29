# ADR-0009 — One canonical report object, three renderers
**Status:** Accepted 2026-09-16 · **Renderer mechanism amended 2026-09-21 by [ADR-0020](0020-pdf-rendering-strategy.md)**

> The core decision — one canonical report object, three renderers, never three
> independent generators — is **retained and implemented** in Phase 9. Only the PDF
> mechanism changed: `HTML→PDF via WeasyPrint` is **withdrawn** (measured absent, needs
> system cairo/pango, hostile to offline install). PDF is composed from the same report
> document model with ReportLab. **OQ-40 is closed.** See ADR-0020.
**Context** PS requires JSON + PDF + HTML (R-03). Three engines = triplicated logic + drift.
**Decision** A single canonical Report object (03 PostureAssessment + Findings + evidence refs).
JSON = direct serialisation; HTML = template render; PDF = HTML→PDF via an offline renderer (e.g.
WeasyPrint) that executes no script. All PCAP-derived text escaped (06 §5).
**Rejected** three independent report generators (drift, duplicated bugs).
**Consequences** + consistency, single source of truth, easy to test (round-trip). − PDF renderer dependency.
**Risks** offline PDF rendering fails → HTML/JSON fallback (08 §4); XSS → context-aware escaping + tests.
**Open questions** OQ-40 confirm offline PDF renderer at Phase 9.
