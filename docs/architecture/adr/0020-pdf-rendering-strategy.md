# ADR-0020 — PDF composed from the report model with ReportLab
**Status:** Accepted 2026-09-21 · **Closes:** OQ-40 ·
**Amends:** ADR-0009 (renderer mechanism only) · **Detail:** `docs/architecture/22`

**Context** ADR-0009 specified *"PDF = HTML→PDF via an offline renderer (e.g.
WeasyPrint) that executes no script"* and left **OQ-40 — confirm offline PDF renderer at
Phase 9** explicitly open. Phase 9 is where that has to be answered with an installed,
working renderer rather than a candidate name.

**Problem** Which PDF path actually works here, on Python 3.9, offline, reproducibly?

---

## What the environment actually has — measured, not assumed

Every candidate was probed before anything was chosen:

| Candidate | Result |
|---|---|
| WeasyPrint | **absent**; needs system cairo/pango, routinely fails to build on macOS |
| wkhtmltopdf | **absent** (binary not on PATH) |
| Chromium / Chrome / Playwright / Selenium | no binary on PATH; a macOS Chrome *app bundle* exists |
| xhtml2pdf, fpdf, pdfkit, borb, cairosvg | **absent** |
| prince, pandoc, gs, qpdf, pdftotext | **absent** |
| **ReportLab** | installed 5.0.1 — verified generating `%PDF-1.4`, multi-page, tables |
| **pypdf** | installed 6.19.0 — verified parsing and extracting text |

## Decision — compose the PDF from `ReportDocument` using ReportLab

**Rejected: HTML→PDF via WeasyPrint**, ADR-0009's own suggestion. It is not installed,
and its system-library requirements make an offline, air-gapped install materially
harder — which is the deployment profile ADR-0011 chose the whole architecture around.
Naming a renderer in 2026-09-16 was reasonable; keeping it after measuring would not be.

**Rejected: headless Chrome.** A Chrome app bundle exists *on this machine*. Depending
on it would make PDF generation work for the developer and fail for an evaluator, and
would hard-code a macOS path into a tool that must run offline elsewhere. A renderer
that works only where it was written is not a renderer.

**Rejected: writing a PDF serialiser by hand.** Attractive for zero dependencies, but
pagination, font metrics, table splitting and text wrapping are exactly the work
ReportLab has already done correctly. Hand-rolling them to avoid one pure-Python
dependency would trade a small packaging cost for a large correctness risk in the
artefact an evaluator reads most closely.

**Selected: ReportLab, pure Python, behind the optional `reporting-pdf` extra.** JSON and
HTML remain dependency-free, so a core install still satisfies two of the three R-03
formats and PDF is additive.

## Consequence — the PDF is not rendered from the HTML

This is a real deviation from ADR-0009's mechanism, and it introduces a drift risk that
ADR-0009's HTML→PDF path would not have had: two renderers could disagree.

ADR-0009's *intent* — one canonical object, no triplicated logic — is preserved, because
both renderers consume the same `ReportDocument` and neither contains security logic.
The drift risk is discharged by a **cross-format semantic equivalence test** that
extracts the assessment id, capture id, posture, score, coverage, issue classes,
standards, ML role and limitations from the rendered HTML and from the text extracted
out of the rendered PDF, and asserts they agree with each other and with the canonical
assessment. Convention would not have been sufficient.

## Determinism

ReportLab is invoked with `invariant=1`, which pins the PDF `CreationDate` to
`D:20000101000000` and removes the per-run identifiers that otherwise vary. Measured:
two builds 1.1 s apart are **byte-identical** with `invariant=1` and differ with
`invariant=0`.

Combined with the report taking its timestamp from the assessment rather than the wall
clock (ADR-0021), this makes the PDF a pure function of the canonical assessment, so
`report_sha256` is stable and content-addressed.

---

**Consequences** + a working, offline, pure-Python PDF path with no system libraries;
+ byte-deterministic output; + PDF stays optional. − ReportLab's layout vocabulary is
not CSS, so HTML and PDF are styled twice from shared design tokens; − a very long
unbroken evidence string must be wrapped explicitly rather than by a browser.

**Risks** The two renderers drift apart → semantic equivalence test. ReportLab absent at
runtime → PDF endpoint returns a structured `REPORT_RENDERER_UNAVAILABLE` error and the
HTML and assessment remain fully available (ADR-0019 Decision 4).

**Open questions** OQ-55: if a browser engine becomes a supported dependency later, is
HTML→PDF worth revisiting for visual fidelity, accepting the loss of byte determinism?
