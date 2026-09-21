# ADR-0019 — The report is a projection, not a second engine
**Status:** Accepted 2026-09-21 · **Detail:** `docs/architecture/22` ·
**Builds on:** ADR-0009 (one canonical report object), ADR-0016 (canonical assessment)

**Context** Phase 8 serves the canonical `PostureAssessment` as JSON. R-03 additionally
requires HTML and PDF, and R-05 requires a forensic report artefact. ADR-0009 already
decided the shape in 2026-09-16 — *one canonical report object, three renderers, never
three independent generators* — and that decision stands. This ADR records what Phase 9
had to decide on top of it.

**Problem** Where does the rendered document get its facts, how do two renderers avoid
drifting apart, and what happens when a report fails to render?

---

## Decision 1 — Rendering reads the canonical document and nothing else

`reporting/` consumes `PostureAssessment.to_dict()`. It never reads the `runs` table, a
`SessionEvidence`, a `SecurityFinding`, or a packet.

**Rejected: rendering from database rows.** Assembling a report from `runs` joined to
`assessments` would let a report show a severity or a band that the assessment does not
contain, and the projections in the `assessments` table exist for listing only
(ADR-0017 Decision 3). A report is the most quotable artefact the system produces; it is
the last place that should be allowed its own opinion.

**Consequence** If a value is not in the canonical document, the report cannot show it.
That is the point. `fused_findings` is absent from `to_dict()`, so the report renders
issue groups and prioritised representatives and **does not fabricate per-session rows**.

## Decision 2 — One `ReportDocument`, two renderers, no logic in either

```
PostureAssessment.to_dict() → projection → ReportDocument → {HTML, PDF}
```

The projection may reorder, group, label and format. It may not reinterpret. Severity,
band, score, certainty, observability, recurrence, remediation text and standards
citations are copied through as strings; no arithmetic is performed on any of them.

**Rejected: rendering HTML and PDF independently from the assessment.** Two readers of
one contract drift, and the drift would be invisible until an analyst compared two
artefacts of the same assessment and found different claims. Both renderers walk one
already-decided structure.

**Rejected: a template engine (Jinja2).** It is installed in this environment but
undeclared, and an HTML report is the one artefact that must render with **zero**
dependencies so JSON and HTML remain available to a core install. Rendering with
`html.escape` and string composition keeps the zero-dependency property and makes the
escaping boundary explicit at every call site rather than delegated to autoescape
settings a future edit could switch off.

## Decision 3 — Presentation is forbidden from resolving uncertainty

The projection carries the six-state evidence vocabulary and the four-state certainty
vocabulary through unchanged, and the renderers display them as text, not only as
colour.

**Rejected: mapping `INSUFFICIENT_EVIDENCE` to "Unknown".** "Unknown" reads as an
absence of concern. `INSUFFICIENT_EVIDENCE` is a refusal to grade, which is a finding
about the capture. **Rejected: collapsing `NOT_OBSERVABLE`, `AMBIGUOUS` and
`INSUFFICIENT_EVIDENCE`** into one "not assessed" bucket, which would erase the
difference between *cannot be seen passively*, *the evidence conflicts* and *there was
not enough traffic*.

**Rejected: colour as the sole carrier of severity or posture.** Printed in greyscale,
or read by anyone with a colour vision deficiency, a colour-only severity is no severity
at all. Every severity, posture, certainty and observability value is rendered as a text
label; colour is redundant reinforcement.

## Decision 4 — Report failure is isolated from the assessment

A completed analysis stays `COMPLETED` when a renderer raises. The failure is recorded
against the report artefact, not against the run.

**Rejected: generating reports inside the analysis transaction.** A missing optional PDF
dependency would then mark a perfectly good forensic analysis as failed, which inverts
the importance of the two things. HTML is generated eagerly after completion because it
is cheap and dependency-free; PDF is generated on request. A PDF failure leaves the HTML
and the assessment intact, and is reported as itself.

**No fabricated artefact, ever.** If a renderer fails there is no artifact row, so the
integrity model cannot be asked to vouch for bytes that were never produced.

---

**Consequences** + the report can never contradict the assessment; + one place decides
what a report says; + JSON and HTML need no dependency; + an evaluator reading the PDF
and the JSON sees the same claims. − the report cannot enrich the assessment (by design);
− two renderers must be kept in step, which is a test obligation, discharged by the
cross-format semantic equivalence test rather than by review.

**Risks** A future contributor adds a "risk percentage" or "compliance score" to make the
report look more complete → no such value exists in the canonical document, architecture
tests forbid arithmetic on severity in `reporting/`, and doc 22 §8 states the prohibition
where a renderer author will meet it.

**Open questions** OQ-54: should the projection expose a stable section-id vocabulary so
a Phase-10 dashboard can deep-link into a rendered report?
