# Finalization — 05. Report pack audit

**Reports packaged:** one JSON, one HTML, one PDF per scene, for 4 scenes (Scene A, B, C, and the
weak-certificate backup) — `demo/reports/`. Per the brief's own guidance, one representative set
per scene rather than a report for all 7 captures.

---

## 1. JSON validity

All 4 generated JSON reports parse successfully (`json.load` on each, verified in
`docs/finalization/02-demo-bundle-audit.md` §3). The JSON report is the canonical assessment
document verbatim — confirmed by comparing top-level keys against `posture/model.py`'s
`PostureAssessment.to_dict()` field set.

## 2. HTML safety

Zero `<script` occurrences across all 4 generated HTML reports (direct `grep -c` on the actual
generated files, not inferred from a test). Consistent with the zero-dependency, script-free
rendering design (`reporting/html.py` uses `html.escape` and string composition only, per
ADR-0019).

## 3. PDF extraction

Text-extracted via `pypdf` from `backup_weak_certificate.pdf` and confirmed to contain the actual
finding content — `1024`, `SHA-1`, `CRITICAL`, key-strength and signature-algorithm text all
present and legible, not just structurally valid bytes.

## 4. Report/artifact SHA-256 and integrity

`svc.list_artifacts(run_id, verify=True)` was run live against a real submitted capture this
phase and returned the artifact's SHA-256 with `verified` status, confirming the re-hash-on-access
integrity check documented in `docs/architecture/22-forensic-reporting.md` actually executes, not
just exists in the design document.

## 5. Provenance

Every generated report carries `capture_id` (the PCAP's SHA-256) and `assessment_id`
(content-addressed) — confirmed present in every JSON report generated this phase, matching the
values independently recorded in `demo/expected/*.json` and `docs/finalization/04-real-pcap-evidence-pack.md`.

## 6. `generated_at` determinism — investigated, not assumed clean

This is the one item in this workstream that required real investigation rather than a quick
check, and the investigation is recorded in full because the brief specifically asks to catch
"no stale generated_at values where determinism requires otherwise."

**Observation:** submitting the same capture twice with `force=True`, with a real, wall-clock-verified
3.2-second gap between the two submissions (bracketed with explicit `datetime.now()` prints on
both sides of each call), produced **two different `run_id`s but the identical `generated_at`**
— the *first* call's timestamp, not each call's own completion time.

**Investigated by reading the actual persistence code**, not by guessing: `backend/repository.py`'s
`store_assessment()` docstring states plainly — *"Persist a canonical assessment document.
Idempotent on identical content."* Because `assessment_id` is a content hash that deliberately
excludes `run_id` and `generated_at` (`RUNTIME_FIELDS`), a `force=True` re-analysis of identical
evidence computes the identical `assessment_id` and identical `generated_at` field, and the
storage layer — by design — keeps the first-stored row rather than overwriting it with a
"newer" record that has no actual content difference.

**Conclusion: not a defect.** This is the intended behaviour, and it is the *correct* one for a
forensic tool: `generated_at` represents when this specific conclusion was first established from
this specific evidence, not when the most recent HTTP request happened to touch it. Two identical
re-analyses producing an identical report, including an identical timestamp, is exactly what
"byte-deterministic" (`README.md`) should mean — a system that gave the same conclusion a
different quoted-generation-time on every re-run would be subtly *less* reproducible, not more.
No code was changed as a result of this investigation.

## 7. AI wording

Re-checked (in addition to Phase 12's system-wide search) against the 4 freshly-generated reports
specifically: no overclaim phrase found. The `ai=False` report correctly omits any `model_summary`
role text (because AI was disabled for that specific render); the `ai=True` role text
(`"secondary prioritisation signal only"`) was independently confirmed present in
`demo/expected/scene_c_no_ai_equivalence.json`'s `ai_true` branch.

## 8. Unsupported security claims

None found. Every finding in the 4 generated reports traces to a specific `SEC-*` rule with a
cited RFC/NIST standard, consistent with the security-claim register already compiled in
`docs/phase12/07-forensic-honesty-audit.md`.
