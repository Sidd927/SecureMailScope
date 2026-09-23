# UI implementation notes — analyst console redesign

Branch `phase/dashboard-redesign`. Companion to `UI-UX-RESEARCH.md` (why) and
`UI-DESIGN-SPEC.md` (what was proposed). This records **what was actually built**, what
changed from the approved spec, and what was verified.

---

## 1. Scope actually touched

**Backend changes: NONE.** **Analysis engine, cryptographic rules, posture scoring,
cross-session logic, evidence semantics, ML behaviour, reporting, security model:
UNCHANGED.** Not one file under `src/securemailscope/` outside `dashboard/static/` was
modified, and `dashboard/` Python (`projection.py`, `model.py`, `vocabulary.py`) was not
modified either — only the static front end.

```
NEW   dashboard/static/upload.js            capture submission
NEW   dashboard/static/views/home.js        the #/ route
NEW   dashboard/static/views/about.js       the #/about route
EDIT  dashboard/static/api.js               + submitCapture()
EDIT  dashboard/static/app.js               routes, shell nav, crumbs
EDIT  dashboard/static/index.html           app shell
EDIT  dashboard/static/style.css            full visual system
EDIT  dashboard/static/views/history.js     empty state, column order, returns total
EDIT  dashboard/static/views/overview.js    hero, abstentions, cross-session
EDIT  dashboard/static/views/evidence.js    full six-state vocabulary as chips
UNCHANGED dashboard/static/views/findings.js
UNCHANGED dashboard/static/dom.js, filtering.js
```

No framework, no npm, no build step, no external font, script, style or image. Every
mark on screen (brand, upload arrow, step numbers) is drawn in CSS.

## 2. The defect that drove this

The console could **read** analyses but not produce one: `api.js` had no submission
function at all, and the empty state printed

```
curl -F file=@capture.pcap http://127.0.0.1:8000/api/v1/analyses
```

That told the analyst the product had to be operated from a terminal. `POST
/api/v1/analyses` already accepted `multipart/form-data` with field `file`, so the fix
needed no backend work — only a client for an endpoint that already existed.

## 3. What was built

### Home (`#/`)
Hero drop zone on a fresh instance, compact above the history once populated.
`idle → dragover → selected → uploading → complete | error`. A drop **selects**; the
analyst confirms with **Analyze capture**. Double-submit is guarded. On completion the
console opens the run; on a non-terminal state it stays on the history, which already
polls. Stray drops outside the zone are suppressed so the browser cannot navigate away
and render the raw capture.

### Overview (`#/run/{id}`)
Capture name and real run metadata, then one inseparable block:

```
SECURITY POSTURE   EVIDENCE COVERAGE   PRIORITISED FINDINGS   NOT CONCLUDED
CRITICAL           100.0%              4                      38
22.15 / 100        12 of 12 sessions
```

then `Inspect N finding(s)` / `Evidence & provenance` / HTML · PDF · JSON. Section order
is the approved priority: findings → what could not be determined → protocol posture →
cross-session → score decomposition → coverage → distributions → ML → reports →
identity → limitations.

### Findings, Evidence
Findings kept its logic verbatim; only the surface changed. Evidence now renders the
**whole six-state vocabulary** — `OBSERVED · INFERRED · UNKNOWN · AMBIGUOUS ·
INCOMPLETE · NOT_OBSERVABLE` — as neutral bordered chips, with `none recorded` for
states this capture did not produce, so the vocabulary never looks smaller than it is.

### About (`#/about`)
Six short points plus `GET /health` facts about this deployment. Nothing else.

## 4. Two decisions that departed from the spec

**a. Cross-session detection keys on issue class, not abstention reason.**

The spec proposed matching `INSUFFICIENT_HISTORY` / `NOT_COMPARABLE`. Measured against
real engine output, a history shortfall is recorded as:

```
reason = INSUFFICIENT_CAPTURE
issue_class = STARTTLS_BEHAVIOUR_DEVIATION
why = "Insufficient comparable history to assess this session."
```

Matching on the reason alone would have missed **every real occurrence**. Detection is
now `issue_class ∈ {STARTTLS_BEHAVIOUR_DEVIATION, TLS_VERSION_DEVIATION}` **or** reason
in the history set — both, so neither path is dropped. Verified: the panel renders 1
established deviation and 20 declined comparisons on
`deepdive_cross_session_control_endpoint.pcap`, and does not render at all on captures
with neither.

**b. `INSUFFICIENT_HISTORY` is never synthesised.** `DEFAULT_MIN_HISTORY = 5` is
enforced by the engine. The UI renders the engine's own abstention text and adds no
threshold of its own.

## 5. Honesty constraints held in code

| Constraint | How |
|---|---|
| No fake progress | `fetch` cannot report upload progress, so the working state is indeterminate and carries **no percentage**. Asserted by test. |
| No fake pipeline animation | `ingest` is ~136 of ~137 ms and five stages measure 0 ms, so no six-step animation exists. |
| No posture gauge, trend line, AI score, threat map | none built |
| Client-side checks never block | extension and size hints are advisory; the server decides. Asserted by test. |
| Uncertainty ≠ failure | evidence states and abstentions use neutral chips, never a severity colour |
| Counts only | the UI computes no security value; the one number it derives is a list length |

## 6. Test impact

Baseline 1219 → **1226 passed, 0 failed, 0 skipped** (two consecutive full runs).

**One pre-existing assertion was rewritten:** `test_empty_history_is_explained` required
`"curl -F file=@capture.pcap" in prose` — it pinned the defect being fixed. It now
requires the empty state to explain itself *and* the curl string to be **absent** from
the shipped code, which is a stricter requirement. Seven tests were added covering the
upload path, the drop-never-submits rule, the double-submit guard, the no-progress rule,
the advisory-never-blocks rule, home ordering, and run-id revalidation before navigation.

**One unrelated pre-existing flake was fixed:**
`tests/test_ingest_pipeline.py::test_malformed_capture_fails_not_crashes` drove
`os.urandom(512)` through tshark and intermittently passed a malformed file as
COMPLETED — the same defect fixed in `test_tshark_adapter.py` during Phase 11. It now
reuses that module's `MALFORMED_FIXTURE`. Test-only change; no production behaviour
touched. Verified 10/10 consecutive runs.

## 7. Defect found and fixed during browser QA

After a **refused** submission the history still showed the old run count, even though
the backend had recorded a `FAILED` run. An analyst would have concluded nothing was
recorded. `uploadPanel` gained an `onFailed` callback that redraws **only** the history
host, so the error card and the rejected file stay on screen. Verified: 5 → 6 runs,
error retained, file retained.

## 8. Verification performed

- Full suite ×2: 1226 passed, 0 failed, 0 skipped
- Scene A1 ADEQUATE 88 · A2 ADEQUATE 85 · B STRONG 100 · C ADEQUATE 88
- AI on vs AI off, identical: Scene C 88.0/88.0, cross-session 22.15/22.15
- Real browser at **1440×900** (primary), 1280×800, 1600×1000
- **0 console messages** across every screen
- Network: one `/analyses` + one `/health` per home load; **one** `/dashboard` fetch
  across Overview → Findings → Evidence (the cache holds)
- Live XSS: a run whose filename is `<script>window.__pwned=1</script>"><img src=x
  onerror=alert(1)>.pcap` → `__pwned` undefined, **0** `<img>` elements, hero node has
  0 child elements, text rendered literally
- Accessibility in-browser: one `<h1>`, every table captioned, skip link present, file
  input keyboard-reachable and label-associated with a 3px focus ring, 0 images, 0
  inline `style` attributes

## 9. Not done, deliberately

Mobile polish beyond "does not break" (desktop-first was the instruction) · dark mode ·
packet drill-down (the assessment carries none) · any chart library.
