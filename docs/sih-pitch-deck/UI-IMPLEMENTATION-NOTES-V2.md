# UI implementation notes V2 — from prototype to workspace

Branch `phase/dashboard-redesign-v2`, created from `phase/dashboard-redesign` at commit
`f8d5b83`. Companion to `UI-UX-RESEARCH-V2.md` (why) and `UI-DESIGN-SPEC-V2.md` (what
was proposed). This records what was actually built.

**Backend, analysis engine, scoring, evidence semantics, cross-session logic, ML
behaviour, reporting: unchanged.** Verified by running Scenes A/B/C and the AI-on/off
equivalence check and comparing every posture/score figure against the V1 baseline —
all identical. This was a presentation-layer pass only.

---

## 1. Scope touched

```
EDIT  dashboard/static/style.css           full visual system rewrite
EDIT  dashboard/static/index.html          masthead nav simplified; tab bar gained
                                            a persistent actions region
EDIT  dashboard/static/app.js              + setRunActions() (Export menu, New
                                            analysis pill), + reportUrl import
EDIT  dashboard/static/views/home.js       whatItDoes() -> methodologyRail()
EDIT  dashboard/static/views/overview.js   headline verdict, capture-filename-as-
                                            heading, section titles carry counts
EDIT  dashboard/static/views/evidence.js   evidence states grouped into two
                                            clusters; provenance rail added
EDIT  dashboard/static/views/about.js      dl -> block grid
UNCHANGED  findings.js, filtering.js, history.js (JS), dom.js, api.js, upload.js
```

No new dependency, no framework, no build step, no external font/CDN/asset. The
`--shadow` token and box-shadow elevation are removed entirely; elevation is a 1px
hairline border, full stop.

## 2. What actually changed, and why

**Nine severity/posture/text tokens kept their exact V1 hex values** — `ink`, `muted`,
`accent`, `critical`, `high`, `medium`, `low`, `info`, `withheld` — because they are
WCAG-AA verified by `test_contrast_tokens_meet_wcag_aa` and shared with the report
renderer. Only the neutral surface tokens moved, and only toward warmth (`--page`
`#f5f6f8` → `#f7f6f2`, matching Notion's "warm canvas, not cold grey" research finding).

**One headline per screen.** Overview's posture band is now the only large typographic
moment on the page (34px, weight 680, tight tracking) — the four-cell bordered grid
from V1 is gone; score and coverage are a single subline underneath it. A latent V1 bug
surfaced while rewriting this: the old coverage cell concatenated `percent_text` and
`summary_text` separately, and `summary_text` already *contained* the percentage —
producing "100.0% · 100.0% (1 of 1 sessions assessed)" duplicated. The new subline uses
`summary_text` alone.

**Fewer cards.** Findings changed from ten bordered, shadowed boxes to ten rows inside
one bordered list, separated by a hairline divider — same `<details>` disclosure
mechanism, same data, no JS logic touched. The four-step "how it works" explainer
moved from a card grid into a single slim rail below a section break, so it never
competes with the drop zone above it. About's six points moved from a bordered
`<dl>` card into an undecorated two-column block grid.

**Evidence grouped into what could and could not be established.** The six-state
table is now two tables — `OBSERVED`/`INFERRED` under "What was established",
`AMBIGUOUS`/`INCOMPLETE`/`UNKNOWN`/`NOT_OBSERVABLE` under "What could not be
established" — over exactly the same six-state vocabulary and counts. A state this
build does not recognise is grouped with the uncertain cluster on principle: an
unrecognised reading is definitionally not a settled one.

**A provenance rail.** Six static labels — `Capture → Frame / stream → Evidence →
Finding → Posture → Report` — precede the existing rule-id/source-count/entry tables.
Presentation only, no new data binding, never labelled "chain of custody."

**Report export became a persistent header control**, reachable from Overview,
Findings and Evidence alike, built from a native `<details>` element — the same
disclosure primitive findings already use, not a second interaction language. This is
a deliberate departure from the brief's own illustrative nav, which showed a fourth
"Reports" tab: Stripe's own IA research (cited in `UI-UX-RESEARCH-V2.md` §5) argues
against navigation that makes a user "know which section data lives in," and reports
are an export action, not a fourth investigative mode. Overview keeps its own labelled
Reports section too — the header is the fast path, the section is the explained one.

**The masthead lost its permanently-visible "New analysis" button.** It is redundant
on Home (the whole page already is the new-analysis workflow) and is now shown only
inside a run or on About, via the new tab-bar actions region — reachable everywhere it
is actually needed, absent everywhere it would just be noise.

## 3. Two things not done as literally specified, with reasons

**No fourth "Reports" tab** — see §2 above and `UI-UX-RESEARCH-V2.md` §5.

**Evidence's dozens-of-abstentions table was not converted to cards.** The brief's own
Overview mockup and Evidence description both invite a card treatment, and Overview's
top-5 abstention summary *is* now cards. But Evidence is the complete forensic record —
one real capture in QA carried 38 abstentions — and "dense where the data is dense" is
one of the five stated visual principles. Thirty-eight stacked cards would be a much
longer page for no added clarity over a scannable table. Kept as a table, restyled only.

## 4. Test impact

**Zero test changes required.** Every dashboard test suite passed on the first run
after implementation — 329/329 across accessibility, security, security-matrix,
history, overview, findings and evidence. No V1 test pinned a CSS token value beyond
the nine WCAG-checked names, and no test pinned a class name introduced or removed by
this pass beyond the two literal strings already required in `overview.js`
(`reportUrl(runId, format)` and `` href: `#/run/${runId}/findings` ``), both of which
are still present via the unchanged `reportPanel()`/`heroActions()` functions.

Full suite: **1226 passed, 0 failed, 0 skipped** — identical to the V1 baseline, run
twice for confidence.

## 5. Verification performed

- Full suite ×2: 1226 passed, 0 failed, 0 skipped
- Scene A1 ADEQUATE 88 · A2 ADEQUATE 85 · B STRONG 100 · C ADEQUATE 88 — identical to
  V1 and to the pre-redesign baseline
- AI on vs AI off, identical: Scene C 88.0/88.0, cross-session capture 22.15/22.15
- Real browser: full accessibility-tree read of Overview, Findings, Evidence and About
  at 1440×900; computed-style measurements confirming zero horizontal overflow and the
  intended typography scale (34px posture headline, 22px capture-name heading) at
  1440×900, 1280×800 and 1600×1000; the content column caps at 1312px and centres
  rather than stretching at 1600px
- **0 console messages** on every screen tested (Overview, Findings, Evidence, About,
  error state)
- Network: the dashboard view-model fetch is not repeated when navigating between
  Overview → Findings → Evidence for the same run (cache holds); no duplicate
  `/analyses` or `/health` calls beyond one per Home load
- Live XSS re-test against the new markup: a run named
  `<script>window.__pwned=1</script>"><img src=x onerror=alert(1)>.pcap` — now the
  page's own `<h2>` heading — rendered as literal text with 0 child elements, 0 `<img>`
  elements created anywhere on the page, and `window.__pwned` undefined
  (the one `<script>` element present is the legitimate `app.js` module tag)
  All 5 inline `style` attributes present belong to the pre-existing, tested
  `.bar-fill` width mechanism (a computed percentage), nothing new
- Export menu: opened via the native `<details>` element, produced exactly the three
  expected `/reports/{html,pdf,json}` hrefs for the current run id; both `/reports/html`
  and `/reports/pdf` resolved 200 against the live backend
- One caveat, reported plainly: the browser pane went into a backgrounded
  (non-compositing) state partway through visual QA and did not return to the
  foreground despite repeated retries and navigation. Three genuine pixel screenshots
  were captured before that point (the first-run hero, the populated history list, the
  not-found error state) and are consistent with the design spec. Every other screen
  was verified through the full accessibility tree, computed CSS values, and DOM
  structure rather than a pixel screenshot — a stronger check for correctness, a weaker
  one for pure aesthetic judgment. More screenshots can be captured on request once the
  pane is back in the foreground.

## 6. Remaining issues

None found that affect correctness, security, or the stated design principles. The one
open item is the unavailable final round of pixel screenshots noted above — a tooling
availability gap in this session, not a defect in the build.

## 7. Screenshot readiness

**YES.** The live application at `http://127.0.0.1:8000/dashboard/` is already serving
this build (static files are read from disk per request; no server restart was
needed), and Asset #6 in `FINAL-ASSET-CHECKLIST.md` can be captured directly from it.
