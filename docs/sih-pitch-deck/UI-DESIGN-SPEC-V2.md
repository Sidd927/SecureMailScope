# UI design specification V2 — analyst workspace

Derived from `UI-UX-RESEARCH-V2.md`. Builds on the approved V1 information architecture
(`UI-DESIGN-SPEC.md`) — four screens, hash router, no backend change — and replaces its
*composition*, not its structure.

**Backend, analysis engine, scoring, evidence semantics, cross-session logic, ML
behaviour, reporting: unchanged.** This is a presentation-layer pass only.

---

## 1. Visual principles (the five rules everything else follows)

1. **Composition over components.** A new visual problem is solved with spacing,
   typography or a divider before it is solved with a new bordered box.
2. **Colour is reserved for meaning.** Severity and posture tones keep their exact,
   WCAG-verified values. Everything else — structure, grouping, elevation — is
   communicated with a 1px hairline border and spacing, never a background tint or a
   shadow.
3. **One typographic headline per screen.** Overview has exactly one moment that is
   allowed to be large: the posture verdict. Nothing else on that screen competes with
   it in size.
4. **Dense where the data is dense, generous where it is not.** Tables and finding rows
   stay information-dense. The space between sections gets *more* generous, not less —
   the two together create rhythm instead of uniform padding.
5. **Every visual change must still answer the honesty constraints already governing
   this product:** no fabricated progress, no severity colour on an evidence state, no
   comparison implied without real cross-session evidence, no security arithmetic in
   the client.

## 2. Typography system

```
Display   (posture verdict only)   34px / 650 / -0.015em / 1.1
Title     (page/capture identity)  22px / 650 / -0.01em  / 1.2
Section   (eyebrow label)          11px / 700 / .09em uppercase / muted — used ONLY
                                    for true section starts, not every sub-block
Subhead   (row/card title)         15px / 600 / 1.3
Body                               15px / 400 / 1.55        (unchanged from V1)
Meta / caption                     13px / 400 / 1.4 / muted
Technical (mono)                   13px / mono stack         (unchanged from V1)
```

System font stack unchanged — no web font, per the offline constraint. The "display"
treatment is achieved with weight and negative tracking on the existing stack, the same
technique Linear/Notion use at large sizes; no new font file is introduced.

## 3. Spacing system

```
--space-1   4px    within a control (chip padding, gap between icon and label)
--space-2   8px    within a row
--space-3   12px   row padding
--space-4   16px   between related rows
--space-6   24px   between a heading and its content
--space-10  40px   between sections on a screen
--space-16  64px   above/below the Overview hero
```

Base 4px scale (matches the existing `--radius`/`--radius-sm` convention). The change
from V1 is not the unit, it's the *application*: V1 used ~24–32px everywhere; V2 uses
12–16px inside a group and 40–64px between groups.

## 4. Colour system

**Severity, posture-band, accent and text tokens keep their exact V1 hex values** —
they are WCAG-AA verified by `test_contrast_tokens_meet_wcag_aa` and reused by the
report renderer. Only the *neutral* surface tokens change, and only toward warmth:

```
--page      #f5f6f8  →  #f7f6f3   (warm off-white canvas, not cool grey)
--surface   #ffffff  →  #ffffff   (unchanged — cards/rows still sit on true white)
--panel     #f6f7f9  →  #f5f3ee   (warm)
--rule      #e3e6ea  →  #e6e2d9   (warm hairline)
```

`--shadow` is **removed as the default elevation mechanism**. Elevation is a 1px
`--rule` border, full stop — matching the "no shadows on content cards" principle from
the research. The one exception: the upload drop-zone's active drag-over state, which
keeps a soft ring because it is communicating an *interactive* state, not resting
elevation.

## 5. Information architecture — unchanged from V1, with one correction

```
#/                        Home        drop zone → history
#/about                   About
#/run/{id}                Overview    (default tab)
#/run/{id}/findings        Findings
#/run/{id}/evidence        Evidence & provenance
```

**Correction from the V2 brief's illustrative nav:** no fourth "Reports" tab (§5 of the
research doc explains why). Report export becomes a **persistent header control**,
present on all three run tabs, not gated behind Overview.

## 6. Application shell

```
┌────────────────────────────────────────────────────────────────┐
│  ◇ SecureMailScope                          Analyses   About    │  ← home / about
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  ◇ SecureMailScope                          Analyses   About    │  ← inside a run
├────────────────────────────────────────────────────────────────┤
│  ← Analyses                                                      │
│  scene_b_certificate_honesty.pcap                                │
│  IMAPS · 1 session · analysed 18:42          [Export ▾] [+ New]  │
├────────────────────────────────────────────────────────────────┤
│  Overview    Findings    Evidence & provenance                   │
└────────────────────────────────────────────────────────────────┘
```

`+ New analysis` moves from "always visible" (V1) to **visible only inside a run or on
About** — on Home it is redundant, since the whole page already is the new-analysis
workflow. `Export ▾` is a single control (native `<details>`, the same disclosure
primitive already used for findings — no new interaction language) that reveals
HTML / PDF / JSON, built from the existing `reportUrl(runId, format)` helper and the
fixed format allowlist. Overview keeps its own labelled Reports section too, with the
one-line description of each format — the header control is the fast path, the section
is the explained path.

## 7. Screen-by-screen composition

### Home — first visit
Large single headline ("Assess an email capture" retained — already tested copy),
subhead, then the drop zone **as the page's own surface**, not a card floating inside
another card. Below it, the four-step methodology becomes a single slim **rail** — one
row, small type, connected by thin rule lines, visually subordinate, positioned after a
clear section break so it never competes with the drop zone for attention.

### Home — populated
Compact drop zone, then "Recent analyses" as a **list** (hairline row dividers) rather
than a bordered table-in-a-card. Table semantics (caption, scoped headers) are kept for
accessibility; only the visual framing changes.

### Overview
```
capture-name.pcap                                    IMAPS · 1 session · 259 ms · ML off

SECURITY POSTURE
STRONG                                                   ← the one true "display" moment
88 / 100 · evidence coverage 100.0% (1 of 1 sessions assessed)

Missing evidence never improves this score.

[Inspect 1 finding →]   [Evidence & provenance →]

────────────────────────────────────────────────────── (section break, 64px)

PRIORITISED FINDINGS                                              [see all →]
  row · row · row                                     ← hairline dividers, not cards

WHAT COULD NOT BE DETERMINED
  row · row

PROTOCOL POSTURE
  …

CROSS-SESSION REASONING (only when present)
  …

[score decomposition / coverage detail / distributions / ML / identity / limitations —
 unchanged content, demoted visually, below the fold]
```

The four-cell boxed grid from V1 is replaced by one headline + a compact stat line
underneath it. Every number that was in a box is still on screen, just carried as
typography and a divider-separated inline stat row instead of four bordered cells.

### Findings
Rows, not cards: severity marker + title + one-line explanation + protocol + evidence
certainty on one line, hairline divider, click to expand (existing `<details>`
mechanism, unchanged). Filters keep their existing facet-checkbox behaviour; only the
container chrome is lightened (no drop shadow, hairline border only).

### Evidence & provenance
Regrouped editorially into two clusters over the same six-state data:

```
WHAT WAS ESTABLISHED
  OBSERVED · INFERRED

WHAT COULD NOT BE ESTABLISHED
  AMBIGUOUS · INCOMPLETE · UNKNOWN · NOT_OBSERVABLE
```

Every state still renders as the same neutral, non-severity chip from V1 — this is a
grouping change, not a new vocabulary and not a new colour. Provenance gains a small
fixed-label rail at the top of the panel:

```
Capture  →  Frame / stream  →  Evidence  →  Finding  →  Posture  →  Report
```

This is presentation only — six static labels describing the pipeline shape, not a new
data binding — followed by the existing rule-id / source-count / entry tables as
supporting detail. Never labelled "chain of custody" (unchanged constraint from V1).

### About
One product statement, then the six points as a tight two-column list instead of a
document-style `<dl>` with a bordered card underneath each item. Instance facts
(`GET /health`) kept, demoted below a visible divider.

## 8. Interaction system

- **Hover:** rows (findings, history) get a background-tint on hover only — no border
  change, no shadow.
- **Focus:** unchanged 3px accent outline (already WCAG-appropriate, already tested).
- **Drag-over:** unchanged from V1 (solid border + tint) — already correct per the
  upload research.
- **Disclosure (`<details>`):** the one expand/collapse language in the whole product,
  used identically for findings and for the new export control — no second interaction
  pattern introduced.
- **No motion beyond what V1 already has** (the indeterminate working bar, the spinner,
  the details-marker rotation). No new animation is added — the brief explicitly warns
  against decorative motion, and V1 has none to remove.

## 9. What is explicitly NOT built

A fourth "Reports" tab (see §5 above) · a sidebar · dark mode · a gauge/donut/trend line
· an "AI Threat Score" · card-shadow elevation as the default surface treatment · any
new external asset, font or icon service.

## 10. Test-impact assessment (before writing code)

No V1 test pins a specific CSS token value beyond the nine named in
`test_contrast_tokens_meet_wcag_aa` (`ink, muted, accent, critical, high, medium, low,
info, withheld`) — those keep their exact hex values, so that test is unaffected. No
test pins overview/findings/evidence class names beyond the two literal strings in
`test_overview_source_obeys_the_dom_boundary` (`reportUrl(runId, format)` and
`` href: `#/run/${runId}/findings` `` must remain present in `overview.js`) — satisfied by
keeping Overview's own Reports section in addition to the new header control. Heading
levels, table captions, DOM-boundary (`textContent` only), href-construction rules,
canonical-order (no client-side sort of findings/abstentions/protocols), and the
curl-free empty state are all structural constraints that this pass does not touch and
must continue to hold — verified by re-running the full suite, not assumed.
