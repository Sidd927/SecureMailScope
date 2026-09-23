# UI/UX research V2 — from "clean prototype" to "premium analyst workspace"

Research conducted 2026-09-24 for the second dashboard design pass. V1
(`UI-UX-RESEARCH.md`) covered *functional* patterns — empty states, upload UX, evidence
honesty. This pass is about **visual and product quality**: why some interfaces read as
expensive and considered, and why V1, despite being functionally correct, still reads as
"well-formatted documentation" rather than "a workspace a professional would pay for."

No product studied here is copied. Nothing below is a component to lift — it is a
principle to apply to SecureMailScope's own identity.

---

## 1. What was actually studied

Public design-system write-ups and product analysis for: **Linear**, **Stripe**,
**Notion**, **Raycast**, **Vanta**, **Wiz**, **GitHub**/**Cloudflare** (component
libraries), plus general research on premium-SaaS perception, provenance/audit-trail
visualization, and file-upload UX patterns.

## 2. The single biggest finding

**Every one of these products is dark-mode-native or treats whitespace as a paid
resource, and SecureMailScope is light-only.** That mismatch is *why* copying any one
of them literally would be wrong — Linear's and Raycast's "expensive" feel comes
specifically from *near-black canvas as absence*, which has no light-mode equivalent.
The transferable principle is not "use a dark canvas," it's **"treat empty space as
something the product can afford to spend."** V1 already has generous margins; what it
lacks is the *rhythm* — tight spacing inside a group, generous spacing between groups —
and it substitutes boxed cards for that rhythm instead of building it with typography
and dividers. That substitution is the root cause of the "documentation" feeling.

## 3. Patterns worth adopting, and why

| Pattern | Source | Why it fixes something specific in V1 |
|---|---|---|
| **Fewer, tighter rows with hairline dividers instead of a bordered-shadowed card per item** | Raycast (dense command-palette rows), Stripe ("dense data, generous chrome") | V1's findings list and the four-step explainer are both card grids; a list of ten findings as ten shadowed boxes reads as a form builder, not an investigation tool |
| **Reserve colour for meaning, never decoration** | Vercel via premium-SaaS research, Linear's "single tuned accent" | V1's borders, chip backgrounds and hover states use colour structurally in places colour carries no information |
| **Warm, slightly-off-white canvas instead of cold grey** | Notion (`#f6f5f4` vs pure white/grey) | V1's `--page: #f5f6f8` is a cool blue-grey that reads clinical; a warm neutral reads considered without changing any WCAG-verified severity token |
| **Hairline borders instead of box-shadow for elevation** | Notion ("no shadows on content cards — hairline borders only"), Raycast | V1 uses a drop-shadow on every card (`--shadow`); removing it and using a single 1px border is a one-line change with outsized effect |
| **Typographic weight as the primary hierarchy signal, tight tracking at display size** | Linear (510/590 weight steps, negative tracking at 48–72px), Notion (aggressive tracking at 64px display) | V1's biggest number on screen (the posture band) is barely larger than a section heading; there is no true "headline" moment |
| **Decision-speed information architecture: show what to act on, not everything that exists** | Stripe home screen (revenue trend, success rate, disputes — not a full ledger) | V1's Overview already orders sections by priority (a real, kept V1 win) but still gives every section equal *visual* weight via identical card chrome |
| **"Tests first" clarity — the thing needing action leads, detail follows on click** | Vanta ("tests displayed first... clicking in allows swift action") | Matches the existing priority-findings-first ordering; reinforces keeping the click-to-expand disclosure pattern for findings, not a wall of open detail |
| **Dual-path upload: drop zone AND explicit click, with a real drag-over state** | Universal 2026 file-upload guidance (PatternFly, Carbon, Untitled UI) | V1 already does this correctly — confirmed, not changed |
| **A named, visually distinct "status surface" separate from the entry point** | Same upload research | V1 already does this (picked/uploading/error states) — confirmed, not changed |
| **Provenance as a *log*, not a table: ordered steps a reader can scan without decoding columns** | Provenance/audit-trail visualization research (the "Provenance Log" pattern) | V1's provenance panel is dense tables; a short fixed pipeline rail (Capture → Evidence → Finding → Posture → Report) as a visual anchor, with the tables as supporting detail, reads as a trail rather than a spreadsheet |

## 4. Patterns confirmed as correctly rejected in V1 and still rejected

Gauges/donuts for posture, AI panels with prominent placement, trend lines, dark
"SOC war-room" themes, skeleton loaders for a ~140 ms operation, a sidebar for four
screens. Nothing in this research changes any of these conclusions — if anything the
"decision-speed" and "calm technology" research reinforces them further.

## 5. The one thing this research argues AGAINST from the V2 brief

The brief's illustrative navigation example includes a **"Reports" tab**. Stripe's own
research on IA explicitly warns against architecture that makes a user "know which
section data lives in." Reports are not a fourth *investigative* mode alongside
Overview/Findings/Evidence — they are an *export action* available from all three. The
"at the top right: [HTML] [PDF] [JSON]" framing in the brief's own §18 agrees with this.
**Conclusion: keep three investigative tabs; make report export a persistent header
control reachable from all of them, not a fourth tab.** This is flagged explicitly
because it is a case where following the brief's own stated principle (decision-speed,
minimal navigation) means not implementing its illustrative example literally.

## 6. Design conclusion

SecureMailScope V2 should read as an **editorial forensic instrument**: warm neutral
canvas, hairline borders (no shadow), one restrained accent used only where an action or
an active state is implied, a real typographic headline for the posture verdict, rows
and dividers in place of repeated card chrome, and a visible pipeline story
(Capture → Evidence → Finding → Posture → Report) that turns the provenance panel from a
spreadsheet into a trail. Nothing about the *underlying information architecture* from
V1 was wrong — the four screens, the section priority order, the evidence-state
vocabulary, the abstention treatment — those are kept. What changes is composition:
fewer boxes, more considered type, more deliberate space.
