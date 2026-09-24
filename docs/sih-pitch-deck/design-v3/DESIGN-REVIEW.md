# Design Review — V3 Stitch Exploration

Status at time of writing: **9 of 24 target screens generated** (Direction A: 6/8, Direction B: 3/8, Direction C: 0/8). Generation was paused mid-session at the user's explicit choice after the Stitch generation service began timing out on roughly half of calls (see §3). This review covers what exists now, honestly, rather than the full 24-screen set the original brief asked for.

## 1. Self-critique against the brief's standard

The brief's question was never "is this pretty" — it was "does this look like a real cryptographic forensic product, or a student project." Running the completed screens against that:

| Question | Assessment |
|---|---|
| Does this look like a real security product? | The screens that generated (Home, PCAP-selected, Overview, Findings, About, Error for A; Home, PCAP-selected, Overview for B) consistently avoid the V2 composition (centered hero → dropzone → four columns). Both directions replaced the upload hero with a compact intake panel and a recent-analyses list, which is the single biggest structural fix requested. |
| Is the first action obvious? | Yes in both A and B — "Start an investigation" with a file-select control is the only prominent action on Home; everything else is de-emphasized (recent analyses, methodology rail). |
| Is evidence visually important? | **Unverified for this checkpoint.** The Evidence & Provenance screen — arguably the most important screen in the whole brief ("the strongest screen in the product") — did not generate successfully in either direction. This is the single biggest gap in the current deliverable. |
| Is cross-session reasoning understandable? | **Unverified for the same reason** — the Cross-session screen didn't generate for A or B. The Overview screens that did generate do include a one-line cross-session summary module, which is a good sign the concept is wired into the IA, but the dedicated screen (with the abstention-state treatment the brief specifically asked for) is outstanding. |
| Is uncertainty represented honestly? | Partially confirmed: the Overview screens' "What could not be determined" column is present and given equal visual weight to findings, not hidden as a footnote — this matches the brief's "proud of abstaining" instruction. The Error screen (Direction A) uses calm graphite tone, not alarm red, and states the file could not be analyzed without implying partial success. |
| Is AI appropriately secondary? | Confirmed on the screens that show it: AI-assisted prioritisation appears only as a collapsed, off-by-default disclosure on the PCAP-selected screen — never a headline element, never a "threat score." |
| Does it avoid generic SaaS aesthetics? | Direction A reads distinctly editorial (asymmetric grid, serif headers, hairline dividers) — not interchangeable with a generic dashboard template. Direction B is more conventionally "enterprise," which is the intended brief for that direction, but still avoids card-grid-everywhere and rounded-pill excess. |
| Does it feel sophisticated without being flashy? | Yes on the evidence available — zero gradients, zero glow, zero donut/gauge charts appeared in any generated screen; motion is confined to hover/expand states per the design system's own constraint. |
| Does it remain technically truthful? | The six EvidenceState values, posture bands, evidence-certainty badges, and cross-session minimum-history language all appear verbatim from production source rather than invented terminology — confirmed by inspecting the generated screen prompts and outputs. |

**Bottom line:** the two most load-bearing screens in the entire brief (Evidence & Provenance, Cross-session) are exactly the two that failed to generate. Everything else has done well against the brief's own checklist, but this review cannot honestly claim the exploration is "done" — it's a strong partial proof that the composition change works, with the hardest and most important screens still outstanding.

## 2. What clearly worked

- **Killing the upload hero.** Replacing the dashed dropzone with a compact "Start an investigation" panel + recent-analyses list, in both directions, immediately reads less like a generic AI-tool demo.
- **Asymmetric two-column findings/abstentions on Overview.** Giving "What could not be determined" equal visual weight to "Prioritised findings" (not a smaller sidebar, not a footnote) is a direct, visible answer to "be proud of abstaining."
- **Evidence-state visual language separated from severity.** The design system's icon+fill-pattern chip family (vs. hue-coded severity) was consistently honored across every generated screen that showed evidence states — this was a specific risk (the brief explicitly warned "severity and evidence state must remain visually distinct") and it held up.
- **AI kept small.** No screen generated in this session gave AI more than a collapsed disclosure row.

## 3. What's unresolved

1. **Evidence & Provenance and Cross-session screens are missing from both completed directions**, and Direction C has no screens at all. This is the largest open item — see each `design-direction-*/README.md` for exact resume instructions and screen IDs.
2. **Stitch generation service instability.** Roughly half of `generate_screen_from_text` calls in the back half of this session returned a client-side timeout (the tool's own documentation acknowledges this can happen while generation continues server-side) — including on prompts nearly identical to ones that had just succeeded. This looks like transient load on the Stitch service rather than anything content- or prompt-specific: even the simplest possible prompts (Direction B's About screen, previously reliable on Direction A) began failing late in the session. Resume by retrying with 30–50s spacing between calls.
3. **Screenshots are thumbnail-resolution** (≤512px long edge, as returned by Stitch's preview endpoint) — fine for this review, not fine for a pitch deck. Pull full-resolution exports before using these anywhere presentation-facing.
4. **Illustrative content needs a pass before any screen leaves this exploration folder.** Every generated screen contains invented example data (filenames, hashes, specific finding titles) needed to make a mockup legible. `IMPLEMENTATION-HANDOFF.md` flags this, but a reviewer skimming the PNGs directly could mistake it for a real captured result — worth a visible "MOCKUP DATA" watermark or caption convention if these screenshots get reused outside this doc set.

## 4. Recommendation

Do not pick a direction yet. Finish generating the two missing screen types (Evidence & Provenance, Cross-session) for at least Directions A and B before comparing — those are the screens the brief calls the differentiator and the strongest screen in the product, and no real comparison between directions is possible without them. Direction C needs a full pass. See `IMPLEMENTATION-HANDOFF.md` for what to do once all 24 exist.
