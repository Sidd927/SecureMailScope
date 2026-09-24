# Direction B — Premium Security Analysis Product

Stitch project: `SecureMailScope — SIH Design Exploration` (`projects/3061007934706342720`)
Design system asset: `assets/17031975523056476685` — "B. Premium Security Analysis Product"

**Concept:** Modern enterprise security product crossed with high-end productivity software — the calm precision of a professional analytics tool, not a marketing SaaS site. Extremely refined navigation, strong hierarchy through weight/spacing, minimal decoration, compact analytical components instead of card grids.

**Structural signature:** refined top navigation with a secondary contextual tab/segment rail per section; Geist sans throughout (no serif — deliberately, this is a software product, not an editorial piece); Google Sans Mono for all numerics/timestamps/IDs. Roundness 8px (a touch softer than A/C, matching enterprise-SaaS conventions without tipping into "excessive rounded pill everything," which is explicitly banned). Density 5/10, variance 4/10 (orderly, not experimental), motion 3/10 (refined hover/focus/expand only).

## Screens generated (3 of 8)

| # | Screen | Status | File |
|---|---|---|---|
| 1 | First-run / Home | ✅ Generated | `screenshots/b1-home.png` |
| 2 | PCAP selected / ready-to-analyze | ✅ Generated | `screenshots/b2-pcap-selected.png` |
| 3 | Analysis Overview | ✅ Generated | `screenshots/b3-overview.png` |
| 4 | Findings | ⏳ Pending — Stitch generation timed out repeatedly |
| 5 | Evidence & Provenance | ⏳ Pending — Stitch generation timed out repeatedly |
| 6 | Cross-session reasoning | ⏳ Pending — Stitch generation timed out |
| 7 | About / Methodology | ⏳ Pending — Stitch generation timed out |
| 8 | Error state | ⏳ Not yet attempted |

Stitch project screen IDs:
- Home: `projects/3061007934706342720/screens/6297656765ec4829aa0b5ead3916d954`
- PCAP selected: `projects/3061007934706342720/screens/fc6eec724a21419395fd4a830f1de484`
- Overview: `projects/3061007934706342720/screens/990a9f0f30724cc099c3688c2c23e579`

## What's real vs. illustrative

Same grounding rules as Direction A (see `design-direction-a/README.md` — the underlying vocabulary is identical system-wide, only the skin differs): posture bands, six EvidenceState values, evidence-certainty badges, coverage framing, and cross-session membership language are all real product vocabulary. Specific filenames, hashes, byte counts, finding titles, and the numeric score shown in these mockups are invented for legibility only — not a claim about actual analysis output.

## Why this direction stalled early

Direction B's generation calls hit the Stitch service's intermittent timeout window harder than Direction A's did — Findings, Evidence, Cross-session, and About all failed on every attempt made in this session (see `DESIGN-REVIEW.md` for the full timeout log and the session pause decision). This is very likely unrelated to the direction's content and purely a function of when in the session those calls landed; resuming should pick up cleanly using the design system asset ID above.

## Next steps to complete this direction

1. Generate the remaining 5 screens using `assets/17031975523056476685` as the `designSystem` parameter, against `projectId: 3061007934706342720`.
2. Space generation calls out (30–50s) if the service is still under load; each call can legitimately take several minutes per Stitch's own tool guidance.
3. Pull full-resolution screenshots once all 8 exist.
