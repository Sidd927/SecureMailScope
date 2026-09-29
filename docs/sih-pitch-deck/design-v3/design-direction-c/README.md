# Direction C — Technical Investigation Workstation

Stitch project: `SecureMailScope — SIH Design Exploration` (`projects/3061007934706342720`)
Design system asset: `assets/17211089811180283360` — "C. Technical Investigation Workstation"

**Concept:** Forensic investigation environment crossed with developer tooling and a professional scientific interface. The most information-dense of the three directions, with session comparison as a first-class, persistently accessible concept rather than a screen you have to navigate to.

**Structural signature:** three-pane layout — persistent left rail (navigation + session context), central analytical canvas, right-hand contextual inspector panel that opens on demand. IBM Plex Sans for headline and body (engineering-grade, chosen for its technical/scientific character). **Density override:** because density exceeds 7/10, every numeric value system-wide — byte offsets, timestamps, ports, session IDs, protocol fields, counters — renders in JetBrains Mono without exception. Roundness 4px, border-top dividers replace cards almost everywhere. Single accent is a muted amber-rust (`#8A5A2B`), used sparingly like a highlighter for active evidence markers and the selected provenance node — never decoratively. Density 8/10 (cockpit-dense, not cluttered), motion 2/10 (static/functional only).

The evidence/provenance rail is the signature component for this direction: rendered like a technical schematic with explicit node connectors and hex/byte references, not a generic table.

## Screens generated (0 of 8)

No screens were generated for this direction in this session — the Stitch generation service was intermittently timing out by the time Direction C's turn came up (see `DESIGN-REVIEW.md`), and the session paused generation at the user's direction before reaching it.

The design system itself **is** fully created and applied in the Stitch project (`assets/17211089811180283360`), so generation can resume directly against it without redoing the design-token work.

## What Direction C is intended to prove out

Per the original brief, this direction should be the strongest test of:
- Session comparison as a persistently visible concept (not buried behind a tab), directly addressing "the product should be proud of abstaining when evidence is insufficient."
- A provenance rail that reads as a technical schematic (hex/byte node references, explicit connectors) rather than a data table — the most literal interpretation of "forensic evidence rail."
- Whether extreme information density (8/10) can still read as calm and intentional rather than cluttered, which is the hardest needle to thread of the three directions.

## Next steps to complete this direction

1. Generate all 8 screens using `assets/17211089811180283360` as the `designSystem` parameter, against `projectId: 3061007934706342720`. Reuse the same 8 screen prompts drafted for Directions A/B (home, PCAP-selected, overview, findings, evidence, cross-session, about, error), adapted for the three-pane layout described above — the prompt text used for A and B is preserved in this session's transcript and can be reapplied with direction-specific structural notes swapped in.
2. Because this direction is the most content-dense, expect longer generation times per screen than A/B — pace retries accordingly.
3. Once generated, this direction in particular should get an explicit "does 8/10 density still feel calm?" gut-check per `DESIGN-REVIEW.md`'s self-critique checklist.
