# Direction A — Editorial Forensic Workspace

Stitch project: `SecureMailScope — SIH Design Exploration` (`projects/3061007934706342720`)
Design system asset: `assets/15827507881879585303` — "A. Editorial Forensic Workspace"

**Concept:** Swiss editorial layout discipline (strong grid, asymmetric columns, generous margins) crossed with the credibility of a forensic report. A calm, restrained analyst report brought to life as software — not a dashboard, not a SaaS product.

**Structural signature:** persistent left navigation (icon + label) beside a wide analytical canvas; asymmetric two-column grids (never equal-width); Newsreader editorial serif reserved for section titles/report headers only, Geist for everything else, JetBrains Mono for all timestamps/hashes/protocol fields. Roundness 4px. Density 6/10, motion 2/10 (near-static, functional transitions only).

## Screens generated (6 of 8)

| # | Screen | Status | File |
|---|---|---|---|
| 1 | First-run / Home | ✅ Generated | `screenshots/a1-home.png` |
| 2 | PCAP selected / ready-to-analyze | ✅ Generated | `screenshots/a2-pcap-selected.png` |
| 3 | Analysis Overview | ✅ Generated | `screenshots/a3-overview.png` |
| 4 | Findings | ✅ Generated | `screenshots/a4-findings.png` |
| 5 | Evidence & Provenance | ⏳ Pending — Stitch generation timed out repeatedly (6 attempts); not yet produced |
| 6 | Cross-session reasoning | ⏳ Pending — Stitch generation timed out repeatedly (2 attempts); not yet produced |
| 7 | About / Methodology | ✅ Generated | `screenshots/a7-about.png` |
| 8 | Error state | ✅ Generated | `screenshots/a8-error.png` |

Stitch project screen IDs (for resuming generation or editing in the Stitch UI directly):
- Home: `projects/3061007934706342720/screens/8a9158ade56c49b18feb1e7774e1eca2`
- PCAP selected: `projects/3061007934706342720/screens/582aa5ee777a4930b6a63be7ed6649fe`
- Overview: `projects/3061007934706342720/screens/8c1fbf6eafc94a0091d82eb83132eee2`
- Findings: `projects/3061007934706342720/screens/dc1e710a5b594d438275eb6d9f944da2`
- About: `projects/3061007934706342720/screens/1e991f1e1f614e45855f7f02d5a48209`
- Error: `projects/3061007934706342720/screens/8ecd403320124d498fac21f08d8d1e09`

## What's real vs. illustrative in these mockups

Grounded in production (verbatim or near-verbatim from source): posture band words (STRONG/ADEQUATE/WEAK), the six EvidenceState values and their basis text (e.g. "TLS 1.3 encrypts the Certificate message"), evidence-certainty badge values (CONFIRMED/PROBABLE/UNCERTAIN/UNDETERMINED), the "8 of 8 sessions assessed — missing evidence never improves this score" coverage framing, the cross-session membership phrase, the AI's bounded-signal framing, and the supported-protocol line (SMTP/IMAP/POP3, STARTTLS/STLS, implicit TLS).

Illustrative only (invented for legibility, not a product claim): specific filenames (`smtp_ingress_tls_boundary_20250514.pcapng`), byte counts, SHA-256 prefixes, stream counts, specific finding titles ("Deprecated 3DES cipher suite..."), specific RFC section citations attached to those example findings, and the numeric score ("68/100"). None of this should be read as verified output — it exists only so the screen isn't blank. Any real integration must pull these fields from the actual `DashboardViewModel` (`src/securemailscope/dashboard/model.py`) — see `IMPLEMENTATION-HANDOFF.md`.

## Gaps to close before this direction could be considered "done"

1. Evidence & Provenance and Cross-session reasoning screens still need to be generated (Stitch generation service was intermittently timing out — see `DESIGN-REVIEW.md` and the session's status notes).
2. Screenshots captured here are Stitch's thumbnail-resolution previews (≤512px on the long edge); a final pass should pull full-resolution exports before this goes into a pitch deck.
