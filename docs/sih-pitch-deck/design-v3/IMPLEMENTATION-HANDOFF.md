# Implementation Handoff — V3 Stitch Exploration

This document is for whoever resumes or eventually implements this design work. It is **not** an instruction to implement anything now — per the brief, no production code, no `src/`, no `tests/`, no backend/API/security-engine changes have been made, and none should be made from this document without a separate, explicit decision to proceed.

## 1. Where everything lives

- Stitch project: `SecureMailScope — SIH Design Exploration`, `projects/3061007934706342720` (private, owned by the session's authenticated Stitch account).
- Three design systems, one per direction, all light-mode:
  - A — Editorial Forensic Workspace: `assets/15827507881879585303`
  - B — Premium Security Analysis Product: `assets/17031975523056476685`
  - C — Technical Investigation Workstation: `assets/17211089811180283360`
- Repo docs: `docs/sih-pitch-deck/design-v3/` — `DESIGN.md` (shared system), `design-direction-{a,b,c}/README.md` (per-direction notes + screenshots), `DESIGN-REVIEW.md` (self-critique), this file.

## 2. How to resume generation

Use `mcp__stitch__generate_screen_from_text` with `projectId: "3061007934706342720"` and the relevant `designSystem` asset ID above. The prompt template used throughout this session (and the one to reuse) follows the generate-design skill's structure: purpose paragraph, `**PLATFORM:**` line, numbered `**PAGE STRUCTURE:**` list — content and layout only, no colors/fonts/hex codes (those live in the design system, not the prompt, per the skill's "no theme leakage" rule).

The exact 8 prompts used for Directions A and B (findable in this session's transcript) cover: Home, PCAP-selected, Overview, Findings, Evidence & Provenance, Cross-session, About, Error. Reuse them verbatim for Direction C with the three-pane structural notes from `design-direction-c/README.md` substituted in.

**On timeouts:** this session saw roughly a 50% timeout rate on generation calls in its second half. The tool's own documentation states generation may still succeed server-side even when the client call times out — but `list_screens` and `get_project` did not surface a usable screen index in this MCP session, so a timed-out call currently has to be treated as failed and retried rather than recovered. Space retries 30–50s apart; simpler/shorter prompts did not reliably time out less often than detailed ones, so don't over-invest in trimming prompts — it's very likely pure service load.

## 3. Real vs. illustrative content — the mapping that matters most

Every generated screen contains invented example data (a filename, a SHA-256 prefix, specific finding titles, a numeric score) so the mockup is legible. **None of it is a product claim.** Before any of this becomes real UI copy, each illustrative field must be traced to its actual source in the `DashboardViewModel` (`src/securemailscope/dashboard/model.py`):

| Mockup shows | Real source |
|---|---|
| Posture band word ("ADEQUATE") | `DashboardViewModel.posture.label` (values: STRONG/ADEQUATE/WEAK/CRITICAL/INSUFFICIENT_EVIDENCE) |
| Numeric score | `posture.score_value` / `posture.score_text` |
| Coverage line | `posture.known` / `withheld` / `coverage.summary_text` — note `withheld` is real: Phase 7 can withhold the band below a coverage floor |
| Finding row (severity, title, explanation) | `FindingRow` — `severity`, `severity_label`, `title`, `conclusion`, `explanation` |
| Evidence-certainty badge | `FindingRow.certainty` (CONFIRMED/PROBABLE/UNCERTAIN/UNDETERMINED) |
| Standard citation tag | `FindingRow.citations` |
| Abstention row | `AbstentionRow` — `reason_label`, `what_could_not_be_concluded`, `why` |
| Evidence chip + basis text | `EvidenceRef` (`field_name`, `observed_value`, `evidence_state`, `basis`, `frames`) |
| Provenance rail node counts | derived from `coverage.*` and `identity.*` — no dedicated per-node count field exists yet in the API; this would need a small addition to `DashboardViewModel` or a client-side derivation |
| Cross-session comparison | `crosssession` rule outputs (`CS-STARTTLS-001/002`, `CS-TLS-001`) + `BaselineStatus` / `Deviation` — **not yet a field on `DashboardViewModel`** as far as this session's research established; confirm before implementing |
| AI panel copy | `MLPanel` — `role`, `note`, `facts`, `limitations`, `boundary_statement` |

Filenames, byte counts, hashes, and stream counts shown in mockups have no real source — they come from `RunResponse.source_filename` / artifact metadata / `Identity.capture_id` and would need to be wired from the actual run, not hard-coded.

## 4. API surface already available

Base path `/api/v1`. There is **no separate findings/evidence/cross-session endpoint** — `GET /analyses/{run_id}/dashboard` returns the full `DashboardViewModel` in one call, already projected and label-paired from the canonical `PostureAssessment` (`GET /analyses/{run_id}/assessment`). Any of the three directions could be implemented against this one endpoint; the differences between directions are purely presentational (layout, density, navigation), not data-shape differences. This is a meaningful point in favor of *any* of the three directions being feasible to build without new backend work, modulo the provenance-rail node-count gap noted above.

## 5. Terminology guardrails for whoever writes real UI copy

Carried over from `docs/sih-pitch-deck/DO-NOT-CLAIM.md` — do not let real implementation copy drift into any of: "AI detects attacks/attackers," unqualified "we validate certificates," "certificate trust checked," "revocation checked," "zero false positives," "100% detection," "real-time," "first/unique/only/revolutionary," "chain of custody," "air-gapped" (say "runs without network access" instead), or `NOT_APPLICABLE` used as an EvidenceState value (it belongs to `BaselineStatus`).

## 6. Suggested next session

1. Finish the 15 remaining screens (see each direction's README for exact counts and screen IDs).
2. Do the side-by-side comparison the brief asks for — only possible once Evidence & Provenance and Cross-session exist for all three directions.
3. Get the user's explicit direction choice (brief: "DO NOT choose and implement a direction automatically").
4. Only after that: a separate, explicitly-scoped implementation task — this doc is the map for it, not the task itself.
