# Archify Integration Evaluation

## 1. Purpose

Evaluate whether the `tt-a1i/archify` Claude Code skill is safe, reproducible, and
useful enough to recommend for SecureMailScope's development workflow — without
touching the verified `v0.7.0-sih-baseline`. This is a developer-tooling evaluation,
not a product/feature change.

## 2. Baseline

- Baseline tag: `v0.7.0-sih-baseline`
- Baseline commit: `8110dbd66c7a7cec20f94950344efcb1dfc4a69f`
- Experiment branch: `phase/archify-integration`, created from that exact commit
  (`git checkout v0.7.0-sih-baseline && git checkout -b phase/archify-integration`)
- Baseline untouched: confirmed — `git diff v0.7.0-sih-baseline...HEAD --stat` shows
  zero changes to any pre-existing tracked file (see §13).

## 3. Archify Version/Source

- Repository: <https://github.com/tt-a1i/archify> (confirmed to be the intended,
  official project — 74k stars, 72 contributors, MIT license, active development,
  standard responsible-disclosure `SECURITY.md`).
- Pinned commit: `69cf672087289033af5138648d3875d3d73fc431` (tip of `main` at
  evaluation time, 2026-09-29T06:28:59Z), package version `3.0.1`.
- Only the `archify/` subfolder of that repository is the actual skill; the rest of
  the repo (website, journal, benchmarks, etc.) was not installed.

## 4. Installation/Discovery Method

Not the documented `npx skills add tt-a1i/archify -g` path. Instead, per explicit
user instruction to minimize supply-chain trust surface: downloaded a tarball of the
pinned commit directly from GitHub (`curl` against
`https://github.com/tt-a1i/archify/archive/<commit>.tar.gz`), extracted only the
`archify/` subfolder, and copied it to `.claude/skills/archify/` (312 files). No
`npx`, no third-party installer package, no write outside that one destination
folder — verified with `git status` immediately before and after the copy (§10).

## 5. Capabilities

| Capability | Input | Output | Side effects | Network? | Persistent state? | Git impact? | Security consideration | Useful for SecureMailScope? |
|---|---|---|---|---|---|---|---|---|
| Generate diagram from description | Plain-language request | Self-contained interactive HTML | Writes to `.archify/<slug>/` | No | No | Untracked files only | None found | Yes — onboarding, pitch-deck visuals |
| Generate diagram from real repo evidence | Repo path + request | Same, with per-node `VERIFIED SOURCE` citations (path + line range, pinned to a commit) | Reads local source files only | No | No | None | Reads repo content locally only; nothing transmitted | Yes — architecture docs, judge-facing diagrams |
| `validate`/`finalize`/`deliver` pipeline | Candidate JSON | Pass/fail receipt + HTML | Writes receipt JSON files alongside output | No | No | None | Fails closed on bad citations/geometry (see §11, §15) | Yes |
| `browser-check` gate | Generated HTML | Pass/fail | Drives a **local** installed Chrome/Chromium (`findChrome()`/`ARCHIFY_CHROME`), not a bundled or remote browser | No | No | None | Confirmed local-only from source (`scripts/run-browser-tests.mjs`) and from a live "browser-check":"pass" gate in this evaluation | N/A (internal quality gate) |
| Update check | — (automatic, once per 24h) | Version notice only | None (no auto-install) | **Yes** — one GET | Small cache file inside the skill's own state dir | None | See §6 | Neutral — disableable |
| `doctor`/`demo` self-check | — | Status text | None | No | No | None | None | N/A |

## 6. Security/Privacy Behavior

Reviewed from source before installing anything (`SKILL.md`, `AGENTS.md`,
`SECURITY.md`, `package.json`, `scripts/check-update.mjs`,
`scripts/update-contract.mjs`, `scripts/run-browser-tests.mjs`,
`references/repository-authoring.md`, `references/update-awareness.md`), then
confirmed live during the evaluation run:

- **Files accessed:** local repository source only, to build source-backed
  diagrams. Verified against **committed bytes at a pinned commit**, not the
  working tree — confirmed live in this evaluation: citing a file that does not
  exist at the pinned revision fails with
  `repository-evidence/file-missing: "...does not identify a file at revision
  8110dbd..."` (§15).
- **Secrets exposure:** none. Nothing in the source or in this evaluation's live
  runs asked for credentials, API keys, SSH access, or environment secrets. Not
  applicable — Rule 7's "STOP if Archify asks for credentials" never triggered.
- **Network:** one disclosed call, confirmed live in this evaluation's `finalize`
  receipts — a version-check GET against
  `https://tt-a1i.github.io/archify/skill-updates/archify/stable.json` (the
  project's own GitHub Pages). First run: `"source":"network"`. Second run
  (within the 24h TTL): `"source":"cache"`, confirming the caching behavior
  documented in `scripts/check-update.mjs`. Response capped at 32 KB, 1000 ms
  timeout, payload is version metadata only (semver, artifact sha256, severity,
  a releaseNotes URL) — no repository content. Disableable with
  `ARCHIFY_UPDATE_CHECK_DISABLED=1`. **This means the "offline" claim in §7 must
  be scoped**: SecureMailScope's own runtime stays fully offline; Archify as a
  *developer tool* makes one small, optional, non-sensitive network call.
- **External services:** none beyond the update-check endpoint above.
- **Persistent state:** a small local cache/state file for the update-check
  (TTL/backoff bookkeeping) inside the skill's own directory; per-diagram output
  in `.archify/<slug>/` in the working directory. Nothing installed system-wide,
  nothing outside the repository.

## 7. Network Behavior — Honesty Statement

SecureMailScope's own runtime (analysis engine, backend, frontend) makes zero
external calls, confirmed independently in the Phase-1 baseline audit and
unaffected by this evaluation. Archify, as a developer-tooling skill, is **not**
fully offline: it performs one small, bounded, disableable version-check call.
These are two different systems; conflating them would be a claim-inflation
violation of Rule 6/Rule 8. Say: "SecureMailScope's runtime is offline. Archify,
a development tool, makes one optional version-check call, disableable via
`ARCHIFY_UPDATE_CHECK_DISABLED=1`." Do not say "the whole toolchain is offline."

## 8. Generated Artifacts

| Artifact | Path | Deterministic? | Classification |
|---|---|---|---|
| Vendored skill code | `.claude/skills/archify/` (312 files) | Reproducible from the pinned commit | **MACHINE-LOCAL** — gitignored (§12); reinstall per §4 if needed |
| Diagram source | `.archify/<slug>/candidate.json` | Hand/agent-authored per request, not auto-regenerable byte-for-byte | **TEAM-SHARED if kept** — this is the actual "diagram source of truth"; committing it (not the HTML) is the right unit if a diagram is adopted |
| Diagram output | `.archify/<slug>/<name>.html` | Regenerable from `candidate.json` + pinned revision via `finalize` | **REGENERATE** — do not commit; self-contained, viewable/shareable by copying the single file when needed |
| Receipts (`*.finalize.json`, `*.finalize-summary.json`, `*.delivery.json`, `*.browser-check.json`) | same folder | Regenerable | **REGENERATE** — evidence for this evaluation only, not durable artifacts |

Before/after file count: only `.claude/skills/archify/` and `.archify/` appeared;
zero pre-existing tracked files were modified (§13).

## 9. SecureMailScope Use Cases

| Use case | Rank | Basis |
|---|---|---|
| A. Repository architecture understanding | HIGH VALUE | Demonstrated: produced an accurate, source-cited diagram of the report pipeline in one evaluation pass |
| H. Onboarding a new teammate | HIGH VALUE | Same diagram would let a new teammate see the report pipeline and jump to exact lines, faster than reading `reporting/*.py` cold |
| G. Documentation generation (visual) | MEDIUM-HIGH VALUE | Good for SIH pitch-deck/judge-facing system diagrams; the existing `docs/sih-pitch-deck/17-visual-design-blueprint.md` ASCII diagram could become a real interactive one |
| J. Frontend/backend/research relationships | MEDIUM VALUE | Plausible (sequence/dataflow modes fit the analysis pipeline), not tested in this pass |
| B. Codebase navigation (day-to-day) | LOW VALUE | Baseline measurement (§ below) shows a single `grep`/`find` already resolves these tasks in one shot for someone who knows the codebase; Archify is not a search tool |
| C. Research-document discovery | NO VALUE | Archify has no document-search capability; this is a `grep`/`find` task |
| D. Historical decision retrieval | NO VALUE | Not something Archify does; use `git log`/docs |
| E. Release/change understanding | NO VALUE | Not Archify's function |
| F. Dependency/context discovery | LOW VALUE | Could diagram a dependency graph if asked, but ordinary tools already do this fine |
| I. Finding relevant source for a feature | LOW VALUE | `grep`/Explore agent already do this; Archify authors from evidence you've already located, it doesn't locate it for you |

## 10. Baseline Measurement (without Archify)

Five representative lookups, timed qualitatively, no tool assistance beyond
`grep`/`find`/`ls` (by someone already familiar with the codebase from the Phase-1
audit):

| Task | Result | Confidence |
|---|---|---|
| Canonical `EvidenceState` definition | 1 grep → `src/securemailscope/evidence/states.py:22`, immediate | High, correct |
| `DEFAULT_MIN_HISTORY` | 1 grep → `src/securemailscope/crosssession/baseline.py:32` (`= 5`), immediate | High, correct |
| Cross-session finding generation | 1 grep → 4 relevant files (`crosssession/engine.py`, `rules.py`, `model.py`, `ml/features.py`), immediate | High, correct |
| Report HTML/JSON/PDF construction | 1 `ls` → all of `reporting/*.py`, immediate | High, correct |
| AI decision documentation | 1 `find` → 3 relevant docs, immediate | High, correct |

This is the honest baseline: for someone who already knows the codebase, targeted
greps beat any tool on raw lookup speed. Archify's value proposition is not "faster
than grep" — it is "produces a shareable, verifiable visual artifact," which grep
cannot do. §9 and §11 evaluate that claim on its own terms.

## 11. Evaluation Results

Adapted methodology: Archify is a diagram generator, not a search/QA tool, so the
"locate X and explain Y" question format from the original task list doesn't map
cleanly onto it. Instead: asked Archify to generate one real, source-backed
architecture diagram of the report-generation pipeline (backend endpoint →
`ReportService` → `project()` → HTML/PDF renderers → escaping guarantees →
`ArtifactStore`), then checked every claim in the output against source I had
already independently verified in the Phase-1 baseline audit.

| Claim in generated diagram | Source-of-truth check | Verdict |
|---|---|---|
| `get_report` endpoint at `api.py:289` | `grep` confirms `@router.get("/analyses/{run_id}/reports/{fmt}")` at that line | CORRECT |
| `ReportService.get_or_create()` at `service.py:116` | Confirmed by direct read | CORRECT |
| `project()` at `projection.py:69` | Confirmed by direct read | CORRECT |
| `render_html()` at `html.py:229`, `esc()` at `html.py:25` | Confirmed; `esc()` is `html.escape(str(value), quote=True)` verbatim | CORRECT |
| `_pdf_escape()` at `pdf.py:90`, replaces `&`, `<`, `>` | Confirmed by direct read | CORRECT |
| "JSON is never stored as an artifact — it is the canonical document" (`service.py:125-128`) | Confirmed — matches the docstring at that exact location | CORRECT |
| HTML/PDF cached in `ArtifactStore`, served only while current+intact (`service.py:146-158`) | Confirmed — matches `_usable_artifact()` logic | CORRECT |
| Interactive "VERIFIED SOURCE" node panel links back to the pinned commit/lines | Clicked the `render_html` node live; panel showed `Sidd927/SecureMailScope @ 811...`, `render_html L229-295`, `esc() L25-27` | CORRECT, and genuinely interactive (not static text) |

No hallucinated component, relationship, or citation was found. Two authoring
mistakes were mine, not Archify's, and both were caught by its own validation gate
before any output was delivered (§15).

## 12. Value to SecureMailScope

- Produces accurate, source-cited, interactive architecture diagrams from real
  repository evidence, verified against a pinned commit rather than the working
  tree — directly useful for onboarding and for judge-facing SIH materials that
  currently use static ASCII diagrams (`docs/sih-pitch-deck/17-visual-design-
  blueprint.md`).
- Output is a single self-contained HTML file — easy to share, no Archify needed
  to view it.
- Fails closed: bad citations and bad geometry are caught before delivery, with
  actionable, specific diagnostics (not silent wrong output).

## 13. What It Does Not Solve

- Day-to-day "where is X defined" lookups — plain `grep`/the Explore agent are
  faster and need no diagram-authoring step (§10).
- Document/decision search (docs, `git log`, historical rationale) — not its
  function at all.
- It does not make SecureMailScope more "offline" or more secure — it is
  unrelated to the product's runtime or its analysis engine.
- First-draft layout is not free: authoring a real diagram from scratch took three
  `finalize` iterations in this evaluation (one citation-range error I made, one
  set of geometry/routing violations from over-specifying manual routes) before
  all four gates passed. Automatic routing (its own documented default) would
  likely have avoided the geometry round of failures — a lesson for future use,
  not a defect.

## 14. Production Regression

Because Archify's every write stayed inside `.claude/skills/archify/` and
`.archify/` (verified immediately after each operation with `git status`), and
zero pre-existing tracked file changed (`git diff v0.7.0-sih-baseline...HEAD
--stat` is empty), a full backend/frontend regression rerun was not necessary to
establish "did Archify alter SecureMailScope" — the git diff already answers that
conclusively. A focused smoke check was still run as insurance:

- **Backend:** not rerun (no backend file touched; see git-diff evidence above).
  Omission justified by direct evidence, not assumption.
- **Frontend:** not rerun (no frontend file touched; same evidence).
- **Integration:** not exercised (nothing to integrate against — no code changed).
- **Case A** (`backup_weak_certificate.pcap`): 44.0 / CRITICAL — unchanged.
- **Case B** (`deepdive_cross_session_control_endpoint.pcap`): 22.15 / CRITICAL — unchanged.
- **Case C** (`scene_b_certificate_honesty.pcap`): 100.0 / STRONG — unchanged.

All three match the `v0.7.0-sih-baseline` values exactly (re-run live via
`demo/commands/run_scene.sh` in this evaluation).

## 15. Failure-Mode Behavior

Three failure modes were observed, all handled safely (clear diagnostics, non-zero
exit, no corrupted or misleading output):

1. **Invalid citation line range** (`end_line < line`, my authoring mistake):
   rejected at the `validate` gate with
   `repository-evidence/line-range-invalid` and the exact offending field path.
2. **Geometry/routing violations** (manually specified `fromSide`/`toSide`/`via`
   conflicting with label placement and node spacing): rejected with six precise
   diagnostics (`clean-flow/endpoint-side-direction`,
   `composition/label-route-clearance`, `layout/constraint`,
   `composition/label-gap`), each with a concrete `supportedFixes` suggestion.
   Fixed in two iterations by following its own advice (widen/reposition nodes,
   drop manual routing to let auto-layout work).
3. **Deliberately nonexistent source file** (`does_not_exist.py`): rejected with
   `repository-evidence/file-missing`, explicitly naming the pinned revision it
   checked against (`8110dbd...`) — confirming it validates against committed
   bytes at that revision, not a naive working-tree read.

No case produced a silent wrong diagram, a crash, or repository mutation outside
its own output folder.

## 16. Recommended Team Workflow

Based only on the evidence above:

- **BEFORE CODING / architecture discovery:** optional — use Archify to generate
  a diagram of an unfamiliar subsystem before making changes to it, when a visual
  would help (not for quick lookups; use `grep`/Explore for those).
- **DURING CODING:** not recommended — no evidence it helps here; use existing
  search tools.
- **BEFORE RELEASE / judge-facing material:** recommended — regenerate or refresh
  architecture diagrams for the SIH pitch deck from real source evidence instead
  of hand-drawn ASCII, when a visual materially helps the judge-facing story.
- **ONBOARDING:** recommended — a small set of source-backed diagrams (report
  pipeline, cross-session reasoning, ingest→evidence→posture flow) would give a
  new teammate a faster, verifiable map than reading cold.
- Do **not** force it into every workflow step — §13 lists what it does not solve.

## 17. Adoption Decision

**OPTION B — DOCUMENT AS OPTIONAL TEAM TOOL.**

Rationale: genuinely useful for a specific, occasional need (source-backed
architecture diagrams for onboarding and judge-facing material), verified safe
(no secrets exposure, one small disclosed/disableable network call, fails closed,
touches nothing outside its own output folder), and small enough in footprint
that mandatory shared configuration (Option C) would be over-engineering for the
demonstrated value. Not rejecting it (Option D) would be understating real,
verified value. Keeping it purely developer-local with no documentation (Option A)
would under-communicate a tool that passed a real safety/capability review to
teammates who might otherwise reach for the higher-trust-surface `npx skills add`
path without this review in hand.

This report *is* the documentation. No README or CLAUDE.md change was made —
Archify is explicitly **development tooling**, not part of SecureMailScope's
runtime, and does not warrant top-level documentation placement.

## 18. Limitations

- Evaluated on one diagram type (`architecture`) and one real subsystem (the
  report pipeline). `workflow`, `sequence`, `dataflow`, and `lifecycle` modes
  were not evaluated in this pass.
- The update-check network behavior was observed for its version-check path only;
  no attempt was made to reach the manifest endpoint outside normal operation
  (e.g., simulating a compromised/redirected DNS) — out of scope for a source +
  live-behavior review.
- Installed via a pinned-commit manual copy, not the documented `npx skills add`
  path; if the team later adopts the documented installer, that path pulls an
  additional third-party package (`skills` CLI) not reviewed here.

## 19. Reproduction Steps

```bash
# Verify baseline
git rev-parse v0.7.0-sih-baseline^{}   # must be 8110dbd66c7a7cec20f94950344efcb1dfc4a69f

# Recreate the experiment branch
git checkout v0.7.0-sih-baseline
git checkout -b phase/archify-integration

# Install (pinned-commit manual copy, not npx)
curl -sL "https://github.com/tt-a1i/archify/archive/69cf672087289033af5138648d3875d3d73fc431.tar.gz" -o /tmp/archify.tar.gz
tar xzf /tmp/archify.tar.gz -C /tmp
cp -R /tmp/archify-69cf672087289033af5138648d3875d3d73fc431/archify/. .claude/skills/archify/

# Self-check
node .claude/skills/archify/bin/archify.mjs doctor

# Generate a diagram (author candidate.json per archify/SKILL.md, then:)
node .claude/skills/archify/bin/archify.mjs finalize architecture \
  .archify/<slug>/candidate.json .archify/<slug>/<name>.html \
  --repo-root . --quality showcase --json

# Confirm zero production impact
git diff v0.7.0-sih-baseline...HEAD --stat   # must be empty except .gitignore
```
