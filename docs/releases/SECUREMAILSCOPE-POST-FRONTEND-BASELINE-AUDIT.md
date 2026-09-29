# SecureMailScope — Post-Frontend Release Baseline Audit

## 1. Executive Summary

The frontend teammate's latest push (`frontend/final-polish`, one commit past `frontend-v1.0.1`)
was audited end-to-end: git state, change inventory, backend regression, frontend build,
live backend↔frontend integration, all three golden demo cases, AI on/off equivalence,
report generation (JSON/HTML/PDF), and a focused security sweep.

One genuine security regression was found in the new frontend code — a client-side report
fallback that did not HTML-escape backend-sourced text, reintroducing an XSS class the
backend has a dedicated regression test against. It has been fixed (one file,
`frontend/src/utils/reportDownload.ts`) and verified. No other regressions were found.
Backend, engine, security rules, evidence vocabulary and scoring formulas were not touched
by the frontend change and were not modified by this audit beyond the one fix above.

**Release decision: READY_FOR_BASELINE_FREEZE** (after the one fix, applied and verified
in this audit).

## 2. Audit Date

2026-09-29

## 3. Git Starting State

- Branch: `frontend/final-polish`
- Commit: `9ac6e40` ("feat: finalize frontend polish and theme updates")
- Working tree: clean, no uncommitted changes, no unpushed local commits.
- `frontend/final-polish` (local) was byte-identical to `origin/frontend/final-polish` —
  nothing to pull.

`main` remains intentionally frozen at phase 3 (`2fd5f09`) — this is a documented project
convention (README.md: "`main` is deliberately frozen... every phase from 4 onward lives
on its own branch, tagged at release"), not a sync failure. All backend phases 4–12 and all
frontend work live on `frontend/final-polish`; phase branches `phase/04`…`phase/12` are all
ancestors of `frontend/final-polish` but not of `main`.

## 4. Remote Synchronization

`git fetch --all --tags --prune` ran clean. No remote branch had commits not already present
locally. No divergence, no force-push needed, no destructive operation used.

## 5. Teammate Change Inventory

Since `frontend-v1.0.1` (`7bc27ad`): **one commit**, `9ac6e40`, 48 files changed
(+4330/−2392), entirely inside `frontend/` plus one new doc
(`docs/presentation-layer-content.md`). No backend/engine/security files touched.

Classification:
- **A. Frontend UI** — new landing page (`LandingHero.tsx`, `BinaryWaterfall.tsx`,
  `landing.css`), a cover/reveal page-transition (`sms-pass` custom event wired through
  `App.tsx`), styling/token refinements across `components.css`, `overview.css`,
  `theme.css`.
- **B. Frontend behavior** — `InvestigationContext` gained a third `activeView` state,
  `'landing'`, sitting in front of the existing `'home' | 'workbench'` states; URL/history
  sync (`popstate` listener) added so back-navigation returns to the landing page.
- **C. Frontend API integration** — new `frontend/src/utils/reportDownload.ts`: a
  client-side fallback that builds JSON/HTML/PDF report renditions locally when the
  backend's own report endpoint is unreachable, or when the app is running against local
  fixtures (`useApi: !isUsingFixtures`). This is the file with the finding described in
  §15 below.
- **G. Demo assets** — three new story/hero images.
- **H. Documentation** — `docs/presentation-layer-content.md` (new).

No renamed endpoints, no changed JSON schemas, no evidence-vocabulary changes.

## 6. Architecture Integration Audit

Traced frontend → `/api/v1/*` → FastAPI → analysis pipeline → TShark → evidence → posture →
reports, live, with the real backend running (`PYTHONPATH=src python3 -m
securemailscope.backend --port 8001`) and the real Vite dev server (`frontend`, port 5173,
proxying `/api/v1` → `127.0.0.1:8001` per `frontend/vite.config.ts`).

One integration issue surfaced and was resolved: a **stale Vite dev-server process**,
already running on port 5173 since 14:21 that session (predating this audit and this
backend), was not proxying `/api/v1/*` correctly — it returned the SPA's `index.html` for
every API call instead of forwarding to the backend. Killing that process and starting a
fresh one (same `.claude/launch.json` config, unchanged) fixed it immediately; direct `curl`
against the fresh dev server returned real backend JSON. This was a leftover process
artifact, not a code or config defect — no source or config file was changed to fix it.

No other API contract mismatches, missing fields, or broken endpoints were found.

## 7. Backend Regression Results

Environment note: the project venv had `securemailscope` not installed in editable mode
(pip 21.2.4 predates PEP 660 editable-install support for pyproject-only projects) and was
missing the optional `pypdf`/`scapy` test dependencies. Neither is a code defect — both are
local environment gaps. Fixed for this audit by running with `PYTHONPATH=src` and
installing `pypdf`/`scapy` into the existing venv (no project files changed).

With the full dependency set:

```
1233 passed, 0 failed, 0 skipped in 65.32s (0:01:05)
```

This exceeds the last documented count (1226, per
`docs/sih-pitch-deck/UI-IMPLEMENTATION-NOTES.md`) — organic test growth between that note
and the current commit, not a loss of coverage. Zero failures, zero skips, zero errors.

## 8. Frontend Validation Results

- `npm ci`: clean install, 31 packages, **0 vulnerabilities**.
- `npm run build` (`tsc -b && vite build`): **exit 0**, no TypeScript errors. One
  informational bundle-size warning (662 KB main chunk) — pre-existing, not a build failure.
- `npx oxlint`: **exit 0**. 7 warnings (React hooks/effect style, one unused catch param),
  zero errors. Re-ran clean after the report-download fix.
- No frontend test runner is configured (`package.json` has no `test` script; no
  vitest/jest present) — this predates the audited commit and is not a regression.

## 9. Integration Results

Live walkthrough against the real backend (not fixtures), via the built-in browser:
landing page → "Get Started" → upload/history view → opened a real completed run
(`backup_weak_certificate.pcap`) → Overview → Findings → Certificates → Provenance →
Report → Download HTML.

- "Engine Live" indicator correctly reflected real backend connectivity (it correctly
  showed "Demo Fixture" against the stale/broken proxy before the fix in §6, and switched
  to "Engine Live" immediately once the proxy worked — the fixture-fallback UI is behaving
  exactly as designed for its "no backend" case).
- No console errors during navigation.
- Report → "Download HTML" network request went to the real API
  (`GET /api/v1/analyses/{id}/reports/html?download=true` → `200 OK`), not the client-side
  fallback — confirming the fallback in §15 is a secondary path, not the default one.
- No fabricated/hardcoded data observed; all values traced to the live `AnalysisService`.

## 10. Golden Case A

**Input:** `demo/captures/backup_weak_certificate.pcap` ("generated TLS 1.2, RSA-1024 +
SHA-1"), run live through `AnalysisService` (both via `demo/commands/run_scene.sh` and via
the real backend + UI).

- **Result:** score `44.0`, posture `CRITICAL` — matches the previously validated baseline exactly.
- **Finding:** two HIGH findings, "Certificate public key strength" (RSA 1024-bit) and
  "Certificate signature algorithm" (SHA-1), both `CONFIRMED`, rule `SEC-CERT-003`.
- **Evidence:** Proof panel shows `PUBLIC_KEY RSA 1024-bit · OBSERVED`,
  `SIGNATURE_ALGORITHM SHA-1 · OBSERVED`, `FRAME #6`, `STREAM #0` — matches the original
  "frame 6" claim exactly, verified live in the UI, not assumed.
- **Frontend:** Overview, Findings, Certificates, and Provenance tabs all render this
  correctly from live backend data; "Open Frame #6" and "Trace Provenance" both wired.

## 11. Golden Case B

**Input:** `demo/captures/deepdive_cross_session_control_endpoint.pcap`.

- **Result:** score `22.15`, posture `CRITICAL` — matches the previously validated baseline exactly.
- **Finding:** HIGH "Authentication activity without TLS protection", MEDIUM "Mail session
  carried no TLS", MEDIUM "STARTTLS/STLS advertisement deviation from baseline".
- **Evidence:** `provenance.source_counts.cross_session_findings = 22`; rule IDs include
  `CS-STARTTLS-001`, `CS-STARTTLS-002` (cross-session rules), confirming cross-session
  reasoning fired, not just single-session rules.
- **Frontend:** not deep-dived per-tab in this pass (Case A and C were walked through the
  full UI); score/posture reproduction was verified via the live backend API used by the
  same UI.

## 12. Golden Case C

**Input:** `demo/captures/scene_b_certificate_honesty.pcap` (TLS 1.3).

- **Result:** score `100.0`, posture `STRONG` — matches the previously validated baseline exactly.
- **Finding:** all issue groups are `INFO` (non-penalising) — no penalized findings.
- **Evidence:** `limitations` includes verbatim: "certificate chain, expiry and key
  strength are not observable for TLS 1.3 or resumed sessions (RFC 8446 §5.2, §2.2)" —
  matches the "certificate NOT_OBSERVABLE" claim.
- **Frontend:** not separately screenshot in this pass; score/limitations verified via the
  same live backend path used by the UI.

## 13. AI On/Off Validation

**Input:** `demo/captures/scene_c_no_ai_equivalence.pcap`, run both `ai_enabled=False` and
`ai_enabled=True`.

- **AI disabled:** score `88.0`, posture `ADEQUATE`.
- **AI enabled:** score `88.0`, posture `ADEQUATE`.
- **Equivalence:** identical — confirmed live, not assumed.
- **New AI claims in the audited commit:** NO. Diffed the entire commit for AI/ML-related
  copy changes — none found.

## 14. Report Validation

Generated all three formats for Case A directly through the backend's `reporting` module
(`project`/`render_html`/`render_pdf`, the same code the API endpoints call):

- **JSON:** 27,230 bytes, valid.
- **HTML:** 22,781 bytes. No `<script>` tag, no external `http(s)://` references (offline-safe).
- **PDF:** 18,645 bytes, 7 pages, parsed and text-extracted successfully with `pypdf`.

Frontend "Download HTML" in the live UI routed through the real API endpoint, not the
client-side fallback (see §9, §15).

## 15. Security Validation

Swept for: `dangerouslySetInnerHTML`, `eval`/`new Function`, external `fetch()` targets,
analytics/telemetry libraries, hardcoded secrets/API keys, tracked `.env` files, and
backend shell invocation patterns. All clean:

- No `dangerouslySetInnerHTML` in frontend source.
- No `eval`/`new Function`.
- No external network calls or telemetry/analytics libraries.
- No hardcoded secrets/keys; no `.env*` files tracked in git.
- Backend TShark invocation uses `subprocess.run`/`Popen` with argument arrays only, never
  `shell=True` — matches its own documented contract and existing
  `test_no_shell_injection_via_filename` coverage.

**One finding (SEVERITY: MEDIUM, found and fixed in this audit):**

- **Location:** `frontend/src/utils/reportDownload.ts`, function `reportHtml()`.
- **Evidence:** the backend has a dedicated regression test
  (`tests/reporting_fixtures.py::hostile_assessment`, exercised by
  `test_hostile_payloads_are_escaped` and `test_hostile_assessment_renders_as_text_everywhere`
  in `tests/test_reporting_html.py`) that injects
  `HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(1)>'` into exactly the
  fields `issue_groups[].title` and `remediation_summary[].recommended_action`, and asserts
  the backend's HTML renderer (`html.escape`-based, `src/securemailscope/reporting/html.py`)
  neutralizes it. The new frontend fallback interpolated those same two
  backend-sourced fields (plus `score.basis`, `overall_posture`, and the user-supplied
  capture filename) into an HTML string with **no escaping**, before saving it as a
  downloadable `.html` file.
- **Impact:** if an analyst uploads a PCAP whose certificate/session data (attacker-
  controlled, since it comes off the wire) contains such a payload, and the "Download HTML"
  click falls through to this client-side path (API report fetch fails, or the app is
  running against local fixtures with no backend), the resulting downloaded file would
  execute script when opened locally — the exact class of payload the backend was
  specifically hardened against with a hostile-fixture test.
  In the default path (backend reachable), the app uses the properly-escaped backend
  endpoint instead (confirmed live in §9), so this is a secondary/fallback-path issue, not
  the primary flow — but it is still a real regression from an established, explicitly
  tested security guarantee.
- **Recommendation / fix applied:** added an `escapeHtml()` helper (`&`, `<`, `>`, `"`, `'`)
  and applied it to `group.title`, `group.severity`, `item.recommended_action`,
  `doc.score?.band`, `doc.overall_posture`, `doc.score?.basis`, and `captureName` before
  interpolation. Verified the backend's exact `HOSTILE` payload string is neutralized
  identically to the backend's own `html.escape` behavior. Frontend rebuild and lint both
  pass clean after the fix.

No other security issues found.

## 16. Offline / Air-Gap Validation

No external AI APIs, telemetry, tracking, remote CDNs, or cloud auth calls found in
frontend source (see §15) or triggered during the live walkthrough (all network requests
observed went to `localhost:5173` → proxied `127.0.0.1:8001`, nothing external). The demo
workflow as audited requires no internet access.

## 17. Documentation Consistency

- `docs/releases/*` (handoff, manifest, final report) all anchor to `frontend-v1.0.1`
  (`7bc27ad`) and do not yet describe the landing page, page-transition, or
  `reportDownload.ts` fallback added in `9ac6e40`. Minor staleness, non-blocking — these
  docs describe the state one commit behind current HEAD.
- `docs/sih-pitch-deck/*` claims "1219 tests, 0 failures, 0 skips" in ~15 files. Current
  verified count is 1233 passed, 0 failed, 0 skipped (see §7) — the claim is stale but
  directionally still true (more tests, same zero-failure/zero-skip property). Non-blocking;
  worth a numeric refresh before judge-facing use.
- `TECH-DEBT.md` item 16 ("Chrome Profile Committed to Git") is marked OPEN but
  `frontend/.chrome-profile/` is no longer tracked in git — doc is stale, item appears
  already resolved. Non-blocking.
- `README.md`'s "`main` is deliberately frozen" explanation is accurate and matches the
  actual branch topology verified in §3 — no correction needed.

No documentation rewrites were performed; these are flagged, not fixed, per the audit's
scope (only the proven security regression in §15 was fixed).

## 18. Claim Firewall

| Claim | Evidence | Verified? | Source | Safe to say? |
|---|---|---|---|---|
| Passive PCAP analysis, no packet injection | TShark invoked read-only, subprocess array args | YES | §15, `tshark.py` | YES |
| 1219/1233 automated tests, 0 failures | Live pytest run this session | YES (1233 current) | §7 | YES, with refreshed number |
| Golden Case A: 44/100 CRITICAL, RSA-1024/SHA-1, frame 6 | Live run + live UI screenshot | YES | §10 | YES |
| Golden Case B: 22.15/100 CRITICAL, cross-session | Live run + provenance counts | YES | §11 | YES |
| Golden Case C: 100/100 STRONG, cert NOT_OBSERVABLE (TLS 1.3) | Live run + limitations text | YES | §12 | YES |
| AI-off/AI-on equivalence | Live run, identical scores | YES | §13 | YES |
| Offline/air-gapped operation | No external calls found/observed | YES | §16 | YES |
| Reports contain no scripts/external refs | Generated + inspected HTML | YES | §14 | YES |
| Cross-session reasoning "solves" STARTTLS stripping universally | Not claimed anywhere audited | N/A | — | Correctly NOT claimed (Rule 10 respected) |
| AI is the primary security engine | Not claimed; no new AI copy in audited commit | YES | §5, §13 | Correctly NOT claimed (Rule 9 respected) |

No unsupported claims were found being newly introduced. No claims were corrected (none
needed correction beyond the two stale-doc notes in §17, which are informational, not
marketing claims).

## 19. Known Limitations

- `src/securemailscope/backend/db.py:105` — a single SQLite connection shared across
  threads (`check_same_thread=False`) with a write lock but unlocked reads. Documented as
  reproducible ("database disk image is malformed" under overlapping `/sessions` +
  `/reports` requests) in `TECH-DEBT.md` item 10, status "OPEN (mitigated)". Mitigated
  today only by the frontend serializing all requests
  (`frontend/src/api/client.ts`). This is a pre-existing, already-known, already-frozen
  backend limitation — not touched by this audit per Rule 5, and not introduced by the
  audited frontend commit. It is a real concurrency risk under load outside the
  frontend's request-serialization discipline (e.g. a second concurrent client, or a
  future API consumer that doesn't serialize).
- TLS 1.3 / resumed-session certificate data is inherently NOT_OBSERVABLE — a design
  limitation, correctly represented (§12), not a bug.
- No frontend automated test suite exists (no vitest/jest configured) — coverage for the
  UI layer relies on TypeScript strictness, lint, and manual/live verification.

## 20. Remaining Risks

- The SQLite concurrency issue in §19 is the single most significant technical risk in the
  system as currently frozen; it is out of scope to fix here (Rule 5) but should be the
  top item for the next backend-focused work session.
- Documentation staleness (§17) creates minor risk of an outdated number surfacing in a
  judge-facing artifact if not refreshed before the SIH demo.

## 21. Release Decision

**READY_FOR_BASELINE_FREEZE.**

Rationale: the only genuine defect found in this audit (§15, client-side report-HTML
escaping) has been fixed with a minimal, narrowly-scoped change and re-verified (rebuild +
lint clean, hostile payload neutralized identically to the backend's own escaping, live
"Download HTML" still confirmed routing through the real API in the default path). Backend
regression suite is 1233/1233 passed with 0 skips. Frontend build and lint are clean.
Live backend↔frontend integration was verified end-to-end with the real engine, not mocks
or fixtures. All three golden demo cases reproduce their previously validated
score/posture/evidence exactly. AI on/off equivalence holds. Reports are safe and valid in
all three formats. No unsupported claims, no vocabulary drift, no AI-claim inflation, no
cross-session overclaiming. Remaining items (§17, §19, §20) are documentation staleness and
an already-known, already-mitigated backend limitation — neither blocks a baseline tag.

## 22. Exact Commit/Tag Baseline

- Base commit audited: `9ac6e40` (`frontend/final-polish`, = `origin/frontend/final-polish`)
- Fix commit (this audit): one file, `frontend/src/utils/reportDownload.ts`
- New tag: `v0.7.0-sih-baseline`, created on `frontend/final-polish` after the fix commit,
  per the project's existing convention of tagging each phase's own branch (`main` stays
  frozen at phase 3 — see §3).

## 23. Reproduction Commands

```bash
# Backend regression (full dependency set)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,backend,test-backend,reporting-pdf,test-reporting]"  # or: PYTHONPATH=src, if editable install is unavailable
pip install pypdf scapy
PYTHONPATH=src python -m pytest tests/ -q

# Golden cases (no server needed)
bash demo/commands/run_scene.sh backup_weak_certificate
bash demo/commands/run_scene.sh deepdive_cross_session_control_endpoint
bash demo/commands/run_scene.sh scene_b_certificate_honesty
bash demo/commands/run_scene.sh scene_c_no_ai_equivalence
bash demo/commands/run_scene.sh scene_c_no_ai_equivalence --ai

# Frontend
cd frontend && npm ci && npm run build && npx oxlint

# Live integration
PYTHONPATH=src python3 -m securemailscope.backend --port 8001 &
cd frontend && npm run dev   # proxies /api/v1 -> 127.0.0.1:8001, serves on :5173
```
