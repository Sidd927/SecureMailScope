# SecureMailScope — Final Engineering Freeze

## 1. Final Tag

`v0.7.1-sih-final` (annotated)

## 2. Final Commit

`381bba48e7b117f75adaf2457aa16c24099e73be`

Tag dereference verified: `git rev-parse v0.7.1-sih-final^{}` == `381bba4...` == `git rev-parse HEAD` on `frontend/final-polish` at tag time.

## 3. Baseline Ancestry

```
v0.7.1-sih-final (381bba4)          — merge commit, THIS freeze
├── phase/final-system-validation (931ea0a and 4 commits below it)
│   ├── 931ea0a docs(pitch-deck): update the current test count (1219 -> 1234)
│   ├── feaee96 docs(runbook): remove startup ambiguity and fix stale release references
│   ├── 9523bf6 test(cross-session): add the missing control-present-no-deviation case
│   ├── 03d1d08 fix(header): stop the Engine-Live/posture-pill overlap at phone width
│   ├── 9a1b709 docs(release): final system validation and demo readiness audit
│   └── cce4d32 fix(cross-session): stop showing a fabricated Divergent comparison with no control
└── v0.7.0-sih-baseline (8110dbd)   — chore(release): establish post-frontend release baseline
    └── 9ac6e40 feat: finalize frontend polish and theme updates
        └── ... (frontend-v1.0.1, frontend-v1.0.0, phase 1-12 engine history)
```

`v0.7.0-sih-baseline` and every earlier tag (`frontend-v1.0.0`, `frontend-v1.0.1`, `v0.1.0-phase1` through `v0.6.0-phase11`) remain exactly where they were — none moved, deleted, or recreated.

## 4. Environment

| Component | Version |
|---|---|
| OS | Darwin 27.0.0 (macOS, arm64) |
| Python (venv) | 3.9.6 |
| Node | v26.4.0 |
| npm | 11.17.0 |
| TShark | 4.6.8 |
| fastapi / pydantic / uvicorn | 0.128.8 / 2.13.5 / 0.39.0 |
| reportlab / pypdf / scapy | 5.0.1 / 6.19.0 / 2.7.0 |
| pytest | 8.4.2 |

## 5. Full Test Results

Backend, run three times across this freeze (pre-merge, post-merge, and as part of live golden-case regression), identical every time:

```
1234 passed, 0 failed, 0 skipped (~65s)
```

(1233 from the `v0.7.0-sih-baseline` audit + 1 new test —
`test_control_present_and_consistent_yields_no_deviation` — added this phase.)

Frontend: `npm run build` exit 0 (no TypeScript errors), `npx oxlint` exit 0 (7 pre-existing style warnings, no errors). Both checked pre-merge and post-merge.

## 6. Golden Case Results

Re-run live, through the real engine, on the merged `frontend/final-polish` branch:

| Case | Capture | Score | Posture |
|---|---|---|---|
| A | `backup_weak_certificate.pcap` | 44.0 | CRITICAL |
| B | `deepdive_cross_session_control_endpoint.pcap` | 22.15 | CRITICAL |
| C | `scene_b_certificate_honesty.pcap` | 100.0 | STRONG |
| Negative cross-session | `deepdive_cross_session_no_control.pcap` | 34.15 | CRITICAL |

All match the values established at `v0.7.0-sih-baseline` exactly — unchanged by anything in this freeze.

## 7. Security Results

- Hostile-payload regression: all 10 tests in `tests/test_reporting_html.py -k hostile` pass; the frontend's `escapeHtml()` (in `frontend/src/utils/reportDownload.ts`) re-verified against the exact prior payload (`<script>alert(1)</script><img src=x onerror=alert(1)>`) — neutralized.
- Path traversal / hostile filename: `test_hostile_filename_never_reaches_disk` passes.
- No `dangerouslySetInnerHTML`, `eval`, or `new Function` anywhere in frontend source.
- No external network calls in `src/securemailscope/` (`requests.`/`httpx.`/`urllib.request`/`http.client` — zero matches).
- No secrets, credentials, `.env` files, or key material found tracked in git.

## 8. Responsive Results

| Breakpoint | Result |
|---|---|
| 1600×1000 | Clean |
| 1440×900 | Clean |
| 1280×800 | Clean |
| 768×1024 | Clean |
| 375×812 | **Fixed this phase** — header no longer overlaps; verified on Overview, Findings, Report, and Cross-Session tabs, with both "STRONG" and "CRITICAL" posture text (the longer word is the harder case), and on the merged branch post-merge |

No horizontal overflow observed at any breakpoint.

## 9. Cross-Session Results

- **Positive** (`deepdive_cross_session_control_endpoint.pcap`): real control population (client `10.0.0.7`), genuine divergence, bounded `MEDIUM`/`SUSPICIOUS DEVIATION`, explicit "no actor is identified" — unaffected by this phase's changes, re-verified on the merged branch.
- **Negative — no control** (`deepdive_cross_session_no_control.pcap`): single client, no control population. **Fixed this phase**: previously showed a fabricated "Divergent" verdict against a `not recorded` placeholder; now shows an honest "No control endpoint observed" state. Re-verified on the merged branch, both desktop and 375px.
- **Negative — control present, no deviation**: no existing fixture (real capture or synthetic) covered this exact combination. Added `test_control_present_and_consistent_yields_no_deviation` to `tests/test_cross_session.py`, using the file's existing `mk()`/`run()` helpers — no production code changed. Passed on first run, confirming the engine already handles it correctly.
- **Insufficient history**: `DEFAULT_MIN_HISTORY = 5`, confirmed at `src/securemailscope/crosssession/baseline.py:32`, documented in source as "a chosen parameter, not a derived one." `BaselineStatus.INSUFFICIENT_HISTORY` and `.NOT_APPLICABLE` confirmed in the same file.

## 10. AI Results

`scene_c_no_ai_equivalence.pcap`: 88.0/ADEQUATE with AI disabled and with AI enabled — identical, re-confirmed at `v0.7.0-sih-baseline` in Phase 3. Not touched by this freeze (Rule 1: no feature development, no model changes).

## 11. Report Validation

JSON (27,230 bytes), HTML (22,781 bytes, no `<script>`, no external refs), PDF (18,649 bytes, 7 pages, parses with `pypdf`) — generated for Case A via the real `reporting.html.render`/`reporting.pdf.render` code path, unchanged by this freeze, re-verified post-merge.

## 12. Operator Reproduction

Followed the corrected `README.md` "Run the full demo" section and `demo/RUNBOOK.md` "Before the room" steps exactly as written (both fixed in this phase):

1. `git checkout v0.7.1-sih-final` (this freeze; `v0.7.0-sih-baseline` also still works for the pre-freeze state).
2. `tshark --version` → 4.6.8.
3. Install backend extras.
4. `PYTHONPATH=src python3 -m pytest -q` → `1234 passed`, matching the documented expectation exactly.
5. Terminal 1: `PYTHONPATH=src python3 -m securemailscope.backend --host 127.0.0.1 --port 8001`. Terminal 2: `cd frontend && npm ci && npm run dev`. Opened `http://localhost:5173` → header showed **Engine Live**.
6. Ran Case A, Case B, Case C live through the UI; opened a report and downloaded HTML.

No friction points remained from the two documentation defects Phase 3 found (stale release tag, ambiguous port). This closes that finding.

## 13. Known Limitations

- Pre-existing, already-known, already-frozen backend SQLite concurrency issue (`TECH-DEBT.md` item 10) — out of scope for this freeze (Rule 1: no feature development, no architecture changes), mitigated by the frontend serializing requests.
- No automated frontend test suite (no vitest/jest configured) — frontend correctness relies on TypeScript strictness, lint, and live manual/browser verification.
- `frontend/public/test_caps/` (`backup_weak_certificate.pcap`, `cross_session.b64`, `weak_cert.b64`) is tracked, unreferenced by any current frontend source (`grep` for `test_caps` in `frontend/src` returns nothing), and predates this entire validation effort (committed in `c55f9fb`, part of the original frontend rebuild, already present at `v0.7.0-sih-baseline`). Confirmed benign (base64-encoded packet bytes, not credentials). Found during this freeze's clean-tree check; left in place — it doesn't fit any of this phase's five authorized fix categories (mobile bug, cross-session honesty, startup/runbook ambiguity, current documentation, release documentation) and isn't a functional or security defect. Flagged here for a future cleanup pass, not fixed now.
- Two items already closed this phase, listed for completeness: the mobile header overlap (§8) and the cross-session honesty gap (§9) — both fixed and verified, not remaining limitations.

## 14. Historical Tags

Untouched, verified via `git tag --list` and individual `git rev-parse <tag>^{}` checks: `frontend-v1.0.0`, `frontend-v1.0.1`, `v0.1.0-phase1`, `v0.2.0-phase7`, `v0.3.0-phase8`, `v0.4.0-phase9`, `v0.5.0-phase10`, `v0.6.0-phase11`, `v0.7.0-sih-baseline`.

## 15. Archify Status

**OPTIONAL DEVELOPER TOOL.** Lives on `phase/archify-integration` (commit `0c4dd06`), evaluated and documented in `docs/releases/ARCHIFY-INTEGRATION-REPORT.md`. **Confirmed NOT merged into this baseline** — `git merge-base --is-ancestor phase/archify-integration frontend/final-polish` returns false; `frontend/final-polish`'s tree contains no Archify files.

## 16. Exact Startup Commands

```bash
git checkout v0.7.1-sih-final

# Terminal 1
PYTHONPATH=src python3 -m securemailscope.backend --host 127.0.0.1 --port 8001

# Terminal 2
cd frontend && npm ci && npm run dev
```

Open `http://localhost:5173`. Header must show **Engine Live**, not **Demo Fixture**.

## 17. Exact Demo Case Paths

- Case A: `demo/captures/backup_weak_certificate.pcap` → 44.0 / CRITICAL
- Case B: `demo/captures/deepdive_cross_session_control_endpoint.pcap` → 22.15 / CRITICAL
- Case C: `demo/captures/scene_b_certificate_honesty.pcap` → 100.0 / STRONG
- Negative cross-session: `demo/captures/deepdive_cross_session_no_control.pcap` → 34.15 / CRITICAL
- AI on/off: `demo/captures/scene_c_no_ai_equivalence.pcap` → 88.0 / ADEQUATE both ways
- Full presenter script: `demo/RUNBOOK.md` (corrected this phase)

## 18. Freeze Declaration

**Engineering is frozen for SIH demo/presentation preparation.**

Every item Phase 3 left open has been closed with evidence: the mobile header defect is fixed and verified at all five required breakpoints; the cross-session honesty gap is fixed and verified against both the case that must stay broken-looking-honest (no control) and the case that must keep showing a real signal (control present, deviation found); the missing test coverage is added and passes against the unmodified engine; the operator-facing startup ambiguity is resolved with an explicit, verified two-terminal recipe; current-facing documentation reflects the verified 1234-test suite. The merge into `frontend/final-polish` was itself tested, not assumed clean. `v0.7.0-sih-baseline` and every earlier tag remain exactly as they were. Archify remains separate, optional, and unmerged.

From here, treat `v0.7.1-sih-final` as the demo source of truth. Do not redesign, refactor, retrain, or add scope against it unless a genuine P0/P1 defect is discovered.

## 19. Reproduction Commands

```bash
# Verify the tag
git rev-parse v0.7.1-sih-final^{}   # 381bba48e7b117f75adaf2457aa16c24099e73be

# Backend
source .venv/bin/activate
PYTHONPATH=src python -m pytest tests/ -q   # 1234 passed

# Frontend
cd frontend && npm ci && npm run build && npx oxlint

# Golden cases (no server needed)
bash demo/commands/run_scene.sh backup_weak_certificate
bash demo/commands/run_scene.sh deepdive_cross_session_control_endpoint
bash demo/commands/run_scene.sh scene_b_certificate_honesty
bash demo/commands/run_scene.sh deepdive_cross_session_no_control

# Security re-test
PYTHONPATH=src python -m pytest tests/test_reporting_html.py -k hostile -v
PYTHONPATH=src python -m pytest tests/test_backend_api.py -k "traversal or filename" -v
```
