# SecureMailScope — Final System Validation

## 1. Executive Summary

Full end-to-end validation of the `v0.7.0-sih-baseline` system (commit `8110dbd`):
backend regression, frontend build, live backend↔frontend integration with the real
engine, all three golden cases, cross-session positive/negative adversarial cases,
evidence-state and cryptographic validation, AI on/off, all three report formats,
security regression (including re-testing the exact hostile payload from the prior
XSS fix), offline behavior, performance/repeatability, responsive QA at 5
breakpoints, and a first-time-operator walkthrough.

One genuine defect was found and fixed: the Cross-Session tab rendered a fabricated
"Divergent" comparison against a literal `not recorded` control when no real
control population existed, instead of the honest abstention the backend already
computes. This directly touches the project's core "does not overstate what
cross-session reasoning proves" claim, so it was treated as a demo blocker (P1) and
fixed with a 10-line, narrowly-scoped change, verified against both the broken case
and the two cases that must keep working unchanged.

No other defects above P2 were found. Backend is 1233/1233 passed, 0 skipped, both
before and after the fix. All three golden cases reproduce their documented values
exactly, live, through the real UI.

**Decision: READY_WITH_MINOR_NON_BLOCKING_ITEMS** — ready for demo production once
the fix on `phase/final-system-validation` is merged; two P2 documentation/UI items
remain, explicitly non-blocking.

## 2. Exact Tested Commit

- Base branch/tag tested: `frontend/final-polish` = `v0.7.0-sih-baseline` = `8110dbd66c7a7cec20f94950344efcb1dfc4a69f`
- Fix branch: `phase/final-system-validation`, one commit ahead: `cce4d32` (the cross-session fix)
- `v0.7.0-sih-baseline` itself was not modified; historical tags untouched.
- `phase/archify-integration` was not merged and is unrelated to this validation.

## 3. Environment

| Component | Version |
|---|---|
| OS | Darwin 27.0.0 (macOS, arm64) |
| Python (venv) | 3.9.6 |
| Node | v26.4.0 |
| npm | 11.17.0 |
| TShark | 4.6.8 |
| fastapi | 0.128.8 |
| pydantic | 2.13.5 |
| uvicorn | 0.39.0 |
| reportlab | 5.0.1 |
| pypdf | 6.19.0 |
| scapy | 2.7.0 |
| pytest | 8.4.2 |

Reproduce: `python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev,backend,test-backend,reporting-pdf,test-reporting]"` (or `PYTHONPATH=src` if editable install is unavailable, per pip version), `pip install pypdf scapy`.

## 4. Test Inventory

42 test files under `tests/`, 1233 collected test items. Categorized:

| Category | Representative files | Notes |
|---|---|---|
| A. Backend/API | `test_backend_api.py`, `test_backend_persistence.py`, `test_backend_pipeline.py`, `test_backend_sessions_api.py`, `test_backend_architecture.py` | includes path-traversal/hostile-filename tests |
| B. Analysis engine | `test_ingest_pipeline.py`, `test_tshark_adapter.py`, `test_session_reconstruction.py`, `test_phase11_crypto.py`, `test_phase11_rules.py`, `test_phase11_real_pcap.py`, `test_hardening_oq46_oq47.py` | shell-injection, malformed-capture coverage |
| C. Evidence | `test_evidence_states.py` | |
| D. Scoring/posture | `test_posture_engine.py`, `test_posture_fusion.py`, `test_posture_corpora.py`, `test_posture_adversarial.py` | |
| E. Cross-session | `test_cross_session.py`, `test_cross_session_adversarial.py` | |
| F. AI/ML | `test_ml_engine.py`, `test_ml_features.py`, `test_ml_adversarial.py`, `test_ml_dataset.py` | |
| G. Reporting | `test_reporting_projection.py`, `test_reporting_html.py`, `test_reporting_pdf.py`, `test_reporting_api.py` | includes the hostile-payload escaping suite |
| H. Security | `test_security_analysis.py`, `test_security_analysis_adversarial.py`, `test_dashboard_security.py`, `test_dashboard_security_matrix.py` | |
| I. Frontend | none | no vitest/jest configured; pre-existing, not a regression |
| J. Browser/integration | exercised manually this session via the built-in browser against the real backend; `test_dashboard_*` files cover the API/view-model layer the frontend consumes | |
| K. Demo/golden | `demo/commands/run_scene.sh`, `demo/expected/*.json`, `tests/golden/manifest.json` (sha256-pinned research captures) | |

Previous verified count (Phase-1 baseline audit, same commit): 1233 passed, 0
failed, 0 skipped. Unchanged.

## 5. Backend Results

```
1233 passed in 66.49s (0:01:06)
```
0 failed, 0 skipped, 0 errors. Measured before and after the fix (fix was
frontend-only; both runs identical).

## 6. Frontend Results

- `npm ci`: clean, 0 vulnerabilities
- `npm run build` (`tsc -b && vite build`): exit 0, no TypeScript errors, both
  before and after the fix
- `npx oxlint`: exit 0, 7 pre-existing style warnings (no errors), unchanged by
  the fix
- No broken imports, no missing assets found during the live walkthrough

## 7. Integration Results

Live walkthrough against the real backend (`PYTHONPATH=src python3 -m
securemailscope.backend --port 8001`) and real Vite dev server (proxying `/api/v1`
→ `127.0.0.1:8001`, per `frontend/vite.config.ts`), no mocks:

- Landing → ingestion transition → recent-checks list (real backend data,
  "Engine Live" indicator correct) → Overview → Findings → Protocol → Certificates
  → Cross-Session → Provenance → Report, for three different captures.
- Zero console errors across the full walkthrough.
- All observed network requests went to `localhost:5173` (proxied to
  `127.0.0.1:8001`) — no external domains.
- No fake/hardcoded placeholder values observed; every screen traced to real
  backend data.

## 8. Case A

Input: `demo/captures/backup_weak_certificate.pcap`.

- Score/posture: **44.0 / CRITICAL** — matches exactly, verified live in the UI.
- Evidence: `PUBLIC_KEY RSA 1024-bit · OBSERVED`, `SIGNATURE_ALGORITHM SHA-1 ·
  OBSERVED`, **Frame #6**, Stream #0 — matches exactly.
- Findings/Certificates/Provenance/Report tabs all verified live, correct.
- Repeatability: 5 repeated runs, identical score and posture every time
  (deterministic). Steady-state timing 117.8–134.5ms (first/cold run 391.2ms,
  explained by process/interpreter warmup) — within the documented 115–320ms
  claim.

## 9. Case B

Input: `demo/captures/deepdive_cross_session_control_endpoint.pcap`.

- Score/posture: **22.15 / CRITICAL** — matches exactly, verified live in the UI.
- Cross-session: Subject `10.0.0.6` vs Control `10.0.0.7`, dimensions STARTTLS/
  TLS/AUTH all genuinely Divergent (real data on both sides), rule
  `CS-STARTTLS-001`, certainty **MEDIUM**, classified **SUSPICIOUS DEVIATION** (not
  CONFIRMED/CRITICAL).
- UI does not overstate what cross-session reasoning proves — verified verbatim:
  *"This client's own history is self-consistent... It is not proof that the
  capability was removed in transit — client-specific server policy produces the
  same observation — and no actor is identified."* Cites RFC 3207 §6.
- Unaffected by the Cross-Session fix (re-verified after the fix, identical).

## 10. Case C

Input: `demo/captures/scene_b_certificate_honesty.pcap` (TLS 1.3).

- Score/posture: **100.0 / STRONG**, "No deductions applied," verified live.
- Certificates tab: **"CERTIFICATE CONTENT: NOT OBSERVABLE,"** cites RFC 8446,
  explains why ("TLS 1.3 encrypts the certificate. This passive capture cannot
  read the X.509 payload."), explicitly separates OBSERVABLE vs NOT OBSERVABLE
  facts, and includes a "Why this is not a missing certificate" clarification.
- No penalty applied for unavailable passive evidence — confirmed.

## 11. Cross-Session Validation

- **Positive case** (Case B, §9): real control population exists, genuine
  divergence found, MEDIUM/SUSPICIOUS DEVIATION framing, explicit denial of
  attacker attribution. Correct, unaffected by the fix.
- **Negative case** (`deepdive_cross_session_no_control.pcap`, 6 sessions, one
  client only): backend correctly abstains — `provenance.source_counts` shows 11
  raw cross-session engine results but 0 penalising cross-session findings
  surfaced; the only 2 issue groups are deterministic (`PLAINTEXT_AUTH_EXPOSURE`,
  `NO_TLS_PROTECTION`). **Before the fix**, the frontend nonetheless showed a
  fabricated "Divergent" verdict on all 3 dimensions against a literal
  `not recorded` control, with no abstention explanation — a real overstatement of
  certainty. **After the fix**, it shows an honest "No control endpoint observed"
  state. See §22/§23.
- **Insufficient history**: `DEFAULT_MIN_HISTORY = 5`, confirmed in
  `src/securemailscope/crosssession/baseline.py:32`, documented as "a chosen
  parameter, not a derived one" (docs/research/02A §5, cited in the source
  docstring). `BaselineStatus` enum (`ESTABLISHED`, `INSUFFICIENT_HISTORY`,
  `NOT_APPLICABLE`) confirmed in the same file.
- "Comparable" defined precisely in `src/securemailscope/crosssession/
  comparability.py`: same client + server_ip/port/protocol/implicit-TLS mode for
  the client-scoped baseline; same server, different client for the
  server-scoped control population. Implicit and explicit TLS are never pooled.

## 12. Evidence Validation

Canonical `EvidenceState` confirmed unchanged at
`src/securemailscope/evidence/states.py:22`: `OBSERVED`, `INFERRED`, `UNKNOWN`,
`AMBIGUOUS`, `INCOMPLETE`, `NOT_OBSERVABLE`. Verified live in the UI across all
three cases (e.g. "RSA 1024-bit · OBSERVED", "CERTIFICATE CONTENT: NOT
OBSERVABLE"). `BaselineStatus` (`NOT_APPLICABLE` included) and `FindingStatus`
(`INSUFFICIENT_EVIDENCE` included) are separate, correctly-scoped enums per
source; no vocabulary mixing found. Missing evidence never improves posture:
Case C's NOT_OBSERVABLE certificate content applies **zero** penalty (it is a
non-comparable dimension, not a compliance credit).

## 13. Cryptographic Validation

Verified live via Case A/C: TLS version negotiation, cipher suite/key-exchange
metadata, certificate key size (RSA 1024-bit) and signature algorithm (SHA-1)
extraction, STARTTLS deviation detection (Case B), and the TLS 1.3 certificate
observability limitation (Case C) all function correctly end-to-end with correct
evidence-state labeling. No passive trust/revocation validation is claimed
anywhere observed in this session (Certificates tab explicitly lists "Local trust
store validation and revocation status (OCSP/CRL)" under NOT OBSERVABLE FROM
CAPTURE).

## 14. AI Validation

- AI disabled: 88.0 / ADEQUATE (`scene_c_no_ai_equivalence.pcap`)
- AI enabled: 88.0 / ADEQUATE — identical
- Equivalence: confirmed, re-run this session
- No model retraining, no model changes, no new AI claims introduced or found in
  this session's diff.

## 15. Report Validation

Generated for Case A via the same code path the API endpoints use
(`reporting.html.render`, `reporting.pdf.render`):

- JSON: 27,230 bytes, valid
- HTML: 22,781 bytes, no `<script>` tag, no external `http(s)://` references
- PDF: 18,647 bytes, 7 pages, parses correctly with `pypdf`

Downloadable reports verified through the real frontend: "Download HTML" routed
through the real API endpoint (`GET /api/v1/analyses/{id}/reports/html?
download=true` → 200), not the client-side fallback.

## 16. Security Validation

- Re-tested the exact hostile payload from the prior XSS fix
  (`<script>alert(1)</script><img src=x onerror=alert(1)>`) against the frontend's
  `escapeHtml()` (still intact in `frontend/src/utils/reportDownload.ts`) — fully
  neutralized. All 10 backend hostile-payload regression tests
  (`tests/test_reporting_html.py`) pass.
- Path traversal / hostile filename: `test_hostile_filename_never_reaches_disk`
  passes; `../../../../etc/passwd`-style payloads are treated as labels, never
  paths (`test_backend_api.py`).
- Shell injection, malformed-capture, oversized-input hardening: 75 tests across
  `test_tshark_adapter.py`, `test_capture_hash.py`, `test_hardening_oq46_oq47.py`,
  `test_security_analysis_adversarial.py` — all pass.
- Frontend sweep: 0 matches for `dangerouslySetInnerHTML`, `eval`/`new Function`,
  or external `fetch()` targets.
- External network calls: none from the backend runtime (`grep` for
  `requests.`/`httpx.`/`urllib.request`/`http.client` in `src/` returns nothing);
  the live browser session showed zero requests to any non-`localhost` origin.
- Secrets exposure: none found or requested anywhere this session.

## 17. Offline Validation

SecureMailScope's runtime (backend analysis pipeline, frontend, report
generation) makes zero external network calls — confirmed both by source
inspection and by live network-request logging during the full walkthrough.
(Distinct from Archify, the optional developer-tooling skill evaluated in Phase
2, which makes one small disclosed/disableable version-check call unrelated to
the product — see `docs/releases/ARCHIFY-INTEGRATION-REPORT.md`.)

## 18. Performance/Repeatability

5 repeated runs of Case A: identical score (44.0) and posture (CRITICAL) every
time — fully deterministic. Steady-state elapsed time 117.8–134.5ms per capture
(first/cold run 391.2ms, attributable to process/interpreter warmup, not
representative of steady-state operation). This is within the documented
"115–320ms per capture" range. No scalability claim was tested or is made beyond
this measurement.

## 19. Responsive QA

| Breakpoint | Result |
|---|---|
| 1600×1000 | Clean |
| 1440×900 | Clean |
| 1280×800 | Clean |
| 768×1024 (tablet) | Clean — nav correctly reflows to a horizontal top bar |
| 375×812 (mobile) | **Defect found** (see §22, P2): the shared header's "Engine Live" badge visually overlaps the posture pill ("STRONG"), and the score value is clipped by the "+ Intake" button. Reproduced identically on both Overview and Report tabs, confirming it is isolated to the shared `Header` component. Page content below the header reflows correctly at all breakpoints tested. |

## 20. Operator Test

Walked the documented flow as a first-time operator would, using only what the
repository documents:

1. README's top-level "Backend (Phase 8)" section documents
   `PYTHONPATH=src python3 -m securemailscope.backend --port 8000` — a
   self-contained example for testing the API via `curl`, not tied to the
   frontend.
2. README's "Forensic Workstation Frontend" section correctly signposts
   `docs/releases/SECUREMAILSCOPE-FRONTEND-HANDOFF.md`, labeled **"Frontend
   engineering team handoff & running guide."**
3. That handoff doc correctly documents port **8001** (`PYTHONPATH=src python3 -m
   securemailscope.backend --host 127.0.0.1 --port 8001`), matching
   `frontend/vite.config.ts`'s dev proxy target exactly. Following it works
   correctly end-to-end (confirmed live this session).
4. **Friction point** (P2, see §22): an operator who reads only the top-level
   "Backend (Phase 8)" section and starts the frontend dev server without
   following the signposted handoff doc will start the backend on the wrong port
   (8000 instead of 8001). The frontend does not error loudly — it silently falls
   back to bundled fixture data and shows a "Demo Fixture" badge instead of
   "Engine Live." This is discoverable (the badge is visible, and console logs a
   clear `"Backend unavailable, using authentic offline PCAP fixtures"` warning)
   but not obvious to someone not looking for it.
5. Once on the correct port, the Case A → finding → evidence → provenance →
   report flow (§7–§10) was smooth with no further confusion points.

## 21. Claim Audit

| Claim | Implementation evidence | Test evidence | Safe? |
|---|---|---|---|
| Passive PCAP analysis, no packet injection | TShark invoked read-only, argument-array subprocess calls | `test_no_shell_injection_via_filename` | YES |
| 1233 automated tests, 0 failures, 0 skips | Live pytest run, this session | §5 | YES (supersedes the older "1219" figure — see §22 P3) |
| Golden Case A: 44/100 CRITICAL, RSA-1024/SHA-1, frame 6 | Live run + live UI | §8 | YES |
| Golden Case B: 22.15/100 CRITICAL, cross-session | Live run + provenance counts | §9, §11 | YES |
| Golden Case C: 100/100 STRONG, cert NOT_OBSERVABLE (TLS 1.3) | Live run + limitations text | §10 | YES |
| AI-off/AI-on equivalence | Live run, identical scores | §14 | YES |
| Cross-session reasoning does not overstate certainty | Positive case: MEDIUM/SUSPICIOUS DEVIATION with explicit non-attribution. Negative case: **was** overstated before the fix in this session; now honest. | §11, §22, §23 | YES, after the fix in §23 |
| Offline/air-gapped operation | No external calls found or observed | §17 | YES |
| Reports contain no scripts/external refs | Generated + inspected HTML | §15 | YES |
| TLS 1.3 hides certificate content | Verified live, correctly explained with RFC 8446 citation | §10, §13 | YES |
| No passive trust/revocation validation claimed | Explicitly listed as NOT OBSERVABLE in the UI | §13 | YES |
| AI is the primary security engine | Not claimed anywhere found this session | §14 | Correctly NOT claimed |
| Real-time / scalability | Not claimed, not tested beyond §18's single-capture timing | — | Correctly not overclaimed |

## 22. Defects

**P0 — release blocker:** none found.

**P1 — demo blocker:**
- **Location:** `frontend/src/components/workbench/crosssession/CrossSessionWorkspace.tsx` (pre-fix).
- **Reproduction:** open any capture with 2+ TCP sessions from a single client and
  zero cross-session findings surfaced (e.g.
  `demo/captures/deepdive_cross_session_no_control.pcap`) → Cross-Session tab.
- **Evidence:** backend `provenance.source_counts.cross_session_findings` internal
  count was 11, but 0 were penalising/surfaced; the UI nonetheless showed
  "Divergent" for all 3 dimensions against a literal `not recorded` control, with
  no abstention explanation (the honest caveat and Engine-determinations panel
  are both gated on `deviations.length > 0`, which was 0).
- **Impact:** directly contradicts the project's central "does not overstate what
  cross-session reasoning proves" claim, in a screen a judge could plausibly open
  during the live demo.
- **Recommended action / status:** fixed on `phase/final-system-validation`
  (commit `cce4d32`); see §23.

**P2 — important but non-blocking:**
- Responsive: shared `Header` component text overlap at 375px width (§19). Not
  fixed (UI polish, not a correctness/security issue; SIH demos run on
  desktop/laptop screens).
- Documentation: README's top-level "Backend (Phase 8)" quick-start example uses
  port 8000, while the frontend's dev proxy (and its own correctly-signposted
  handoff doc) uses port 8001 — an operator who skips the signposted handoff doc
  gets silent fixture-fallback, not a hard error (§20). Not fixed — the correct
  instructions already exist and are signposted; this is a discoverability gap,
  not a broken instruction.

**P3 — cosmetic/documentation:**
- `docs/sih-pitch-deck/*` (~15 files) still say "1219 tests" — the current
  verified count is 1233 (§21). Historically accurate at the time written; not
  mass-rewritten per the task's own instruction to distinguish historical from
  current results, not blanket-correct.

## 23. Fixes

One file changed, on `phase/final-system-validation` (commit `cce4d32`), separate
from this documentation commit:

- **File:** `frontend/src/components/workbench/crosssession/CrossSessionWorkspace.tsx`
- **Change:** added one branch — when 2+ sessions exist but `deviations.length ===
  0 && controlSessions.length === 0`, render an honest "No control endpoint
  observed" empty state instead of the fabricated comparison table.
- **Justification:** demonstrated P1 correctness/honesty regression (§22).
- **Post-fix regression:** `npm run build` (exit 0), `npx oxlint` (exit 0, no new
  warnings), full backend suite re-run (1233 passed, 0 failed — untouched by this
  frontend-only fix), Case A/B/C re-verified live and unchanged, the negative
  cross-session case now shows the honest empty state, the positive cross-session
  case (Case B) re-verified unaffected, AI on/off re-confirmed, hostile-payload
  security re-test re-confirmed, offline behavior re-confirmed.

## 24. Remaining Limitations

- Pre-existing, already-known, already-frozen backend SQLite concurrency issue
  (`TECH-DEBT.md` item 10) — not touched, out of scope for this validation (Rule
  4/backend freeze), mitigated today by the frontend serializing requests.
- No automated frontend test suite (no vitest/jest) — frontend correctness in
  this validation relies on TypeScript strictness, lint, and live manual/browser
  verification, not an automated regression suite.
- The two P2 items in §22 remain open by design (non-blocking, explicitly not
  fixed per the task's hardening policy).

## 25. Demo Readiness Decision

**READY_WITH_MINOR_NON_BLOCKING_ITEMS.**

The one demonstrated demo-blocking defect (cross-session honesty overstatement,
P1) has been fixed, verified, and isolated on `phase/final-system-validation`
without touching the immutable `v0.7.0-sih-baseline` tag or any other release tag.
Backend is 1233/1233 passed both before and after the fix. All three golden cases
reproduce their documented values exactly, live, through the real engine and real
UI. Cross-session reasoning correctly distinguishes its positive case (genuine,
bounded, non-attributing divergence) from its negative case (honest abstention,
after the fix) from insufficient-history behavior (documented, source-confirmed).
Evidence-state vocabulary, cryptographic analysis, AI boundedness, report safety,
security hardening (including a direct re-test of the prior XSS fix), and offline
operation all hold. Two P2 items remain — a cosmetic header-overlap bug at phone
width and a documentation discoverability gap for the backend port — both
explicitly non-blocking for a desktop/laptop live demo and left unfixed per the
task's hardening policy.

## 26. Exact Reproduction Commands

```bash
# Verify starting state
git rev-parse v0.7.0-sih-baseline^{}   # 8110dbd66c7a7cec20f94950344efcb1dfc4a69f
git checkout phase/final-system-validation

# Backend regression
source .venv/bin/activate
PYTHONPATH=src python -m pytest tests/ -q

# Frontend
cd frontend && npm ci && npm run build && npx oxlint

# Real backend + frontend (correct port — see §20 for the documented pitfall)
PYTHONPATH=src python3 -m securemailscope.backend --host 127.0.0.1 --port 8001 &
cd frontend && npm run dev   # proxies /api/v1 -> 127.0.0.1:8001, serves on :5173

# Golden cases
bash demo/commands/run_scene.sh backup_weak_certificate
bash demo/commands/run_scene.sh deepdive_cross_session_control_endpoint
bash demo/commands/run_scene.sh deepdive_cross_session_no_control
bash demo/commands/run_scene.sh scene_b_certificate_honesty
bash demo/commands/run_scene.sh scene_c_no_ai_equivalence
bash demo/commands/run_scene.sh scene_c_no_ai_equivalence --ai

# Security re-test
PYTHONPATH=src python -m pytest tests/test_reporting_html.py -k hostile -v
PYTHONPATH=src python -m pytest tests/test_backend_api.py -k "traversal or filename" -v
```
