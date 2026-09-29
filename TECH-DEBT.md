# Tech Debt

Status as of the end of Phase 2 (demo-ready). Resolved items stay listed so
the record of what was fabricated, and how it was removed, is kept.

## Open

### 4. Artifacts Endpoint — No UI (Priority: Low) — DEFERRED
GET /analyses/{id}/artifacts exists in the backend but has no frontend
representation. The Report tab now shows each rendition's SHA-256,
renderer and schema from /reports, which covers the demo; a full
integrity-verification view is a post-demo feature.

### 10. Backend SQLite Connection Shared Across Threads (Priority: Critical — Backend) — OPEN (mitigated)
src/securemailscope/backend/db.py:105 opens one sqlite3 connection with
check_same_thread=False and FastAPI calls it from a thread pool. Writes are
serialized by a lock; reads are not. Two overlapping requests (reproduced
with /sessions + /reports in parallel) raise "database disk image is
malformed" and can kill the process. The database file itself passes
PRAGMA quick_check. A `while true` shell loop from a previous session
(PID 41464) restarts the backend, so the failure looked like random 502s.
Frontend mitigation (applied): frontend/src/api/client.ts serializes all
requests. With it, the final QA pass (4 runs x 7 tabs, plus the demo
journey) produced zero API failures. Real fix (backend, frozen): one
connection per thread, or a lock around every cursor.

### 16. Chrome Profile Committed to Git (Priority: Medium — Hygiene) — OPEN
frontend/.chrome-profile/ (browser profile caches and lock files) was
committed in d328093. Not ignored. Untrack with
`git rm -r --cached frontend/.chrome-profile` and add it to .gitignore.
Not done automatically: it rewrites what the repository tracks.

### 20. Two Non-Component Files Over 300 Lines (Priority: Low) — OPEN
src/context/InvestigationContext.tsx (about 600 lines) and
src/api/types.ts (about 530 lines). Every view component is under 300.
The context would split cleanly into run-list, investigation and UI-state
providers; not done before the demo because every tab depends on it.

## Resolved

### 1. Offline Font Loading (Priority: High) — RESOLVED
Phase 2B-0: IBM Plex Sans and Mono are self-hosted via @fontsource
(imported in src/main.tsx); the four Google Fonts links were removed from
index.html. No request leaves the machine for fonts.

### 2. Off-Scale Type Sizes (Priority: Medium) — RESOLVED
Phase 2C: every use of 10/11/15/17 px moved to --ds-text-12 or larger and
the four off-scale tokens were deleted. theme.css now defines exactly the
DESIGN.md 2.2 scale: 12/13/14/16/20/24/32. --ds-text-16 was missing and
has been added.

### 3. Hardcoded Spacing Values (Priority: Medium) — RESOLVED
Phase 2B/2C: all component spacing uses --ds-space-* tokens (inline styles
and components.css). Remaining literal pixels are deliberate sub-scale
optical adjustments, not layout spacing: badge padding (1px 6px), the
1-2px baseline nudges on timeline step metadata and the offline-banner
icon, the tab underline overlap (-1px), and the visually-hidden utility.
Hardcoded colours in TSX: zero. In CSS outside theme.css: zero (the modal
scrim became --ds-scrim). The 135 backwards-compatibility aliases
(--color-*, --sev-*, --ink-*, ...) had no remaining consumers and were
deleted, along with DirectionS.css (462 lines, no remaining consumers).

### 5. ProvenanceGraph Null Certainty (Priority: High — Forensic Integrity) — RESOLVED
Phase 2A-3: the `|| 'CONFIRMED'` fallback is gone. CertaintyBadge renders
the backend value or a muted "—"; the Provenance chain explains certainty
only from the evidence refs the assessment actually cites.

### 6. CoverageLanes Hardcoded Data (Priority: Critical — Forensic Integrity) — RESOLVED
Phase 2A-4: lanes come from dashboard.coverage only; an explicit empty
state renders when the backend returns none.

### 7. InvestigationOverview Severity Collapse (Priority: Critical — Forensic Integrity) — RESOLVED
Phase 2A-5 and the 2B Summary rebuild: every finding uses its own
--ds-sev-* tokens; a missing severity renders "—", never HIGH. MEDIUM was
moved to yellow in 2B-0 so HIGH and MEDIUM are distinct on the dark theme.

### 8. EvidenceLedger Vocabulary Collapse (Priority: High — Forensic Integrity) — RESOLVED
Phase 2A-6: UNKNOWN and NOT_OBSERVABLE are counted and filtered
separately, each with its own token and border style.

### 9. HomeView Posture Band Collapse (Priority: High — Forensic Integrity) — RESOLVED
Phase 2B C9: Home was rebuilt. Recent analyses show the run's own
overall_posture through PosturePill (all five bands distinct) and
score_value, or "—". The fabricated 44.0 / 100.0 scores are gone. Only
completed runs are listed (they are the only ones with a dashboard); the
number of runs that did not complete is stated under the list.

### 11. ProvenanceGraph Fabricated Fallbacks (Priority: High — Forensic Integrity) — RESOLVED
Frame #1, a NIST SP 800-52r2 citation, a -28.0 penalty, severity HIGH,
artifact names chosen by issue class and a first-session fallback. Each
node now shows backend values or is omitted (Phase 2A-3B), and the 2B
rebuild traces capture → stream → evidence → rules → finding → standards →
posture impact from /assessment and /dashboard.

### 12. Design-Lab Mockups in Production (Priority: Critical — Forensic Integrity) — RESOLVED
ProvenanceGraphSvg, CrossSessionMatrix and ProtocolLadderSvg rendered one
demo scenario for every capture. All three and the hidden ?design-lab
route were deleted in Phase 2A-8.

### 13. EvidenceLedger Frontend-Decided Evidence States (Priority: Critical — Forensic Integrity) — RESOLVED
Defaults to OBSERVED, invalid NOT_APPLICABLE states, computed certificate
rows, hardcoded proof frames and "FS=True" when the backend said false.
The ledger renders backend EvidenceField values directly (Phase 2A-6).

### 14. InvestigationOverview Scripted Content (Priority: Critical — Forensic Integrity) — RESOLVED
Filename-chosen determination, protocol label and score, a hardcoded
"Frame #6 · SMTPS :465" proof line, "-28 points" on every card and an
"active downgrade" claim. Replaced by the 2B Summary, built from
dashboard.posture, dashboard.findings and dashboard.coverage only.

### 15. CrossSessionWorkspace Scripted Content (Priority: Critical — Forensic Integrity) — RESOLVED
Subject/control chosen by IP and stream-id thresholds from one demo
capture. Replaced in 2B by engine deviation determinations from
/assessment and a session matrix built from /sessions.

### 17. Report Preview Injected Backend HTML (Priority: High — Security) — RESOLVED
ReportExperience rendered the backend HTML report in an unsandboxed
iframe via srcDoc. Phase 2B C8 renders the preview natively from the JSON
rendition; the HTML/PDF/JSON files remain available as downloads.

### 18. Fabricated Run Record and Premature Fixture Runs (Priority: High — Forensic Integrity) — RESOLVED
Found in 2B C9. InvestigationContext invented a run when the active run
was outside the 50-item list (source_filename = capture id or
"capture.pcap", created_at = now). It now fetches the real record from
GET /analyses/{id} and synthesises nothing. The run list also started as
fixture runs before the first fetch settled; `runsLoaded` now gates Home,
which shows a skeleton until the live list arrives.

### 19. Command Palette Mislabels and Severity Collapse (Priority: High — Forensic Integrity) — RESOLVED
Found in 2B shell restyle. Every stream without implicit TLS was badged
"STARTTLS" (including plaintext sessions that never upgraded), every
finding had the critical-red icon regardless of severity, and shortcut
badges contradicted the real keymap. Streams now state implicit TLS only
when the session record says so, findings use their own severity dot,
and hints mirror the keyboard handler.

### 21. Null Session Endpoints Rendered as "null" (Priority: Medium — Correctness) — RESOLVED
Found in 2C empty-state audit. The API returns protocol, ip and port as
null when the dissector cannot attribute a stream (e.g. the STRONG
starttls_basic run); labels rendered "null → null:null null". The types
now say so, and every label goes through utils/session.ts, which says
"not recorded" / "not identified". Duplicate React keys on unmapped
citations (standard UNMAPPED, null section) were fixed at the same time.

### 22. Muted and Faint Ink Below WCAG AA (Priority: Medium — Accessibility) — RESOLVED
Found in 2C. --ds-ink-faint (2.4:1) was used for section labels, tab-key
hints and the upload formats line; --ds-ink-muted was 4.36:1 on elevated
surfaces. Labels moved to muted, muted lightened to #8391a4 (4.97:1 on
the darkest-contrast surface), and faint is now reserved for icons, rules
and separators.
