# UI design specification — analyst console

**Status: PROPOSED, awaiting approval before implementation.**
Derived from `UI-UX-RESEARCH.md` and the verified API contract (§2 below).

---

## 1. Constraint recap

- Backend, analysis engine, scoring, ML, evidence semantics: **frozen, untouched**.
- Static ES modules, no build step, no npm, no framework. **Keep this.**
- Fully offline: no web fonts, no CDN, no icon service.
- All API-derived text rendered via `textContent`, never markup.

## 2. Verified API contract (measured live, not assumed)

| Need | Endpoint | Verified |
|---|---|---|
| Upload a capture | `POST /api/v1/analyses`, `multipart/form-data`, field name **`file`** (or `capture`), query `?ai=`, `?force=`, `?formula=` | ✅ returns 201 with the full run record |
| Analysis is synchronous | response already `state: COMPLETED`, `duration_ms: 137` | ✅ no polling needed for a single upload |
| Real stage timings | `stages[]` → `ingest`, `sessions`, `analysis`, `crosssession`, `ml`, `posture` with real ms | ✅ **but ingest is ~136 of 137 ms; the other five are 0 ms** |
| History rows | `GET /analyses` → includes `overall_posture`, `score_value`, `source_filename`, `duration_ms`, `state`, `ai_enabled`, `created_at` | ✅ no per-row extra fetch needed |
| Overview / findings / evidence | `GET /analyses/{id}/dashboard` → 16 sections incl. `posture`, `coverage`, `protocols`, `findings`, `issue_groups`, `abstentions`, `standards`, `provenance`, `ml`, `limitations`, `filters`, `unavailable` | ✅ already rich |
| Per-finding provenance | finding carries `frames`, `frames_text`, `stream_key`, `tcp_stream_id`, `source_rule_ids`, `citations`, `limitations` | ✅ |
| Reports | `GET /analyses/{id}/reports` then `/reports/{html,pdf,json}` | ✅ |

**Conclusion: no backend change is required.** Every UI need is already served.

**Honesty note on stages:** because five of six stages measure 0 ms, the UI must **not** animate a
six-step progress sequence — that would imply duration the system does not spend. Stages are shown
as a completed pipeline summary with the total, not as a fake progress bar.

**Honesty note on synchrony:** the measured POST returned `COMPLETED` inline, but `JobState` still
has `QUEUED`/`RUNNING`/`FINALIZING`, and `max_concurrent_analyses = 1` means a second submission
*can* be non-terminal. So the UI branches on the returned `state`: terminal → navigate straight to
the run; non-terminal → land on history, which **already polls** (`test_polling_is_bounded_and_
stops_at_terminal_state`, `..._uses_a_single_chained_timer_not_an_interval`). That polling module
is reused as-is, not rewritten.

**Honesty note on the size hint:** `/health` publishes `limits.max_upload_bytes`, but the *real*
ceiling is `min(max_upload_bytes, config.max_capture_bytes)` (`limits.py:59`) and is not exposed.
The client-side size check is therefore **advisory and possibly looser** than the server's. The
server stays the authority; the UI never claims a file is acceptable, only that it is obviously
too large.

## 3. Information architecture

```
┌─ App shell (persistent) ────────────────────────────────┐
│  SecureMailScope            [ + New analysis ]  [About] │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ROUTE #/            → Home                              │
│      ├── empty       → Hero drop zone + what it does     │
│      └── populated   → Drop zone (compact) + history     │
│                                                          │
│  ROUTE #/run/{id}    → Analysis                          │
│      ├── Overview    (default)                           │
│      ├── Findings                                        │
│      └── Evidence & provenance                           │
└─────────────────────────────────────────────────────────┘
```

Four screens. No sidebar. Tabs only appear inside an analysis.

## 4. Screen specifications

### A. Home — first run (no analyses)

The screen the user complained about. Replaces `emptyPanel()` and its curl command.

```
┌──────────────────────────────────────────────────────────┐
│                    SecureMailScope                        │
│   Passive cryptographic posture assessment for email      │
│                                                           │
│   ┌───────────────────────────────────────────────────┐  │
│   │                  ⇪  (inline SVG)                   │  │
│   │         Drop a packet capture here                 │  │
│   │              or  [ Select a .pcap ]                │  │
│   │                                                    │  │
│   │   SMTP · IMAP · POP3 — including SMTPS/IMAPS/POP3S │  │
│   └───────────────────────────────────────────────────┘  │
│                                                           │
│   Runs locally · no server access · no keys · no          │
│   message content read                                    │
│                                                           │
│   ── What it does ──────────────────────────────────     │
│   Reconstructs sessions → assesses TLS, certificates,     │
│   forward secrecy → cites a published standard for        │
│   every finding → states what the capture cannot show     │
└──────────────────────────────────────────────────────────┘
```

Copy is positive ("Drop a packet capture here"), not an absence ("No analyses yet").
**No curl command anywhere in the UI.**

### B. Home — populated

Compact drop zone at top (still the primary action), then the history table:

| Capture | Posture | Score | State | Analysed | Duration | AI |
|---|---|---|---|---|---|---|

All fields verified present in the listing response. **Finding count and coverage are NOT in the
listing and will not be shown here** — they would require a fetch per row, and inventing them is
forbidden.

### C. Upload interaction states

`idle → dragover → selected → uploading → complete | error`

- **dragover**: dashed border becomes solid accent, background tints. Whole drop zone is the
  target (research: generous target).
- **selected**: filename + human-readable size + an explicit `[ Analyze capture ]` button.
  Submission is never automatic on drop — the user confirms.
- **uploading**: button disabled and relabelled, indeterminate progress bar. **Guarded against
  double-submit.**
- **error**: the API's own `error.code`/`message` rendered as text, with the file retained so the
  user can retry without re-selecting.

Client-side pre-checks (advisory only, the API remains the security boundary): extension hint
(`.pcap`/`.pcapng`) and size against the ceiling already published by `/health`
(`limits.max_upload_bytes`).

### D. Analysis — Overview

Answers "what did it find?" in 5–10 seconds.

```
Capture name                          [View HTML] [PDF] [JSON]
imap · analysed 18:13 · run 9cd35cbb…

┌──────────────────────┬──────────────────────────────────┐
│  POSTURE             │  EVIDENCE COVERAGE               │
│  STRONG              │  100.0%  (1 of 1 sessions)       │
│  100 / 100           │  OBSERVED 4 · NOT_OBSERVABLE 4   │
└──────────────────────┴──────────────────────────────────┘
  (if withheld: band replaced by INSUFFICIENT EVIDENCE + withheld_note)

PRIORITY FINDINGS                                 [see all →]
 [!! ] HIGH   Certificate public key strength     smtp
             A certificate uses an RSA key below the permitted length.
 [!  ] MEDIUM …

PROTOCOL POSTURE
 imap   1 session   STRONG   dimensions assessed: 2 · not observable: 0

WHAT COULD NOT BE DETERMINED              ← abstentions, neutral styling
 NOT_OBSERVABLE · Certificate extraction
   why … / resolved by …

Anomaly prioritisation: disabled for this run     ← ml.enabled, one line
```

The ML line is a single row of metadata. No panel, no score, no icon.

### E. Findings

Scannable rows; click to expand. Severity chip carries colour **and** `severity_label` **and**
`severity_marker`. Existing 8 filter facets retained (they come from `filters`).

Expanded row reveals: `explanation` · affected sessions/protocol · `frames_text` · `source_rule_ids`
· `citations` · `limitations` · `remediation` (only when non-null) · certainty/observability chips.

### F. Evidence & provenance

Three blocks:
1. **Evidence states** — the six `EvidenceState` values with counts from `coverage.observation_counts`,
   neutral chips, each with a one-line gloss.
2. **Abstentions** — each with `what_could_not_be_concluded`, `why`, `resolved_by`, `frames`.
3. **Provenance chain** — a horizontal strip:
   `PCAP SHA-256 → capture_id → frame → TCP stream → evidence → finding → report`, with the real
   `capture_id` shown. Plus `standards` and `unmapped_citations`. Never labelled "chain of custody".

### G. Cross-session

Rendered **only** when the assessment actually contains cross-session evidence
(`issue_class` in the `STARTTLS_BEHAVIOUR_DEVIATION` / `TLS_VERSION_DEVIATION` family, or an
abstention with `INSUFFICIENT_HISTORY`). Shows current session vs comparable history and the
resulting finding text. When history is insufficient, shows the honest abstention instead —
never implies comparison occurred.

## 5. Visual system

```
--surface        #ffffff       page
--surface-sunken #f7f8fa       app background
--surface-raised #ffffff + 1px #e4e7ec border, radius 10px
--ink            #101828       primary text
--ink-muted      #667085       secondary
--border         #e4e7ec
--accent         #1f3a5f       (existing, WCAG-verified)
--accent-soft    #eef2f7

severity:  critical #8d1f1f · high #a8480f · medium #8a6510 · low #3d5a2b · info #41526b
evidence:  neutral chips only — border #d0d5dd, text #475467, NO severity colour
```

Existing severity tokens are **retained** — they are already WCAG-AA verified by
`test_contrast_tokens_meet_wcag_aa`, which must keep passing.

**Type scale:** 30/20/16/15/13/12 px — page title, section, card title, body, meta, chip.
Base 15px stays. System font stack, unchanged, no web fonts.

**Spacing:** 4px base; 24px card padding; 32px section gaps.

## 6. What is deliberately NOT built

No charts library · no donut/gauge · no trend lines · no threat map · no dark mode · no sidebar ·
no toasts · no AI panel · no packet-level drill-down (the assessment carries none) · no skeleton
loaders.

## 7. Test impact (assessed before writing code)

Existing dashboard tests assert **source-level properties** — heading levels, `table()` captions,
label association, no `innerHTML`, contrast tokens, no duplicate fetches, filter behaviour.

| Test class | Impact |
|---|---|
| Contrast tokens | keep passing — severity tokens unchanged |
| No unsafe sinks | keep passing — `dom.js` discipline preserved |
| Heading hierarchy (`h1` shell, `h2` sections, `h3` inside) | **must be honoured by new markup** |
| `table()` caption required | **must be honoured by the new history table** |
| Filter module behaviour | unchanged — `filtering.js` is reused |
| Scene A/B/C real-PCAP tests | assert view-model *content*, not layout — expected to keep passing |
| History polling tests (`bounded`, `single chained timer`, `stops on leaving route`) | **must keep passing** — the polling module is reused unchanged |

**Exactly one existing test is known to require a change:**

`tests/test_dashboard_history.py:277` `test_empty_history_is_explained` asserts

```
assert "No analyses yet" in prose
assert "curl -F file=@capture.pcap" in prose
```

That second assertion pins the very defect being fixed. It will be **rewritten, not deleted** —
the replacement asserts the empty state still explains itself *and* now offers an in-app control
(a file input and a drop target), and asserts the curl string is **absent**. The test's purpose
(the empty state must be explanatory, not blank) is strengthened, not weakened.

`tests/test_dashboard_security_matrix.py:516` mentions curl only in a docstring describing what it
does *not* target; no assertion there depends on it.

Any further test that must change will be reported explicitly with its justification before it is
touched, never silently weakened.

## 8. Open question for approval

**Does the new home screen keep the existing four-route hash router (`#/`, `#/run/{id}`,
`#/run/{id}/findings`, `#/run/{id}/evidence`)?** The proposal keeps it — it is simple, testable,
and needs no server rewrite. Changing it would break existing route tests for no user benefit.
