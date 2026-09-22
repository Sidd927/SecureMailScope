# Phase 12 — 04. Demo reliability audit

Folds in brief §12 (scene-level reliability) and §23 (demo performance) — performance is a
reliability factor, not a separate concern, since the only performance question that matters for
a live demo is "can the judge wait comfortably," answered once, here.

---

## 1. Performance — measured, not estimated (brief §23)

Every number below was measured directly against the released system this phase, not carried
from an earlier phase's report or assumed.

| Step | Measured cost | Comfortable to wait through live? |
|---|---|---|
| `AnalysisService()` construction (cold) | 3.8 ms | yes, imperceptible |
| Full PCAP → assessment, real STARTTLS capture (`submit_path`) | 277 ms | yes, imperceptible |
| Full PCAP → assessment, generated TLS 1.2 + certificate capture | 123 ms | yes, imperceptible |
| `get_assessment()` (already-run, from SQLite) | 0.11–0.12 ms | yes |
| `fastapi` + `uvicorn` + `pydantic` import (one-time process startup) | 175 ms | yes |
| `create_app()` | 67 ms | yes |
| `reportlab` import (PDF path, one-time) | 4.6 ms | yes |
| Dashboard API endpoints (Phase-10 measurement, unchanged by Phase 11): `GET /analyses` 1.18 ms, `GET .../assessment` 0.89 ms, `GET .../dashboard` 1.51–30.95 ms depending on finding count, `GET .../reports/*` 0.84–1.00 ms | sub-millisecond to low tens of ms | yes |
| `GET /health` | 57 ms (an outlier — first-request cold path, not repeated on subsequent calls) | yes |

**Conclusion: there is no performance problem to solve.** Total end-to-end latency for any single
demo action is under 300 ms; the entire 7-minute demo journey in `03-demo-journey.md` is bounded
by presenter pacing, not by the system. **No optimisation work is justified by these numbers.**
This closes brief §23 without further investigation — the "precompute vs. UX vs. caching vs.
optimisation" decision tree the brief asks for collapses immediately: none of the four is needed.

## 2. Reliability checklist, system-wide

| Factor | Status | Detail |
|---|---|---|
| Reproducibility | strong | same PCAP → same `assessment_id` (content-addressed), verified this phase and in Phase 11's release audit |
| Deterministic output | strong | reports are byte-deterministic (`report_sha256`); posture scoring has no randomness; the one known nondeterministic test (`test_malformed_file`, unrelated to any demo path) was fixed to be deterministic in the Phase-11 release-hygiene commit |
| Startup time | strong | see §1 — sub-second everywhere |
| PCAP availability | strong for the core scenes; **staging required** for the cross-session deep-dive | 10 real captures + 3 generated fixtures + 25-capture golden corpus all present on disk; no capture needs to be generated live |
| Report availability | strong | generated on demand in well under 100 ms; no pre-rendered artifact exists yet (a packaging gap, not a reliability one — see `10-demo-environment.md`) |
| Dashboard stability | strong on paper, **unverified in a live browser this phase** | zero npm dependencies, no build step, 33 dashboard security-matrix tests, browser visual QA was performed in Phase 10 but not re-run in Phase 12; recommend one dry-run in the actual demo browser before presenting |
| Browser stability | not independently re-tested this phase | static ES modules, no external CDN, no webfonts — the failure surface is small by construction, but "small failure surface" is not the same claim as "tested this week" |
| tshark dependency | real, and load-bearing | every live scene needs tshark 4.6.8+ on the demo machine; version mismatch is the single most likely infrastructure failure — see the fallback below |
| Filesystem dependency | real, minor | SQLite catalogue + content-addressed artifact store under a data directory (`./securemailscope-data` by default); trivial to reset between runs |
| Network dependency | **none** | no code path in `src/securemailscope/` makes a network call; confirmed by import-set inspection this phase |
| External service dependency | **none** | no cloud API, no LLM endpoint, nothing to be unreachable on demo day |
| AI dependency | **none for the core security story** | every Scene-A/B finding is deterministic; the AI lane is optional (`?ai=true`) and its absence changes nothing about the security conclusion — this is Scene C's entire point |
| CPU/RAM sensitivity | negligible | captures used are a few KB to a few hundred KB; no capture in the demo corpus stresses memory or CPU |
| Timing sensitivity | none identified | no test or scene depends on wall-clock time except the (deliberately) capture-timestamp-based certificate expiry logic, which uses the **capture's** timestamp, not the presenter's clock |

## 3. Per-scene reliability plan

### Scene A — STARTTLS inversion

| | |
|---|---|
| Pre-demo setup | none beyond having the repo checked out at `v0.6.0-phase11` (or later) with `research/experiments/oq33r/out/postfix_smtp_client_declines.pcap` and `postfix_smtp_no_starttls_offered.pcap` present (they ship with the repo) |
| Demo actions | upload both captures; open Findings for each; point at the `AMBIGUOUS`/`COMPLIANT` status and the "no attacker, intent or attribution" limitation text |
| Expected result | identical to `test_scene_a_inversion_declines_are_not_attacks` — no affirmative attack claim in either output |
| Failure mode | tshark absent/wrong version → dissection fails at ingest; user typo in file path → upload error, recoverable in seconds |
| Backup plan | pre-run both captures before the demo session starts and keep the resulting `run_id`s noted; if live upload fails, navigate directly to the History screen entries for the pre-run analyses |

### Scene B — evidence honesty / certificate observability

| | |
|---|---|
| Pre-demo setup | `dovecot_imap_imaps_implicit_tls.pcap` present (ships with the repo) |
| Demo actions | upload; open Evidence screen; point at the abstention and its `resolved_by` text |
| Expected result | identical to `test_scene_b_honesty_states_what_cannot_be_observed` |
| Failure mode | same class as Scene A (tshark/env) |
| Backup plan | same as Scene A — pre-run and keep the `run_id` |

### Scene C — `--no-ai` equivalence

| | |
|---|---|
| Pre-demo setup | `postfix_smtp_starttls_upgrade.pcap`; confirm the `backend` extra (fastapi/pydantic/uvicorn) and `ml`-lane dependencies are installed **before** the demo starts, since this is the one scene that exercises the optional AI path |
| Demo actions | submit the same PCAP twice, once with `?ai=true`, once without; show identical `overall_posture` and `score.value` side by side |
| Expected result | identical to `test_scene_c_no_ai_equivalence_across_the_whole_stack` |
| Failure mode | if the ML dependency is missing, `?ai=true` will not construct a model — **verify this fails loudly, not silently**, before presenting (see the open action in §4) |
| Backup plan | pre-run both variants and keep both `run_id`s; the comparison can be shown from two saved runs with no live re-analysis needed |

### Cross-session deep-dive (only if a judge asks)

| | |
|---|---|
| Pre-demo setup | **requires staging** — the current 10-capture real corpus has too few same-server sessions to reliably trigger the ≥5-session baseline live; a multi-session capture must be prepared and validated in advance if this deep-dive is planned |
| Demo actions | not scripted here — depends on the prepared capture, which does not yet exist as a committed fixture |
| Expected result | a cross-session finding (`CS-STARTTLS-001/002` or `CS-TLS-001`) with baseline evidence cited |
| Failure mode | attempting this live without staging, discovering no baseline forms, and having to explain the mechanism instead of showing it |
| Backup plan | **do not attempt live without staging.** If asked and unstaged, answer verbally (the mechanism is simple to state) rather than attempting a live demo that risks anticlimax |

### Certificate deep-dive (generated TLS 1.2 fixtures)

| | |
|---|---|
| Pre-demo setup | `research/experiments/p11cert/out/smtps_tls12_weak_sha1_rsa1024.pcap` and `smtps_tls12_selfsigned_rsa2048.pcap` present (ship with the repo) |
| Demo actions | upload the weak fixture; show the RSA-1024 and SHA-1 findings at HIGH severity with citations |
| Expected result | matches the measured Phase-11 outcome: 44.0 CRITICAL, two HIGH issue groups |
| Failure mode | same tshark-dependency class as above |
| Backup plan | pre-run and keep the `run_id`; **always state up front that this is a generated, not a real-world, capture** — the honesty discipline this project is built on applies to the demo itself |

## 4. One open action before presenting (not fixed by this audit — flagged for pre-demo execution)

**Verify Scene C's failure behaviour when the AI extras are not installed, on the actual demo
machine, before presenting.** This was not tested this phase (it is a runtime/dependency
question, not a code question, and installing/removing packages on the working environment
during a read-only audit was out of scope). Confirm on the actual demo machine that `?ai=true`
without the `ml`/backend dependencies produces a clear, honest error rather than a silent
fallback — consistent with this project's own discipline, but unverified on that specific machine
until someone runs it there.
