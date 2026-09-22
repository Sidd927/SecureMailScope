# Finalization — 13. Final security/integrity audit

**Method:** per the brief's explicit instruction, this audit **reuses existing evidence rather
than repeating enormous test suites** — the 1219-test suite and Phase 11's hostile-content
release audit already cover most of this checklist exhaustively. What's new here is targeted:
checks specific to what this finalization phase actually introduced (symlinked capture inputs,
new demo scripts, freshly generated reports), plus pointers to where the pre-existing coverage
lives for everything else.

---

## 1. Checked fresh this phase (new material, new risk surface)

| Check | Method | Result |
|---|---|---|
| **Symlink handling** — do symlinked capture inputs (new this phase, all of `demo/captures/`) hash and analyse correctly? | Directly hashed a symlink target and compared against the `capture_id` the pipeline computed from the same symlink path | **identical** — the system correctly follows the symlink and hashes the real target's bytes, not the symlink's own path string |
| **Path traversal** | Fed `../../../../etc/passwd` directly to `TsharkAdapter.dissect()` | Correctly classified `MALFORMED`, `usable: False` — no traversal-based content exposure; a non-PCAP file is rejected by content validation regardless of how its path was constructed |
| **Hostile content in freshly generated reports** | `grep -c "<script"` on all 4 reports generated this phase (`demo/reports/`) | **zero**, confirmed in `docs/finalization/05-report-pack-audit.md` §2 |
| **PDF content correctness under hostile-adjacent data** | Text-extracted a report containing real (not synthetic-hostile) attacker-influenced certificate fields (RSA-1024, SHA-1) | Correct, legible, no injection artifacts — `docs/finalization/05-report-pack-audit.md` §3 |
| **New demo scripts** (`generate_bundle.py`, `run_scene.sh`, `start_demo.sh`, `preflight.sh`) | Manual review: no `shell=True`, no string-interpolated commands, no `eval` | Clean — `run_scene.sh` passes the capture path as a Python argv element, not through shell interpolation into a command string |

## 2. Reused from existing evidence, not re-run

| Area | Where the evidence already lives |
|---|---|
| Malformed/truncated/empty/oversized PCAP handling | `tests/test_tshark_adapter.py` — including the deterministic-fixture fix landed in the `v0.6.0-phase11` release-hygiene commit |
| Hostile certificate content (script tags, event handlers, CSS/prototype injection, RTL override, template injection) — 15-payload matrix | Phase 11's release audit, re-confirmed structurally unchanged (`git diff --stat -- src/` shows zero drift) |
| Prompt injection | `research/experiments/oq28/pcaps/X_prompt_injection.pcap`, a dedicated golden-corpus regression fixture; no LLM surface exists for a prompt to be injected into (`docs/finalization/10-final-judge-cheatsheet.md` Q) |
| Unsafe HTML sinks / unsafe JS eval | zero `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`/`new Function` anywhere in `dashboard/static/`, verified in Phase 10 and re-confirmed unchanged this phase (no dashboard source file touched) |
| Resource limits (`max_upload_bytes`, `max_json_bytes`, `max_analysis_seconds`, `max_concurrent_analyses`) | exposed transparently via `GET /api/v1/health` (observed live this phase: 268,435,456 / 65,536 / 600 / 1), enforced per `tests/test_backend_pipeline.py`, `tests/test_backend_api.py` |
| Concurrent analysis behaviour | `max_concurrent_analyses: 1` enforced, covered in `tests/test_backend_persistence.py` |
| Corrupted artifact / tamper detection | `tests/test_backend_pipeline.py`, `tests/test_reporting_api.py`; live-verified this phase via `list_artifacts(verify=True)` returning a re-hashed, verified result (`docs/finalization/05-report-pack-audit.md` §4) |
| Provenance integrity | traced live across 13 real capture executions this phase with zero mismatch (`docs/finalization/04-real-pcap-evidence-pack.md` §7) |
| Report/hash consistency | `demo/hashes/SHA256SUMS.txt`, computed directly against real files, all 64-character digests confirmed programmatically (not eyeballed) |

## 3. Findings

**No release-blocking issue found.** No new test was added, because no genuine finalization
regression was found — every check either passed directly or confirmed existing coverage already
holds. This is consistent with `docs/phase12/09-architecture-freeze-audit.md`'s independent
conclusion that the architecture is measurably stable.
