# Finalization — 11. Deployment / installation runbook

Fresh-machine runbook. Assumes Python, tshark, and Git are already present, and the reader has
never seen this project before. Every command below was tested directly this phase (README's
documented startup command was smoke-tested with a live `curl`; the offline claim was verified by
import-set inspection — see `docs/finalization/12-offline-demo-audit.md`).

---

## 1. Prerequisites

| | Minimum | Verified this phase |
|---|---|---|
| Python | ≥ 3.9 | 3.9.6 |
| tshark (Wireshark) | ≥ 4.x (`tshark_min_major=4`, config-overridable via `SMS_TSHARK_MIN_MAJOR`) | 4.6.8 |
| Git | any recent version | — |
| Disk | a few MB for the data directory; captures used in this project are 4–8 KB each | — |
| Network | **none required** | confirmed offline (§14 below) |

## 2. Installation

```bash
git clone <repository-url> SecureMailScope
cd SecureMailScope
git checkout v0.6.0-phase11        # the released system -- NOT main, which is frozen at Phase 3
```

`pip install -e .` is documented as unreliable on the system pip; use `PYTHONPATH=src` throughout
instead, as this entire project's own test suite and tooling does.

```bash
# core analysis engine -- zero dependencies
PYTHONPATH=src python3 -m pytest -q
# expect: 1219 passed
```

## 3. Environment (optional extras, for the backend + dashboard + PDF reports)

```bash
python3 -m pip install 'fastapi>=0.110' 'pydantic>=2' 'uvicorn>=0.27' 'python-multipart>=0.0.9'
python3 -m pip install 'reportlab>=4'      # PDF reports only; JSON and HTML need nothing extra
```

## 4. Database / artifact setup

No manual setup step exists — the backend creates its SQLite catalogue and content-addressed
artifact store automatically on first run, under `./securemailscope-data` by default
(`--data-dir` to change it). Deleting that directory resets everything; there is no migration
step to run.

## 5. Backend startup

```bash
PYTHONPATH=src python3 -m securemailscope.backend --port 8000
```

Binds to `127.0.0.1` only by default — **there is no authentication**, so do not pass `--host` to
bind to a shared network (ADR-0011). Verify it's up:

```bash
curl -s http://127.0.0.1:8000/api/v1/health
```

Expect `"status":"ok"` and `"tshark":"available"` — verified with a live `curl` this phase,
returning a full health payload in under 2 seconds from process start.

## 6. Dashboard startup

No separate step — the dashboard is served by the same process. Open
`http://127.0.0.1:8000/dashboard/` in a browser once the backend (§5) is running.

## 7. Loading a demo capture

Either through the dashboard's upload control, or directly:

```bash
curl -s -F file=@demo/captures/scene_a_1_benign_decline.pcap http://127.0.0.1:8000/api/v1/analyses
```

Or without the server running at all, via the direct pipeline:

```bash
bash demo/commands/run_scene.sh scene_a_1_benign_decline
```

## 8. Running analysis

Analysis runs synchronously and completes as part of the upload call — there is no separate
"start analysis" step. Measured this phase: 115–320 ms per capture, cold-start included.

## 9. Viewing the result

- **Dashboard:** the run appears immediately on the History screen; click through to Overview,
  Findings, or Evidence.
- **API:** `GET /api/v1/analyses/{run_id}/assessment` — **note:** the canonical document is
  nested under an `"assessment"` key in this endpoint's response, not at the top level (a real
  discrepancy found and documented during this phase's rehearsal —
  `docs/finalization/03-demo-rehearsal.md` §3). Use `jq .assessment.score.value`, not
  `jq .score.value`.

## 10. Exporting reports

```bash
curl -s http://127.0.0.1:8000/api/v1/analyses/<run_id>/reports/html -o report.html
curl -s http://127.0.0.1:8000/api/v1/analyses/<run_id>/reports/pdf  -o report.pdf
curl -s http://127.0.0.1:8000/api/v1/analyses/<run_id>/reports/json -o report.json
```

All three verified this phase to be well-formed, safe (zero `<script` in HTML), and correctly
content-bearing (PDF text extraction confirmed real finding text present) —
`docs/finalization/05-report-pack-audit.md`.

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `TsharkNotFound` | tshark not on `PATH`, or path misconfigured | set `tshark_path` in config, or install tshark |
| `TsharkVersionError` | tshark major version < 4 | upgrade tshark; the adapter fails closed rather than silently degrading |
| Port 8000 already in use | another process bound it | `--port <other>` |
| `pip install -e .` fails oddly | known system-pip issue, not project-specific | use `PYTHONPATH=src` invocations instead, as documented throughout |
| Score/posture missing from a `curl \| jq` one-liner | wrong JSON nesting level (§9) | read from `.assessment.score.value`, not `.score.value` |
| Stale results after changing something | leftover data directory | delete `./securemailscope-data` (or point `--data-dir` elsewhere) |

## 12. Common tshark problems

- **Wrong major version:** the adapter checks and fails with a clear `TsharkVersionError` rather
  than misinterpreting output from an incompatible version — this is a deliberate fail-closed
  design, not a bug to route around.
- **Missing entirely:** `TsharkNotFound`, raised at the first call that needs it — no silent
  degraded mode exists.
- **Malformed/truncated/empty PCAPs:** classified explicitly via tshark's own exit codes
  (`MALFORMED`/`TRUNCATED`/`EMPTY`), never treated as valid — see
  `docs/finalization/13-final-security-audit.md`.

## 13. Offline demo procedure

No special procedure is required — the system does not distinguish "offline mode" from normal
operation, because it never attempts network access in the first place. Confirmed by direct
import-set inspection (`docs/finalization/12-offline-demo-audit.md`) and by the live health-check
in §5, which succeeded with no internet dependency at any point.
