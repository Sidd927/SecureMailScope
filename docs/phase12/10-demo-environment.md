# Phase 12 — 10. Demo environment audit

Folds in brief §24 (environment) and §30 (demo package plan — no dedicated filename was specified
for it; it belongs here because a demo bundle *is* a packaged environment).

---

## 1. Can it run fully offline?

**Yes, verified this phase.** No code path in `src/securemailscope/` makes a network call
(confirmed by import-set inspection in `00-release-state-audit.md` §2). The backend was started
with the exact documented command and answered `GET /api/v1/health` correctly in under 2 seconds
from process start, with no internet connection required for that request:

```
$ PYTHONPATH=src python3 -m securemailscope.backend --port 18766 --data-dir /tmp/demo-data
$ curl -s http://127.0.0.1:18766/api/v1/health
{"status":"ok", ... "tshark":"available", "posture_engine_version":"0.8.0", ...}
```

## 2. Environment audit

| Dependency | Required? | Notes |
|---|---|---|
| Mac / Linux | either | this audit ran on macOS (Darwin); nothing in `src/` is platform-specific — subprocess calls use an argument array, never a shell string, and paths are handled with `os.path`, not hardcoded separators |
| Docker | **no** | referenced only by `research/experiments/` fixture-generation scripts, never by the shipped application |
| TShark | **yes, hard dependency** | pinned to 4.6.8 in this audit's environment; the adapter checks the version and fails closed (`TsharkVersionError`) rather than silently degrading on an incompatible version — verify the demo machine's tshark version **before** the day |
| Python | **yes**, ≥3.9 | 3.9.6 confirmed working this phase; all Phase-11 modules independently verified to parse under 3.9 grammar |
| Browser | needed for the dashboard scenes only | no CDN, no webfont, no external script — static ES modules served by the same process |
| SQLite | bundled with Python's stdlib | no separate install |
| Filesystem | a writable data directory | defaults to `./securemailscope-data`; trivially reset between demo runs by deleting it |
| Ports | loopback only, default 8000 | `--port`/`--host` are configurable; binding to a non-loopback address logs a warning (no authentication exists — do not do this on a shared network) |
| Permissions | read access to the PCAP corpus, write access to the data directory | nothing else |

## 3. Exact reproducible startup commands

```bash
# from the repository root, on the released tag
git checkout v0.6.0-phase11

# core analysis only (zero dependencies)
PYTHONPATH=src python3 -m pytest -q                       # confirms the environment is sound

# backend + dashboard (needs the optional extras once)
python3 -m pip install 'fastapi>=0.110' 'pydantic>=2' 'uvicorn>=0.27' 'python-multipart>=0.0.9'
python3 -m pip install 'reportlab>=4'                      # for PDF reports

PYTHONPATH=src python3 -m securemailscope.backend --port 8000
# then open http://127.0.0.1:8000/dashboard/
```

`pip install -e .` is documented in the README as unreliable on the system pip; the
`PYTHONPATH=src` invocation above is the tested path and is what this audit used throughout.

## 4. What can fail, and the fallback for each

| Failure | Likelihood | Fallback |
|---|---|---|
| tshark absent or version-mismatched on the demo machine | the single most likely infrastructure failure | verify with `tshark --version` before the demo starts; there is no code fallback for this — it is a hard dependency, so pre-flight checking is the only mitigation |
| optional extras (fastapi/reportlab) not installed | moderate, if the demo machine differs from the dev machine | install ahead of time; the core analysis engine works with zero extras, so JSON output via direct Python calls remains a fallback even without the backend |
| port 8000 already in use | low | `--port` flag; trivial |
| stale data directory from a previous run | low | delete `./securemailscope-data` (or point `--data-dir` elsewhere) before the demo |
| demo laptop has no internet | **not a failure at all** | the system needs none |

## 5. Demo package plan (brief §30)

**No demo bundle exists yet.** This section specifies what it should contain; building it is a
candidate action evaluated in `13-final-engineering-decision.md`, not performed during this
read-only audit.

### 5.1 Required captures (already present in the repository — no new capture generation needed)

| Capture | SHA-256 | Role |
|---|---|---|
| `postfix_smtp_client_declines.pcap` | `1f9863aef21f602c7093c980750b13afb4f63262c94c978512bd0047779f04f0` | Scene A (benign decline) |
| `postfix_smtp_no_starttls_offered.pcap` | `eacbc065c3427acf406ec8f2059ded8b6e77162a60a3c1497b8fbd805a941e20` | Scene A (genuine non-support) |
| `dovecot_imap_imaps_implicit_tls.pcap` | `d257ec482cd486432e510f8ddb9cf9e46747c237e743036c977b67b76cc51f65` | Scene B (certificate abstention) |
| `postfix_smtp_starttls_upgrade.pcap` | `c2a84bf4ed973fcdff29bc5dd8ea24791d195fa186be3bbe7a359f68a3201ff` | Scene C (`--no-ai` pair) |
| `smtps_tls12_weak_sha1_rsa1024.pcap` | `ce5377348e22ad92c33d705e31388944bad8224534d478c38b57a75d3ba4a501` | certificate deep-dive (weak fixture) |
| `smtps_tls12_selfsigned_rsa2048.pcap` | `c08508835713a7485fc8456a58b93c226786f7f46b6da483706f586240ac2ca` | certificate deep-dive (self-signed) |
| `smtps_tls12_chain_rsa2048.pcap` | `43ee75d5eae7b523dcc051b6e92a200a8d171342ddecf24ce32e3a0f140e216` | certificate deep-dive negative control (healthy) |

Hashes were computed directly this phase (`shasum -a 256`), not carried from an earlier document.

### 5.2 Expected outputs (already measured, this phase and Phase 11's release audit)

| Capture | Expected `overall_posture` | Expected score |
|---|---|---|
| `postfix_smtp_client_declines` | ADEQUATE | 88.0 |
| `postfix_smtp_no_starttls_offered` | ADEQUATE | 85.0 |
| `dovecot_imap_imaps_implicit_tls` | STRONG | 100.0 |
| `postfix_smtp_starttls_upgrade` | ADEQUATE | 88.0 |
| `smtps_tls12_weak_sha1_rsa1024` | CRITICAL | 44.0 |
| `smtps_tls12_selfsigned_rsa2048` | ADEQUATE | 88.0 |
| `smtps_tls12_chain_rsa2048` | STRONG | 100.0 |

A live result that doesn't match this table on demo day means the environment differs from this
audit's — check the tshark version first.

### 5.3 What the bundle should eventually contain

```
demo/
  README.md                # the exact commands in SS3 above, plus this table
  captures/                # symlinks or copies of the 7 files in SS5.1, with a SHA256SUMS file
  manifests/                # the expected-output table in SS5.2, machine-readable (JSON)
  expected/                 # one saved JSON assessment per capture, for offline diffing
  scripts/
    run_all.sh               # submits all 7 captures, prints pass/fail against manifests/
    start_demo.sh             # the backend startup command, with the data dir pre-set
  screenshots/              # not yet captured -- would need a live dashboard session
  reports/                  # pre-rendered HTML/PDF for the 7 captures (closes the R-03 packaging gap noted in doc 01)
  presentation-assets/       # empty until a slide deck exists
```

**Nothing above requires new engineering.** Every piece is either already-present data (the
captures) or a thin packaging/scripting task around existing, tested functionality
(`run_all.sh` is a loop over `submit_path` calls this audit already exercises manually). This is
explicitly the kind of work `13-final-engineering-decision.md` classifies separately from feature
engineering — see that document for the effort estimate and priority classification.
