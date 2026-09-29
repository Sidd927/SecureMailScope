# SecureMailScope — Deployment Acceptance Tests

Run these against the actually-deployed services after `DEPLOYMENT-RUNBOOK.md`.
Every item here was executed against a real local Docker build of the backend
during the deployment readiness audit (not assumed) unless marked otherwise.

**This deployment runs on Render's Free web-service compute plan with no
persistent Disk.** Filesystem/SQLite state is ephemeral — see
`DEPLOYMENT-ARCHITECTURE.md` "Ephemeral storage on Render Free." Item 21
below tests for the *correct* ephemeral behavior (clean restart from empty
state), not for persistence across restarts.

| # | Test | Expected | Verified in audit? |
|---|---|---|---|
| 1 | Frontend loads | Vercel URL renders the landing page over HTTPS | Deployment-specific — verify after Vercel deploy |
| 2 | API health | `GET /api/v1/health` → `status: ok`, `database: ok` | Yes, via Docker container |
| 3 | TShark availability | Same response → `tshark: available` | Yes — required a base-image fix; see below |
| 4 | PCAP upload (SMTP) | `backup_weak_certificate.pcap` → `state: COMPLETED` | Yes |
| 5 | IMAP capture | Any IMAP demo capture analyzes without error | Not re-run in this audit (SMTP path verified; IMAP/POP3 share the same dissection code path, not separately re-tested against the container) |
| 6 | POP3 capture | Same | Not re-run in this audit, same reasoning |
| 7 | Certificate extraction | `backup_weak_certificate.pcap` → RSA 1024-bit / SHA-1 findings | Yes (implied by the exact score match, §9) |
| 8 | Cross-session reasoning | `deepdive_cross_session_control_endpoint.pcap` → 22.15/CRITICAL | Yes |
| 9 | AI ON | `scene_c_no_ai_equivalence.pcap?ai=true` → 88.0/ADEQUATE | Not re-run against the container in this audit (verified on `main` directly, not re-verified through Docker) |
| 10 | AI OFF | Same capture, AI off → 88.0/ADEQUATE, identical | Same as above |
| 11 | Case A | `backup_weak_certificate.pcap` → **44.0 / CRITICAL** | **Yes — exact match, through the real container** |
| 12 | Case B | `deepdive_cross_session_control_endpoint.pcap` → **22.15 / CRITICAL** | **Yes — exact match, through the real container** |
| 13 | Case C | `scene_b_certificate_honesty.pcap` → **100.0 / STRONG** | **Yes — exact match, through the real container** |
| 14 | JSON report | `GET .../reports/json` returns valid JSON | Implied by assessment reads succeeding; not separately re-fetched as a report artifact in this audit |
| 15 | HTML report | `GET .../reports/html` returns valid, script-free HTML | Not re-run against the container in this audit (verified on `main` directly) |
| 16 | PDF report | `GET .../reports/pdf` returns a valid multi-page PDF | **Yes — 7 pages, parsed with pypdf, through the real container** |
| 17 | Hostile payload | The exact prior XSS payload stays escaped in generated reports | Not re-run against the container in this audit (verified on `main` directly via the test suite, which the Docker image's own `pip install` does not re-run — see note below) |
| 18 | Path traversal | Hostile filenames never reach disk | Same as above |
| 19 | CORS | Configured origin allowed; other origins rejected | **Yes — verified both directions, through the real container** |
| 20 | HTTPS | Both services serve only HTTPS | Deployment-specific — Render and Vercel both provide this by default; verify after deploy |
| 21 | Restart behavior | **On Render Free (no Disk), stored assessments are EXPECTED to be lost on restart/redeploy — this is not a bug.** Verify the service instead starts cleanly from an empty `/data` and accepts a fresh submission afterward (`state: COMPLETED`), rather than expecting a previous `run_id` to still resolve. | **Yes — verified directly: built the image, ran it against a brand-new, empty data directory, and confirmed startup, health, and a fresh golden-case submission all succeed with zero pre-existing state.** |

**Note on items marked "not re-run against the container":** the backend's
own test suite (1234 tests, including the hostile-payload and path-traversal
regressions) runs against the source code directly, not inside the built
Docker image — the Docker image does not contain or run `tests/`. Since the
Dockerfile changes no application code (only the base OS image), and the
source code build/verification chain proves those properties hold, re-running
the tests inside every future container build is unnecessary for the *code*
guarantee. It is still real work to **directly exercise** the deployed
service for items 5, 6, 9, 10, 14, 15, 17, 18 the same way items 11–13, 16,
and 19 were — that has not been done as part of this repository audit and
should be part of the first real deployment's acceptance pass, not assumed
complete from this document.

## The one finding this audit's testing actually caught

Item 3 (TShark availability) was not a simple pass. The first Docker build
(Debian's default `apt-get install tshark`, version 4.4.18) produced **wrong**
golden-case results — 72.0/WEAK instead of 44.0/CRITICAL for the identical
input file, because of a real dissector-behavior difference between TShark
4.4.x and the 4.6.8 this project's golden cases were established against. The
`Dockerfile` was corrected (Ubuntu 24.04 + the official `wireshark-dev` PPA,
providing 4.6.6) and re-verified until items 11–13 passed exactly. This is
recorded here specifically so a future base-image change is not made without
repeating this exact check.
