# SecureMailScope — Deployment Architecture

## Overview

```
GitHub main (v0.7.1-sih-final state, plus deployment/readiness)
    │
    ├── Frontend → Vercel
    │     frontend/ (Vite + React, static build)
    │     Root Directory: frontend/
    │     Build: npm ci && npm run build
    │     Output: frontend/dist/
    │     Env (build-time): VITE_API_BASE_URL
    │
    └── Backend → Render Web Service (Docker), Free compute plan
          Dockerfile (repo root)
          FastAPI + uvicorn, TShark, SQLite on the container's own
          ephemeral filesystem (no Render Disk -- Free web services
          don't support one; see "Ephemeral storage" below)
          Env: SMS_DATA_DIR, SMS_ALLOWED_ORIGINS, PORT (set by Render)
```

Two independently deployed services, on two different origins, talking directly
over HTTPS with CORS — not through a proxy. See "Why not a Vercel proxy" below.

## Why Docker for the backend

TShark is an OS-level package (`apt-get install tshark`), not a Python package.
Render's native Python runtime has no `apt-get`/system-package access during
build — Render's own documentation and support threads are explicit that Docker
is required for any OS-level dependency the native runtimes don't already include.
TShark is not among them.

The `Dockerfile` at the repo root installs `tshark` via `apt-get`, then installs
the Python package with the `backend` and `reporting-pdf` extras (`pip install
".[backend,reporting-pdf]"` — the PDF extra is easy to miss since it's separate
from `backend` in `pyproject.toml`, and without it `/reports/pdf` fails at
runtime).

No live-capture privileges are needed inside the container: the application's
only TShark invocation is `tshark -r <file> -T ek` (`src/securemailscope/
dissect/tshark.py`) — reading an already-uploaded file, never touching a live
network interface. A plain `apt-get install` is sufficient; no `setcap` or
capture-group configuration is required.

## Why not a Vercel proxy (rewrites) for the API

Vercel supports proxying a path to an external origin via `rewrites` in
`vercel.json`. That was considered and rejected for the API path specifically:
external-target rewrites are subject to a **120-second** timeout, but
`POST /api/v1/analyses` (`src/securemailscope/backend/api.py`) runs the entire
upload + TShark dissection + analysis pipeline **synchronously**, inside the one
HTTP request, with a budget of up to `SMS_MAX_ANALYSIS_SECONDS` (600s default).
A legitimately large or slow capture could be correctly processing on the
backend while Vercel's proxy layer has already given up and returned
`ROUTER_EXTERNAL_TARGET_ERROR` to the browser.

Instead: the frontend talks **directly** to the Render backend origin
(`VITE_API_BASE_URL`), and the backend allows that origin via CORS
(`SMS_ALLOWED_ORIGINS`). No proxy layer sits between them, so no proxy-imposed
timeout applies — only Render's own request-handling behavior, which is not
bounded by a 120s ceiling for a normal HTTP request to a running web service.

No `vercel.json` is needed for routing: the frontend has no path-based routes
(confirmed — no React Router, `window.location.pathname` is never changed; all
navigation state lives in the query string on `/`), so there is nothing for a
SPA rewrite rule to fix. Set the Vercel project's **Root Directory** to
`frontend/` in the dashboard; Vercel auto-detects the Vite framework and build
output from there.

## Why SQLite, unchanged

SQLite itself is not migrated to anything else, and nothing about its
*application-layer* design changes for this deployment. It remains deliberately
durable-by-design application state (`synchronous=FULL`, described in `db.py`
as a "forensic store"), and `max_concurrent_analyses=1` remains an explicit,
documented architectural invariant (ADR-0018) — not a limitation this
deployment needs to work around. This is a bounded-scale SIH demo, not a
multi-tenant service, so nothing here required introducing Postgres or any
other database engine.

**What did change: where it's deployed.** The rest of this section (and the
one below) explains the consequence.

## Ephemeral storage on Render Free

Render's **Free** web-service compute plan does not support attaching a
persistent Disk (that capability requires a paid plan). This deployment
targets Free, so:

- `SMS_DATA_DIR=/data` is a plain directory inside the container's own
  filesystem — created by `mkdir -p /data` in the `Dockerfile`, and by
  `AnalysisService.__init__`'s own `os.makedirs(..., exist_ok=True)` if it
  didn't already exist. No code change was needed for this: the application
  already tolerates a completely empty, freshly created data directory on
  every startup (verified — see `DEPLOYMENT-ACCEPTANCE.md`).
- That directory, and everything in it — the SQLite catalog and every stored
  artifact — **does not survive** a service restart, a redeploy, an instance
  replacement, or Render's own maintenance/recycling of the underlying
  compute. It is container-local, ephemeral storage, not a mounted volume.
- **This is an accepted tradeoff for the SIH demonstration deployment, not
  durable production persistence.** Say exactly that — do not describe this
  deployment as retaining analysis history across restarts, and do not call
  it "production-grade storage." A fresh capture submitted after any restart
  works completely normally; a capture submitted *before* a restart will be
  gone afterward.
- If a future deployment needs analyses to survive restarts/redeploys, that
  requires a separate persistence architecture — e.g. upgrading the Render
  plan to one with an attachable Disk, or moving the artifact/catalog storage
  to an external service — evaluated on its own merits at that time. It is
  explicitly out of scope for this change.

## Known, pre-existing, unfixed risk

`TECH-DEBT.md` item 10 (found during earlier validation, not introduced by
deployment prep): the SQLite connection uses `check_same_thread=False` with
unlocked reads; overlapping requests have been reproduced to occasionally
corrupt reads. The previous mitigation — the frontend serializing its own
requests — protects one browser tab talking to the backend, but does not
protect against genuinely concurrent public traffic once the API is reachable
directly. This is a real, known limitation of deploying this specific backend
publicly as-is. It is not fixed here: it is a persistence-layer engineering
change, out of scope for deployment configuration, and explicitly preserved
per the audit's "do not change the security engine / persistence" instruction.

## No authentication

The backend has no authentication by design (ADR-0011): it is documented as a
single-analyst local tool. Deploying it publicly means anyone with the URL can
submit captures and read every stored assessment (`GET /api/v1/analyses` lists
everything, with no per-user scoping — there is no concept of a user at all).
This was not redesigned as part of this deployment preparation. If the SIH
demo deployment needs to restrict access, do so at the platform layer (e.g.
Render's own access controls) rather than inside the application.

## Payment/billing truth

`render.yaml` requests Render's **Free** web-service compute plan
(`plan: free`) and declares no Disk, so nothing in this Blueprint requires a
paid resource. That is the accurate, complete claim this document makes.

It does **not** claim that Render's account/workspace signup or verification
flow can never ask for billing details — that is a platform/account-level
policy, independent of what any given Blueprint requests, and this repository
has no visibility into or control over it. If Render's dashboard prompts for
payment information during account setup, that is an account-level condition
to resolve with Render directly, not something `render.yaml` can or should
try to override.
