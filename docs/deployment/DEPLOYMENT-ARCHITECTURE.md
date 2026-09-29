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
    └── Backend → Render Web Service (Docker)
          Dockerfile (repo root)
          FastAPI + uvicorn, TShark, SQLite on a Render Disk
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

See `docs/deployment/DEPLOYMENT-ACCEPTANCE.md` for the restart-persistence test,
and the main audit conversation for the full reasoning. Summary: SQLite here is
deliberately durable application state (`synchronous=FULL`, described in
`db.py` as a "forensic store"), `max_concurrent_analyses=1` is an explicit,
documented architectural invariant (ADR-0018) — not a limitation this
deployment needs to work around — and this is a bounded-scale SIH demo, not a
multi-tenant service. Persistence across restarts/redeploys is achieved with a
**Render Disk** mounted at `SMS_DATA_DIR`, not a different database engine.

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
