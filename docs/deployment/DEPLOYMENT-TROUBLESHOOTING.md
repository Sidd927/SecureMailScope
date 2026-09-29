# SecureMailScope — Deployment Troubleshooting

## Golden case score doesn't match

**Symptom:** `backup_weak_certificate.pcap` returns a score other than
44.0/CRITICAL (or the other golden cases don't match their documented values).

**Most likely cause: TShark version drift.** This exact failure was
reproduced during the deployment audit — Debian's default `apt-get install
tshark` package (4.4.18) silently changed dissection output for the
project's own golden captures versus the 4.6.8 (and the Dockerfile's
verified 4.6.6) every other verification in this project was run against.

Check: `curl https://<backend>/api/v1/health` → look at nothing in
particular in the response for the version (it isn't surfaced there) — instead
exec into the running container/service and run `tshark --version` directly,
or add a temporary log line. Compare against the `Dockerfile`'s own comment
block, which records exactly which TShark version was last verified.

**Do not** adjust the application's scoring, rules, or golden-case
expectations to match a new TShark version's output — that treats a real
environment problem as if it were a product change. Fix the TShark version
instead (pin a base image/PPA combination that reproduces the documented
version), then re-verify.

## Backend health check fails / TShark unavailable

- Confirm the service is actually running the Docker build (`runtime: docker`
  in Render), not a native Python runtime — native runtimes cannot install
  TShark at all (see `DEPLOYMENT-ARCHITECTURE.md`).
- Exec into the container and run `tshark --version` directly; if the binary
  is missing entirely, the `apt-get install tshark` step in the Dockerfile
  build failed — check the Render build logs.

## Frontend shows "Demo Fixture" instead of "Engine Live"

This means the frontend's API requests are failing. In order of likelihood:

1. `VITE_API_BASE_URL` was not set (or was set to the wrong value) at Vercel
   **build** time — this is a build-time variable, not runtime; changing it
   requires a redeploy, not just a restart.
2. CORS: `SMS_ALLOWED_ORIGINS` on the backend doesn't exactly match the
   Vercel URL (check for a trailing slash, `http` vs `https`, or a preview
   deployment URL that differs from production).
3. The backend itself is down or restarting — check `/api/v1/health`
   directly.

Check the browser console for the actual failed request and its status —
a CORS failure and a 404/502 look different there and point to different
fixes.

## Upload fails or times out for a large capture

The backend processes `POST /api/v1/analyses` **synchronously** — the whole
upload + TShark dissection + analysis pipeline runs inside one HTTP request,
budgeted up to `SMS_MAX_ANALYSIS_SECONDS` (600s default). If the frontend and
backend are talking directly (the recommended architecture — see
`DEPLOYMENT-ARCHITECTURE.md`), there is no platform-imposed proxy timeout in
the way. If something *was* inserted between them (a Vercel rewrite, a CDN,
an unexpected reverse proxy), check its timeout first — a naive external
proxy is commonly capped around 120s, well under the backend's own budget for
a legitimately large capture.

## Restart loses all analysis history

**This is expected on Render's Free plan — not a misconfiguration to fix.**
Free web services don't support a persistent Disk, so `SMS_DATA_DIR=/data` is
just a plain directory in the container's own ephemeral filesystem. It is
recreated empty on every restart, redeploy, instance replacement, or Render
maintenance recycle; the SQLite catalog and every stored artifact go with it.
See `DEPLOYMENT-ARCHITECTURE.md` "Ephemeral storage on Render Free."

If durable history genuinely is required, that is a plan/architecture
decision (a paid Render plan with an attached Disk, or an external storage
service), not a bug in this deployment's current configuration.

The one thing worth checking: after a restart, the service must still start
up cleanly against a **freshly empty** `/data` and accept a new submission
normally. If it does not (e.g. it crashes, or `/api/v1/health` fails), that
*is* a real bug — see "Backend health check fails" above.

## PDF report generation fails (JSON/HTML work fine)

The `reporting-pdf` extra (`reportlab`) is separate from the `backend` extra
in `pyproject.toml` — easy to install only `.[backend]` and miss it. The
`Dockerfile` installs `.[backend,reporting-pdf]` together; if a custom build
process was used instead, confirm both extras are present
(`pip show reportlab` inside the container).
