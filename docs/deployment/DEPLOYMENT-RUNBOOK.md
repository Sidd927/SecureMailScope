# SecureMailScope — Deployment Runbook

Prerequisites: a Render account, a Vercel account, this repository pushed to
GitHub with the `deployment/readiness` changes merged into whatever branch you
deploy from.

## 1. Backend — Render

1. Render Dashboard → New → Blueprint → select this repository. Render will
   read `render.yaml` at the repo root.
2. Confirm the service uses `runtime: docker` and `dockerfilePath: ./Dockerfile`
   — do not let Render fall back to a native Python runtime; it cannot install
   TShark (see `DEPLOYMENT-ARCHITECTURE.md`).
3. Confirm the Render Disk (`securemailscope-data`, mounted at `/data`) is
   attached. Without it, every redeploy silently loses all stored analyses.
4. Leave `SMS_ALLOWED_ORIGINS` unset for the first deploy (no frontend exists
   to allow yet).
5. Deploy. First build takes longer than usual — it installs TShark via the
   `wireshark-dev` PPA, not just Python packages.
6. Verify: `curl https://<your-service>.onrender.com/api/v1/health` — must
   show `"tshark": "available"` and `"database": "ok"`.

## 2. Backend verification (before touching the frontend)

```bash
curl -F "file=@demo/captures/backup_weak_certificate.pcap" \
  https://<your-service>.onrender.com/api/v1/analyses
# note the run_id, then:
curl https://<your-service>.onrender.com/api/v1/analyses/<run_id>/assessment \
  | python3 -c "import json,sys; a=json.load(sys.stdin)['assessment']; print(a['score']['value'], a['overall_posture'])"
# must print: 44.0 CRITICAL
```

If it prints anything else, **stop** — do not proceed to the frontend. See
`DEPLOYMENT-TROUBLESHOOTING.md` §"Golden case score doesn't match."

## 3. Frontend — Vercel

1. Vercel Dashboard → New Project → import this repository.
2. Set **Root Directory** to `frontend/`.
3. Vercel auto-detects the Vite framework (build: `npm run build`, output:
   `dist/`). No `vercel.json` is required — the app has no path-based routes
   to rewrite (confirmed: no React Router; all state lives in the query
   string on `/`).
4. Add environment variable `VITE_API_BASE_URL` =
   `https://<your-render-service>.onrender.com/api/v1`.
5. Deploy.

## 4. Close the loop — allow the frontend origin

1. Copy the deployed Vercel URL.
2. Render Dashboard → your backend service → Environment → set
   `SMS_ALLOWED_ORIGINS` to that exact URL (e.g.
   `https://securemailscope.vercel.app` — no trailing slash).
3. Redeploy the backend (env var changes require a restart).

## 5. Frontend/backend integration check

Open the Vercel URL in a browser. The header must show **Engine Live**
(green), not **Demo Fixture** (amber). If it shows Demo Fixture, check the
browser console for the failed request and see
`DEPLOYMENT-TROUBLESHOOTING.md`.

## 6. Golden cases, through the real UI

Upload (or use "Recent checks" if pre-seeded) each of:

| Capture | Expected |
|---|---|
| `backup_weak_certificate.pcap` | 44.0 / CRITICAL |
| `deepdive_cross_session_control_endpoint.pcap` | 22.15 / CRITICAL |
| `scene_b_certificate_honesty.pcap` | 100.0 / STRONG |

Full acceptance checklist: `DEPLOYMENT-ACCEPTANCE.md`.

## 7. Security checks

- From a browser console on a *different* origin than the Vercel deployment,
  attempt `fetch('https://<backend>/api/v1/health')` — must fail with a CORS
  error.
- Confirm HTTPS is enforced on both URLs (both platforms provide this by
  default; just confirm neither serves plain HTTP).

## 8. Deployment freeze

Record the exact deployed commit SHA (backend and frontend, which should
match since they deploy from the same repo state) and the two service URLs.
Do not make further engineering changes to the deployed services without a
genuine defect — this mirrors the `v0.7.1-sih-final` engineering freeze.

## Rollback procedure

- **Backend:** Render Dashboard → Deploys → select the previous successful
  deploy → "Redeploy". The Render Disk is untouched by a rollback (it is not
  part of the image), so stored analyses survive.
- **Frontend:** Vercel Dashboard → Deployments → select the previous
  deployment → "Promote to Production". Instant, no data implications (the
  frontend is stateless).
- Neither rollback touches the GitHub repository, `v0.7.1-sih-final`, or any
  other tag.
