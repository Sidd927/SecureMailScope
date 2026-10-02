# SecureMailScope — analyst dashboard

React 19 + TypeScript + Vite single-page app that renders the backend's assessment as a forensic workstation: **Overview · Findings · Protocol · Certificates · Cross-Session · Provenance · Report**.

It computes no security conclusions of its own; it displays the canonical assessment produced by the backend (see [`../docs/architecture/ARCHITECTURE.md`](../docs/architecture/ARCHITECTURE.md)). If the backend is unreachable it falls back to labelled demo fixtures and shows a **Demo Fixture** badge instead of **Engine Live**.

## Run locally

Start the backend on port 8001 (from the repository root, see the main [README](../README.md#quick-start)), then:

```bash
npm ci
npm run dev        # http://localhost:5173 — /api is proxied to http://127.0.0.1:8001
```

## Build

```bash
npm run build      # type-check + static build into dist/
npm run lint       # oxlint
```

For a deployment where the API is on another origin (as on Vercel + Render), set `VITE_API_BASE_URL` at build time to the backend's `/api/v1` URL, and set `SMS_ALLOWED_ORIGINS` on the backend to the frontend's origin. The default is the relative `/api/v1`.

## Notes

- Fonts (IBM Plex Sans/Mono) are self-hosted via `@fontsource`; no request leaves the browser for fonts.
- There is no automated unit-test suite for the frontend; it is checked by the build, lint and the scripted browser checks in [`scripts/`](scripts/).
- Design tokens and rationale: [`../DESIGN.md`](../DESIGN.md). Handoff: [`../docs/releases/SECUREMAILSCOPE-FRONTEND-HANDOFF.md`](../docs/releases/SECUREMAILSCOPE-FRONTEND-HANDOFF.md).
