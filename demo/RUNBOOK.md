# Demo runbook

The condensed, presenter-facing version of `docs/finalization/11-deployment-runbook.md` and
`docs/phase12/03-demo-journey.md` — what to actually do, in order, on demo day.

## Before the room

1. `git checkout v0.7.0-sih-baseline` on the demo machine.
2. `tshark --version` — confirm it runs and note the version. This project was built and tested
   against 4.6.8; a materially different version is the single most likely failure point.
3. Install the optional extras once: `python3 -m pip install 'fastapi>=0.110' 'pydantic>=2'
   'uvicorn>=0.27' 'python-multipart>=0.0.9' 'reportlab>=4'`.
4. `PYTHONPATH=src python3 -m pytest -q` — confirm the environment is sound (expect `1234 passed`).
5. Start the real system, two terminals (see README.md "Run the full demo" for the full recipe):
   - Terminal 1: `PYTHONPATH=src python3 -m securemailscope.backend --host 127.0.0.1 --port 8001`
     — confirm `http://127.0.0.1:8001/api/v1/health` returns `"tshark":"available"`.
   - Terminal 2: `cd frontend && npm ci && npm run dev` — open `http://localhost:5173` and
     confirm the header shows **Engine Live** (green), not **Demo Fixture** (amber).
6. Pre-run every scene once (`bash demo/commands/run_scene.sh <scene_id>` for each), so every
   `run_id` already exists in the frontend's "Recent checks" list as a fallback if a live
   upload misbehaves.

## During the demo

Follow `docs/phase12/03-demo-journey.md` §3 for the full ~7-minute script. In order:

1. **Opening** — load `demo/captures/scene_a_1_benign_decline.pcap` live; point at its SHA-256
   in the "Recent checks" list (`demo/hashes/SHA256SUMS.txt` has it precomputed if needed).
2. **Scene A** — upload `scene_a_1_benign_decline.pcap` and `scene_a_2_genuine_nonsupport.pcap`
   side by side; point at the `AMBIGUOUS`/`COMPLIANT` states and the "no attacker, intent or
   attribution" text.
3. **Scene B** — upload `scene_b_certificate_honesty.pcap`; open the Certificates tab; point at
   the certificate abstention ("CERTIFICATE CONTENT: NOT OBSERVABLE") and its stated reason.
4. **Scene C** — submit `scene_c_no_ai_equivalence.pcap` twice, `?ai=true` and without; show the
   identical score and posture side by side (pre-generated proof: `demo/expected/scene_c_no_ai_equivalence.json`).
5. **Closing** — download the HTML report for any session shown; note it opens offline, from disk.

If a live upload fails for any reason, fall back to the pre-run `run_id`s from the "before the
room" step — the "Recent checks" list already has them.

## If asked for the deep-dive scenes

- **Certificate deep-dive:** upload `demo/captures/backup_weak_certificate.pcap`; state plainly
  it is a *generated* fixture, not real-world traffic, before showing the RSA-1024/SHA-1 findings.
- **Cross-session deep-dive:** upload `demo/captures/deepdive_cross_session_control_endpoint.pcap`
  (12 sessions, one client deviates from what every *other* client at the same server does — a
  real `MEDIUM` cross-session finding) or `deepdive_cross_session_no_control.pcap` (6 sessions,
  all one client, no control endpoint — the honest negative case: `COMPLIANT` with an explicit
  stated limitation that passive evidence alone cannot rule out consistent stripping here). Full
  worked walkthrough with verbatim engine output: `docs/finalization/06-cross-session-demo.md`.
  The interesting evidence is in the **cross-session findings** on the Findings screen, not the
  top-line posture/score.

## API response shape — one thing to know before scripting anything live

`GET /api/v1/analyses/{run_id}/assessment` wraps the canonical assessment under an
`"assessment"` key, alongside a few top-level convenience fields (`overall_posture`,
`coverage`, `limitations`, `run_id`, `assessment_id`, `capture_id`). **The score is nested:**
`response.assessment.score.value`, not `response.score.value`. Discovered during this phase's
live rehearsal (`docs/finalization/03-demo-rehearsal.md`) when a quick verification one-liner
read the wrong level and appeared to show a missing score — it wasn't missing, it was one level
deeper. If demoing with `curl | jq` live, use `jq .assessment.score.value`, not `jq .score.value`.

## If tshark fails

There is no code fallback — tshark is a hard dependency. Verify the version before the room, not
during it. If it still fails: fall back to the pre-rendered reports in `demo/reports/` and narrate
from those; the story does not require a live re-run.
