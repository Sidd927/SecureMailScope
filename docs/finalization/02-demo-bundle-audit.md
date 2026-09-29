# Finalization — 02. Demo bundle audit

**What was built:** `demo/` — captures (symlinked, not duplicated), machine-generated expected-output
manifests, pre-rendered reports for four scenes, a SHA-256 manifest, an environment record, and
three scripts (`generate_bundle.py`, `start_demo.sh`, `run_scene.sh`).

**Every expected value in `demo/expected/*.json` was written by running the real, released
pipeline this phase — none was hand-typed.** `commands/generate_bundle.py` was executed directly
against `AnalysisService` and produced results that match the values Phase 11 and Phase 12 already
measured independently, which is itself a consistency proof: three independent measurements
(Phase 11's release audit, Phase 12's documentation audit, and this phase's live execution) agree
exactly.

---

## 1. Structure delivered vs. the suggested structure

| Suggested | Delivered | Note |
|---|---|---|
| `demo/README.md` | ✅ | quick start + scene index |
| `demo/RUNBOOK.md` | ✅ | presenter-facing, condensed from `docs/finalization/11-deployment-runbook.md` |
| `demo/captures/` | ✅ | **symlinks** into `research/experiments/`, not copies — the brief explicitly asked to reference rather than duplicate |
| `demo/expected/` | ✅ | one JSON manifest per scene + `all_scenes.json`, all machine-generated |
| `demo/reports/` | ✅ | JSON/HTML/PDF for 4 of 7 scenes (Scene A, B, C, and the weak-certificate backup) — not all 7, per the brief's own guidance to package "one report per scene rather than a huge collection"; the remaining 3 backup scenes are covered by their `expected/` manifest without a rendered artifact |
| `demo/screenshots/` | **empty** | needs a live browser session; not populated this phase (no browser was driven) — recorded honestly as a gap, not silently skipped |
| `demo/commands/` | ✅ | `generate_bundle.py`, `start_demo.sh`, `run_scene.sh` |
| `demo/hashes/` | ✅ | `SHA256SUMS.txt`, computed directly against the real files, verified as 64-character digests programmatically (not eyeballed) |
| `demo/environment/` | ✅ | `environment.json` — Python 3.9.6, tshark 4.6.8, macOS-26.6.2-arm64 |
| `demo/evidence/` | ✅, as a pointer | deliberately does not duplicate `docs/finalization/04` and `docs/phase12/08` — points to them instead |

## 2. Scene mapping, confirmed against real execution

| Scene | Capture | Command exists and runs | Real result this phase |
|---|---|---|---|
| A.1 — benign decline | `scene_a_1_benign_decline.pcap` | ✅ (`run_scene.sh scene_a_1_benign_decline`, tested directly) | ADEQUATE 88.0, 320.9 ms (cold run) |
| A.2 — genuine non-support | `scene_a_2_genuine_nonsupport.pcap` | ✅ | ADEQUATE 85.0, 116.6 ms |
| B — certificate honesty | `scene_b_certificate_honesty.pcap` | ✅ | STRONG 100.0, 119.0 ms |
| C — `--no-ai` equivalence | `scene_c_no_ai_equivalence.pcap` | ✅ | ADEQUATE 88.0 both with and without AI — `penalising_issue_classes` byte-identical between the two runs, verified programmatically |
| Backup — weak certificate | `backup_weak_certificate.pcap` | ✅ | CRITICAL 44.0, 118.4 ms |
| Backup — self-signed | `backup_selfsigned_certificate.pcap` | ✅ | ADEQUATE 88.0, 116.7 ms |
| Backup — healthy chain | `backup_healthy_chain.pcap` | ✅ | STRONG 100.0, 118.6 ms |

**Every number above matches what Phase 11's release audit and Phase 12's documentation both
independently reported.** No drift found.

## 3. What was verified about the generated reports (Workstream E overlap, recorded once here)

- **JSON:** all 4 generated reports parse as valid JSON (`json.load` succeeded on each).
- **HTML:** zero `<script` occurrences in any of the 4 generated HTML reports (`grep -c "<script"`
  returned 0 for each) — consistent with the zero-dependency, script-free rendering design.
- **PDF:** text-extracted (via `pypdf`) from `backup_weak_certificate.pdf` and confirmed to contain
  `1024`, `SHA-1`, `CRITICAL`, and the key-strength/signature-algorithm finding text — the report
  is not merely well-formed, its content is correct.
- **AI wording:** searched the generated HTML for overclaim patterns — none found. The `ai=False`
  report correctly shows no `model_summary` role text at all (because AI was disabled for that
  render); the `ai=True` role text (`"secondary prioritisation signal only"`) was independently
  confirmed present in the `expected/scene_c_no_ai_equivalence.json` manifest's `ai_true` branch,
  since no report was rendered for that specific run — this phase only renders one report per
  scene family to avoid the "huge report collection" the brief explicitly discourages.

## 4. Known gap, stated rather than hidden

**No screenshots exist.** Capturing dashboard screenshots requires driving a real browser against
a running server, which this audit phase did not do (the brief's Workstream C asks for scene
*execution* and *rehearsal*, which was done via direct pipeline calls — see
`docs/finalization/03-demo-rehearsal.md` — not via a browser). This is recorded as a remaining,
non-blocking task, not silently left empty.
