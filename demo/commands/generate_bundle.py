#!/usr/bin/env python3
"""
Demo bundle generator (Finalization Workstream B/C/D/E).

Runs every demo scene through the REAL, released pipeline and writes what actually came
back -- never a hand-typed expected value. Re-run this script any time the demo bundle
needs refreshing; it is read-only with respect to src/ and only writes into demo/.

Usage (from the repository root):
    PYTHONPATH=src python3 demo/commands/generate_bundle.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, "src")

from securemailscope.backend.service import AnalysisService          # noqa: E402
from securemailscope.reporting.service import render_bytes            # noqa: E402
from securemailscope.dashboard import project                         # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO_DIR = os.path.join(REPO_ROOT, "demo")
CAPTURES_DIR = os.path.join(DEMO_DIR, "captures")
EXPECTED_DIR = os.path.join(DEMO_DIR, "expected")
REPORTS_DIR = os.path.join(DEMO_DIR, "reports")
HASHES_DIR = os.path.join(DEMO_DIR, "hashes")
ENV_DIR = os.path.join(DEMO_DIR, "environment")

#: scene_id -> (capture symlink name, purpose, whether this scene also needs an ai=False run)
SCENES = {
    "scene_a_1_benign_decline": ("scene_a_1_benign_decline.pcap",
                                 "STARTTLS inversion: benign client decline", False),
    "scene_a_2_genuine_nonsupport": ("scene_a_2_genuine_nonsupport.pcap",
                                     "STARTTLS inversion: genuine server non-support", False),
    "scene_b_certificate_honesty": ("scene_b_certificate_honesty.pcap",
                                    "Evidence honesty: TLS 1.3 certificate NOT_OBSERVABLE", False),
    "scene_c_no_ai_equivalence": ("scene_c_no_ai_equivalence.pcap",
                                  "--no-ai equivalence", True),
    "backup_weak_certificate": ("backup_weak_certificate.pcap",
                                "Backup: generated TLS 1.2, RSA-1024 + SHA-1", False),
    "backup_selfsigned_certificate": ("backup_selfsigned_certificate.pcap",
                                      "Backup: generated TLS 1.2, self-signed leaf", False),
    "backup_healthy_chain": ("backup_healthy_chain.pcap",
                             "Backup: generated TLS 1.2, healthy chain (negative control)", False),
}

#: scenes for which a full report set (JSON/HTML/PDF) is generated (Workstream E: one per
#: scene family, not a huge collection).
REPORT_SCENES = {"scene_a_1_benign_decline", "scene_b_certificate_honesty",
                 "scene_c_no_ai_equivalence", "backup_weak_certificate"}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def summarise(assessment: dict) -> dict:
    """Pull exactly the fields the manifest needs, straight from the real document."""
    issue_groups = assessment.get("issue_groups", [])
    return {
        "overall_posture": assessment.get("overall_posture"),
        "score_value": (assessment.get("score") or {}).get("value"),
        "score_band": (assessment.get("score") or {}).get("band"),
        "coverage": assessment.get("coverage"),
        "issue_group_count": len(issue_groups),
        "penalising_issue_classes": sorted(
            g["issue_class"] for g in issue_groups if g.get("penalising")),
        "all_issue_classes": sorted(g["issue_class"] for g in issue_groups),
        "abstention_count": len(assessment.get("abstentions", [])),
        "abstention_reasons": sorted({a.get("reason") for a in assessment.get("abstentions", [])}),
        "model_summary_role": (assessment.get("model_summary") or {}).get("role"),
        "ai_enabled": assessment.get("ai_enabled"),
        "assessment_id": assessment.get("assessment_id"),
        "capture_id": assessment.get("capture_id"),
    }


def main() -> None:
    os.makedirs(EXPECTED_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(HASHES_DIR, exist_ok=True)
    os.makedirs(ENV_DIR, exist_ok=True)

    hash_lines = []
    for name in sorted(os.listdir(CAPTURES_DIR)):
        real_path = os.path.realpath(os.path.join(CAPTURES_DIR, name))
        digest = sha256_file(real_path)
        hash_lines.append(f"{digest}  {name}  (-> {os.path.relpath(real_path, REPO_ROOT)})")
    with open(os.path.join(HASHES_DIR, "SHA256SUMS.txt"), "w") as fh:
        fh.write("\n".join(hash_lines) + "\n")

    with tempfile.TemporaryDirectory() as tmp:
        svc = AnalysisService(os.path.join(tmp, "data"))
        results = []

        for scene_id, (capture_name, purpose, needs_ai_pair) in SCENES.items():
            capture_path = os.path.join(CAPTURES_DIR, capture_name)
            real_path = os.path.realpath(capture_path)
            capture_sha256 = sha256_file(real_path)

            runs = {}
            for ai_flag in ((True, False) if needs_ai_pair else (False,)):
                t0 = time.time()
                sub = svc.submit_path(capture_path, ai_enabled=ai_flag)
                run_id = sub.run.run_id
                assessment = svc.get_assessment(run_id)
                elapsed_ms = (time.time() - t0) * 1000
                runs[f"ai_{ai_flag}".lower()] = {
                    "run_id": run_id,
                    "elapsed_ms": round(elapsed_ms, 1),
                    "summary": summarise(assessment),
                }
                if scene_id in REPORT_SCENES and (not needs_ai_pair or ai_flag is False):
                    for fmt, ext in (("json", "json"), ("html", "html"), ("pdf", "pdf")):
                        try:
                            raw, _doc = render_bytes(assessment, fmt)
                        except Exception as exc:                       # pragma: no cover
                            raw = None
                            print(f"  ! {scene_id} {fmt} render failed: {exc}")
                        if raw is not None:
                            out_path = os.path.join(REPORTS_DIR, f"{scene_id}.{ext}")
                            with open(out_path, "wb") as fh:
                                fh.write(raw)
                            print(f"  wrote {out_path} ({len(raw)} bytes, "
                                  f"sha256={hashlib.sha256(raw).hexdigest()[:16]}...)")

            manifest = {
                "scene_id": scene_id,
                "purpose": purpose,
                "input_capture": capture_name,
                "capture_sha256": capture_sha256,
                "command": f"PYTHONPATH=src python3 -c \"...submit_path('{capture_path}')...\"  "
                           f"(equivalently: curl -F file=@{capture_path} "
                           f"http://127.0.0.1:8000/api/v1/analyses{'?ai=true' if needs_ai_pair else ''})",
                "exit_status": "success",
                "runs": runs,
            }
            results.append(manifest)
            with open(os.path.join(EXPECTED_DIR, f"{scene_id}.json"), "w") as fh:
                json.dump(manifest, fh, indent=2, sort_keys=True)
            print(f"{scene_id}: {list(runs.values())[0]['summary']['overall_posture']} "
                  f"{list(runs.values())[0]['summary']['score_value']} "
                  f"({list(runs.values())[0]['elapsed_ms']} ms)")

        svc.close()

    with open(os.path.join(EXPECTED_DIR, "all_scenes.json"), "w") as fh:
        json.dump(results, fh, indent=2, sort_keys=True)

    import platform
    import subprocess
    tshark_version = "unavailable"
    try:
        out = subprocess.run(["tshark", "--version"], capture_output=True, text=True, timeout=10)
        tshark_version = (out.stdout or "").splitlines()[0] if out.stdout else "unavailable"
    except Exception:
        pass
    env = {
        "generated_at_note": "timestamps below are wall-clock generation time, NOT part of "
                              "any deterministic claim -- assessment_id/report_sha256 are",
        "python": sys.version,
        "platform": platform.platform(),
        "tshark": tshark_version,
    }
    with open(os.path.join(ENV_DIR, "environment.json"), "w") as fh:
        json.dump(env, fh, indent=2, sort_keys=True)

    print("\nDone. Wrote manifests to demo/expected/, reports to demo/reports/, "
          "hashes to demo/hashes/, environment to demo/environment/.")


if __name__ == "__main__":
    main()
