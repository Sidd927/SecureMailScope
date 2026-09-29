#!/bin/sh
# Submits one demo scene's capture through the real analysis pipeline and prints the
# resulting posture/score, without needing the backend server running.
#
# Usage: bash demo/commands/run_scene.sh <scene_id> [--ai]
set -eu
cd "$(dirname "$0")/../.."
SCENE="${1:?usage: run_scene.sh <scene_id> [--ai]}"
AI_FLAG="False"
if [ "${2:-}" = "--ai" ]; then AI_FLAG="True"; fi

CAPTURE="demo/captures/${SCENE}.pcap"
if [ ! -e "${CAPTURE}" ]; then
  echo "No such scene capture: ${CAPTURE}" >&2
  echo "Available scenes:" >&2
  ls demo/captures/*.pcap | xargs -n1 basename | sed 's/\.pcap$//' >&2
  exit 1
fi

PYTHONPATH=src python3 - "${CAPTURE}" "${AI_FLAG}" <<'PY'
import sys, tempfile, os
sys.path.insert(0, "src")
from securemailscope.backend.service import AnalysisService

capture, ai_flag = sys.argv[1], sys.argv[2] == "True"
with tempfile.TemporaryDirectory() as tmp:
    svc = AnalysisService(os.path.join(tmp, "data"))
    sub = svc.submit_path(capture, ai_enabled=ai_flag)
    a = svc.get_assessment(sub.run.run_id)
    print(f"capture:  {capture}")
    print(f"ai:       {ai_flag}")
    print(f"posture:  {a['overall_posture']}")
    print(f"score:    {(a.get('score') or {}).get('value')}")
    print(f"run_id:   {sub.run.run_id}")
    svc.close()
PY
