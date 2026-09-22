#!/bin/sh
# Pre-demo sanity check. Read-only: checks the environment is ready without starting
# anything or writing anything (other than a scratch write-permission probe, cleaned up
# immediately). Intentionally small -- this checks exactly what docs/finalization/04
# through 13 identified as real failure points, nothing speculative.
set -u
cd "$(dirname "$0")/../.."
FAIL=0

check() {
  DESC="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  OK   $DESC"
  else
    echo "  FAIL $DESC"
    FAIL=1
  fi
}

echo "SecureMailScope demo preflight"
echo "================================"

echo "-- Python --"
PYVER=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null)
if [ -n "${PYVER:-}" ]; then
  echo "  OK   python3 found: ${PYVER}"
  case "$PYVER" in
    3.[0-8].*|2.*) echo "  FAIL python3 version ${PYVER} is below the required 3.9"; FAIL=1 ;;
  esac
else
  echo "  FAIL python3 not found on PATH"
  FAIL=1
fi

echo "-- TShark --"
TVER=$(tshark --version 2>/dev/null | head -1)
if [ -n "${TVER:-}" ]; then
  echo "  OK   ${TVER}"
else
  echo "  FAIL tshark not found on PATH -- this is a hard dependency, no fallback exists"
  FAIL=1
fi

echo "-- Git / release identity --"
GITTAG=$(git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD 2>/dev/null)
echo "  ..   current checkout: ${GITTAG:-unknown}"
if git merge-base --is-ancestor v0.6.0-phase11 HEAD 2>/dev/null; then
  echo "  OK   v0.6.0-phase11 is an ancestor of the current checkout"
else
  echo "  FAIL v0.6.0-phase11 is not an ancestor of the current checkout -- wrong branch?"
  FAIL=1
fi

echo "-- Demo captures present --"
for f in demo/captures/*.pcap; do
  [ -e "$f" ] || continue
  check "$(basename "$f")" test -s "$f"
done

echo "-- Write permission (data directory) --"
PROBE="./securemailscope-data/.preflight-probe"
if mkdir -p "$(dirname "$PROBE")" 2>/dev/null && touch "$PROBE" 2>/dev/null; then
  echo "  OK   can write to ./securemailscope-data"
  rm -f "$PROBE"
else
  echo "  FAIL cannot write to ./securemailscope-data"
  FAIL=1
fi

echo "-- Port 8000 --"
if command -v lsof >/dev/null 2>&1 && lsof -i ":8000" >/dev/null 2>&1; then
  echo "  WARN port 8000 already in use -- start the demo with a different --port"
else
  echo "  OK   port 8000 appears free"
fi

echo "-- Optional extras (backend + reporting) --"
PYTHONPATH=src python3 -c "import fastapi, pydantic, uvicorn" >/dev/null 2>&1 \
  && echo "  OK   backend extras (fastapi/pydantic/uvicorn) importable" \
  || echo "  WARN backend extras not installed -- dashboard/API demo will not start (pip install per SS2 of the runbook)"
PYTHONPATH=src python3 -c "import reportlab" >/dev/null 2>&1 \
  && echo "  OK   reportlab importable (PDF reports available)" \
  || echo "  WARN reportlab not installed -- PDF export will not work; JSON and HTML are unaffected"

echo "================================"
if [ "$FAIL" -eq 0 ]; then
  echo "READY."
  exit 0
else
  echo "NOT READY -- see FAIL lines above."
  exit 1
fi
