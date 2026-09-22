#!/bin/sh
# Starts the backend + dashboard for the demo. Loopback only, no authentication (ADR-0011) --
# do not bind to a shared network.
set -eu
cd "$(dirname "$0")/../.."
PORT="${1:-8000}"
DATA_DIR="${2:-./securemailscope-data}"
echo "Starting SecureMailScope backend on http://127.0.0.1:${PORT} (data dir: ${DATA_DIR})"
echo "Dashboard will be at http://127.0.0.1:${PORT}/dashboard/"
PYTHONPATH=src python3 -m securemailscope.backend --port "${PORT}" --data-dir "${DATA_DIR}"
