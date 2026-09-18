#!/usr/bin/env bash
# NetProof - platform-neutral startup script.
#   ./run.sh            starts the server on 0.0.0.0:8000
#   NETPROOF_HOST=x NETPROOF_PORT=y ./run.sh   overrides host/port
#
# Requires: python3 with the requirements installed (bootstrap with your venv
# tool of choice, or use the Docker image instead).
set -euo pipefail

cd "$(dirname "$0")"

HOST="${NETPROOF_HOST:-127.0.0.1}"
PORT="${NETPROOF_PORT:-8000}"
export NETPROOF_DB="${NETPROOF_DB:-$PWD/backend/data/netproof.db}"

# Prefer a local venv if present (mirrors run.ps1), else system python3.
if [ -x "lib/venv/bin/python" ]; then
    PY=lib/venv/bin/python
else
    PY="${NETPROOF_PYTHON:-python3}"
fi

echo "[NetProof] starting on http://${HOST}:${PORT}"
exec "$PY" -m uvicorn main:app --host "$HOST" --port "$PORT" "$@"