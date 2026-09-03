#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$ROOT_DIR/.venv-wsl/bin/python"

if [[ ! -x "$PYTHON" ]]; then
    echo "Expected WSL virtual environment at .venv-wsl/bin/python" >&2
    exit 1
fi

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

cd "$ROOT_DIR"

PORT="$($PYTHON - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

export CAPULA_BASE_URL="http://127.0.0.1:${PORT}"
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

"$PYTHON" -m uvicorn server.src.main:app --host 127.0.0.1 --port "$PORT" >/tmp/capula-demo-uvicorn.log 2>&1 &
SERVER_PID=$!

for _ in {1..60}; do
    if "$PYTHON" - <<'PY' >/dev/null 2>&1
import os
from urllib.request import urlopen

with urlopen(os.environ["CAPULA_BASE_URL"] + "/openapi.json", timeout=1):
    pass
PY
    then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        cat /tmp/capula-demo-uvicorn.log >&2
        exit 1
    fi
    sleep 1
done

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat /tmp/capula-demo-uvicorn.log >&2
    exit 1
fi

"$PYTHON" demo/demo.py "$@"