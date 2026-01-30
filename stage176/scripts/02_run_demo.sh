#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

mkdir -p out/logs out/evidence out/reports

# Make /app/protocol importable for runners copied from stage167
export PYTHONPATH="/app:${PYTHONPATH:-}"

SERVER_PY="runners/run_server167.py"
CLIENT_PY="runners/run_client167.py"

if [ ! -f "$SERVER_PY" ]; then
  echo "[ERR] missing $SERVER_PY"
  echo "Hint: cp ../stage167/run_server167.py runners/"
  exit 1
fi

if [ ! -f "$CLIENT_PY" ]; then
  echo "[ERR] missing $CLIENT_PY"
  echo "Hint: copy client runner into runners/ (e.g., run_client167.py)"
  exit 1
fi

SERVER_LOG="out/logs/server167.log"
CLIENT_LOG="out/logs/client167.log"
DEMO_JSON="out/logs/demo.json"

rm -f "$SERVER_LOG" "$CLIENT_LOG" "$DEMO_JSON"

echo "[demo] start server in background..."
( python -u "$SERVER_PY" >"$SERVER_LOG" 2>&1 ) &
SERVER_PID=$!

cleanup() {
  echo "[demo] cleanup: stopping server pid=$SERVER_PID"
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# give server time to bind/listen
sleep 1

echo "[demo] run client..."
set +e
python -u "$CLIENT_PY" client >"$CLIENT_LOG" 2>&1
CLIENT_RC=$?
set -e

OK=0
if [ "$CLIENT_RC" -eq 0 ]; then
  OK=1
fi

# Write JSON evidence (single python call, no heredoc piping)
python - <<PY
import json, time, os

data = {
  "stage": 176,
  "case": "demo_real_runner167",
  "ok": bool(${OK}),
  "client_rc": int(${CLIENT_RC}),
  "ts_ms": int(time.time()*1000),
  "artifacts": {
    "server_log": "${SERVER_LOG}",
    "client_log": "${CLIENT_LOG}",
  },
}
os.makedirs(os.path.dirname("${DEMO_JSON}"), exist_ok=True)
with open("${DEMO_JSON}", "w", encoding="utf-8") as f:
  json.dump(data, f, separators=(",", ":"))
  f.write("\\n")
print(json.dumps(data, separators=(",", ":")))
PY

echo "[demo] wrote $DEMO_JSON"
echo "[OK] demo done"
