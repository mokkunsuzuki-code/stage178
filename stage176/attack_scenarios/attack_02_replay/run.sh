#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

# --- robust project root (works both on host and in container) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

mkdir -p out/logs out/reports

SERVER_LOG="out/logs/server167_attack02.log"
CLIENT_LOG="out/logs/client167_attack02.log"
REPORT_JSON="out/logs/attack_02_replay.json"

: > "${SERVER_LOG}"
: > "${CLIENT_LOG}"

echo "[attack-02] start server in background..."
python -u runners/run_server167.py >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

cleanup() {
  echo "[attack-02] cleanup: stopping server pid=${SERVER_PID}"
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
  wait "${SERVER_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---- Wait until server is ready (log OR port-open evidence) ----
echo "[attack-02] waiting server to listen..."
deadline=$((SECONDS + 15))   # ★5秒→15秒（CI/コンテナ揺れを潰す）

while true; do
  # (A) server wrote the listening line
  if grep -q "listening on" "${SERVER_LOG}"; then
    break
  fi

  # (B) server process already died -> crash evidence
  if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    echo "[attack-02] [NG] server crashed before ready"
    echo "[attack-02] --- server log tail ---"
    tail -n 80 "${SERVER_LOG}" || true

    python - <<PY > "${REPORT_JSON}"
import json, time
obj = {
  "stage": 176,
  "attack": "attack_02_replay_ack",
  "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "expected": "FAIL_CLOSED",
  "observed": "SERVER_CRASHED_BEFORE_READY",
  "ok": False,
  "client_rc": 1,
  "artifacts": {"server_log": "${SERVER_LOG}", "client_log": "${CLIENT_LOG}"},
}
print(json.dumps(obj))
PY
    echo "[attack-02] wrote ${REPORT_JSON}"
    bash scripts/05_summarize.sh >/dev/null 2>&1 || true
    exit 1
  fi

  # (C) timeout
  if (( SECONDS >= deadline )); then
    echo "[attack-02] [NG] server not ready (timeout)"
    echo "[attack-02] --- server log tail ---"
    tail -n 80 "${SERVER_LOG}" || true

    python - <<PY > "${REPORT_JSON}"
import json, time
obj = {
  "stage": 176,
  "attack": "attack_02_replay_ack",
  "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "expected": "FAIL_CLOSED",
  "observed": "SERVER_NOT_READY",
  "ok": False,
  "client_rc": 1,
  "artifacts": {"server_log": "${SERVER_LOG}", "client_log": "${CLIENT_LOG}"},
}
print(json.dumps(obj))
PY
    echo "[attack-02] wrote ${REPORT_JSON}"
    bash scripts/05_summarize.sh >/dev/null 2>&1 || true
    exit 1
  fi

  sleep 0.05
done

echo "[attack-02] run client with replayed ACK AFTER COMMIT (QSP_ATTACK02_REPLAY_ACK=1)..."
set +e
QSP_ATTACK02_REPLAY_ACK=1 python -u runners/run_client167.py >"${CLIENT_LOG}" 2>&1
CLIENT_RC=$?
set -e

# Give server time to flush
sleep 0.2

# ---- Determine outcome from server log ----
if grep -q "REPLAY DETECTED" "${SERVER_LOG}"; then
  echo "[attack-02] [OK] replay detected (fail-closed)"
  python - <<PY > "${REPORT_JSON}"
import json, time
obj = {
  "stage": 176,
  "attack": "attack_02_replay_ack",
  "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "expected": "FAIL_CLOSED",
  "observed": "FAIL_CLOSED_REPLAY_REJECTED",
  "ok": True,
  "client_rc": ${CLIENT_RC},
  "artifacts": {"server_log": "${SERVER_LOG}", "client_log": "${CLIENT_LOG}"},
}
print(json.dumps(obj))
PY
  echo "[attack-02] wrote ${REPORT_JSON}"
  bash scripts/05_summarize.sh >/dev/null 2>&1 || true
  exit 0
else
  echo "[attack-02] [NG] replay not detected"
  echo "[attack-02] --- server log tail ---"
  tail -n 80 "${SERVER_LOG}" || true

  python - <<PY > "${REPORT_JSON}"
import json, time
obj = {
  "stage": 176,
  "attack": "attack_02_replay_ack",
  "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "expected": "FAIL_CLOSED",
  "observed": "REPLAY_NOT_DETECTED",
  "ok": False,
  "client_rc": ${CLIENT_RC},
  "artifacts": {"server_log": "${SERVER_LOG}", "client_log": "${CLIENT_LOG}"},
}
print(json.dumps(obj))
PY
  echo "[attack-02] wrote ${REPORT_JSON}"
  bash scripts/05_summarize.sh >/dev/null 2>&1 || true
  exit 1
fi
