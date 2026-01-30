#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

mkdir -p out/logs out/reports

SERVER_LOG="out/logs/server167_attack03.log"
CLIENT_LOG="out/logs/client167_attack03.log"
OUT_JSON="out/logs/attack_03_epoch_rollback.json"

echo "[attack-03] start server in background..."
PYTHONPATH="/app" python -u runners/run_server167_attack03.py >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

cleanup() {
  echo "[attack-03] cleanup: stopping server pid=${SERVER_PID}"
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
  wait "${SERVER_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# server ready wait (simple)
sleep 0.2

echo "[attack-03] run client with epoch rollback ACK AFTER COMMIT (QSP_ATTACK03_EPOCH_ROLLBACK=1)..."
set +e
PYTHONPATH="/app" QSP_ATTACK03_EPOCH_ROLLBACK=1 python -u runners/run_client167_attack03.py >"${CLIENT_LOG}" 2>&1
CLIENT_RC=$?
set -e

# Determine detection by server evidence line
if grep -q "EPOCH ROLLBACK DETECTED" "${SERVER_LOG}"; then
  OBSERVED="FAIL_CLOSED_EPOCH_ROLLBACK_REJECTED"
  OK=true
  RC=0
  echo "[attack-03] [OK] epoch rollback detected (fail-closed)"
else
  OBSERVED="EPOCH_ROLLBACK_NOT_DETECTED"
  OK=false
  RC=1
  echo "[attack-03] [NG] attack-03 failed (epoch rollback not detected)"
fi

TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "${OUT_JSON}" <<JSON
{"stage":176,"attack":"attack_03_epoch_rollback","ts_utc":"${TS_UTC}","expected":"FAIL_CLOSED","observed":"${OBSERVED}","ok":${OK},"client_rc":${CLIENT_RC},"artifacts":{"server_log":"${SERVER_LOG}","client_log":"${CLIENT_LOG}"}}
JSON

echo "[attack-03] wrote ${OUT_JSON}"

# refresh summary
bash scripts/05_summarize.sh

exit "${RC}"
