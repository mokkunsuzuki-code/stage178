#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"
export PYTHONUNBUFFERED=1

mkdir -p out/logs out/reports

SERVER_LOG="out/logs/server167_attack05.log"
CLIENT_LOG="out/logs/client167_attack05.log"
OUT_JSON="out/logs/attack_05_key_schedule_confusion.json"

: > "${SERVER_LOG}"
: > "${CLIENT_LOG}"

echo "[attack-05] start server in background..."
python -u runners/run_server167_attack05.py >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

cleanup() {
  echo "[attack-05] cleanup: stopping server pid=${SERVER_PID}"
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
  wait "${SERVER_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[attack-05] waiting server to listen..."
deadline=$((SECONDS + 3))
while true; do
  if grep -q "listening on" "${SERVER_LOG}"; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    echo "[attack-05] [NG] server crashed before listen"
    tail -n 120 "${SERVER_LOG}" || true
    TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    cat > "${OUT_JSON}" <<JSON
{"stage":176,"attack":"attack_05_key_schedule_confusion","ts_utc":"${TS_UTC}","expected":"FAIL_CLOSED","observed":"SERVER_CRASH_BEFORE_LISTEN","ok":false,"client_rc":1,"artifacts":{"server_log":"${SERVER_LOG}","client_log":"${CLIENT_LOG}"}}
JSON
    echo "[attack-05] wrote ${OUT_JSON}"
    bash scripts/05_summarize.sh >/dev/null 2>&1 || true
    exit 1
  fi
  if [[ ${SECONDS} -ge ${deadline} ]]; then
    echo "[attack-05] [NG] server not ready (timeout)"
    tail -n 120 "${SERVER_LOG}" || true
    TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    cat > "${OUT_JSON}" <<JSON
{"stage":176,"attack":"attack_05_key_schedule_confusion","ts_utc":"${TS_UTC}","expected":"FAIL_CLOSED","observed":"SERVER_NOT_READY","ok":false,"client_rc":1,"artifacts":{"server_log":"${SERVER_LOG}","client_log":"${CLIENT_LOG}"}}
JSON
    echo "[attack-05] wrote ${OUT_JSON}"
    bash scripts/05_summarize.sh >/dev/null 2>&1 || true
    exit 1
  fi
  sleep 0.05
done

echo "[attack-05] run client (ACK header epoch/seq confusion)..."
set +e
python -u runners/run_client167_attack05.py >"${CLIENT_LOG}" 2>&1
CLIENT_RC=$?
set -e

if grep -q "BAD REKEY ACK HEADER" "${SERVER_LOG}"; then
  OBSERVED="FAIL_CLOSED_BAD_ACK_HEADER_REJECTED"
  OK=true
  RC=0
  echo "[attack-05] [OK] bad ack header detected (fail-closed)"
else
  OBSERVED="BAD_ACK_HEADER_NOT_DETECTED"
  OK=false
  RC=1
  echo "[attack-05] [NG] bad ack header NOT detected"
fi

TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "${OUT_JSON}" <<JSON
{"stage":176,"attack":"attack_05_key_schedule_confusion","ts_utc":"${TS_UTC}","expected":"FAIL_CLOSED","observed":"${OBSERVED}","ok":${OK},"client_rc":${CLIENT_RC},"artifacts":{"server_log":"${SERVER_LOG}","client_log":"${CLIENT_LOG}"}}
JSON

echo "[attack-05] wrote ${OUT_JSON}"
bash scripts/05_summarize.sh >/dev/null 2>&1 || true
exit "${RC}"
