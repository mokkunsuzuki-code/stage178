#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

# --- robust project root (works both on host and in container) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

# Make imports stable in container/host
export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"

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

echo "[attack-02] waiting server to listen..."
deadline=$((SECONDS + 3))
while true; do
  if grep -q "listening on" "${SERVER_LOG}"; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    echo "[attack-02] [NG] server crashed before listen"
    tail -n 120 "${SERVER_LOG}" || true
    TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    cat > "${REPORT_JSON}" <<JSON
{"stage":176,"attack":"attack_02_replay_ack","ts_utc":"${TS_UTC}","expected":"FAIL_CLOSED","observed":"SERVER_CRASH_BEFORE_LISTEN","ok":false,"client_rc":1,"artifacts":{"server_log":"${SERVER_LOG}","client_log":"${CLIENT_LOG}"}}
JSON
    echo "[attack-02] wrote ${REPORT_JSON}"
    bash scripts/05_summarize.sh >/dev/null 2>&1 || true
    exit 1
  fi
  if [[ ${SECONDS} -ge ${deadline} ]]; then
    echo "[attack-02] [NG] server not ready (timeout)"
    tail -n 120 "${SERVER_LOG}" || true
    TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    cat > "${REPORT_JSON}" <<JSON
{"stage":176,"attack":"attack_02_replay_ack","ts_utc":"${TS_UTC}","expected":"FAIL_CLOSED","observed":"SERVER_NOT_READY","ok":false,"client_rc":1,"artifacts":{"server_log":"${SERVER_LOG}","client_log":"${CLIENT_LOG}"}}
JSON
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

if grep -q "REPLAY DETECTED" "${SERVER_LOG}"; then
  echo "[attack-02] [OK] replay detected (fail-closed)"
  TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  cat > "${REPORT_JSON}" <<JSON
{"stage":176,"attack":"attack_02_replay_ack","ts_utc":"${TS_UTC}","expected":"FAIL_CLOSED","observed":"FAIL_CLOSED_REPLAY_REJECTED","ok":true,"client_rc":${CLIENT_RC},"artifacts":{"server_log":"${SERVER_LOG}","client_log":"${CLIENT_LOG}"}}
JSON
  echo "[attack-02] wrote ${REPORT_JSON}"
  bash scripts/05_summarize.sh >/dev/null 2>&1 || true
  exit 0
fi

echo "[attack-02] [NG] replay not detected"
tail -n 120 "${SERVER_LOG}" || true
TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "${REPORT_JSON}" <<JSON
{"stage":176,"attack":"attack_02_replay_ack","ts_utc":"${TS_UTC}","expected":"FAIL_CLOSED","observed":"REPLAY_NOT_DETECTED","ok":false,"client_rc":${CLIENT_RC},"artifacts":{"server_log":"${SERVER_LOG}","client_log":"${CLIENT_LOG}"}}
JSON
echo "[attack-02] wrote ${REPORT_JSON}"
bash scripts/05_summarize.sh >/dev/null 2>&1 || true
exit 1
