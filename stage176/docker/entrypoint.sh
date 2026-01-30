#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

MODE="${1:-help}"

case "$MODE" in
  demo)
    bash scripts/02_run_demo.sh
    ;;
  matrix)
    bash scripts/03_run_matrix.sh
    ;;
  attack-01)
    bash attack_scenarios/attack_01_tamper_sig/run.sh
    ;;
  attack-02)
    bash attack_scenarios/attack_02_replay/run.sh
    ;;
  attack-03)
    bash attack_scenarios/attack_03_epoch_rollback/run.sh
    ;;
  test)
    python -m pytest -q || {
      rc=$?
      if [[ $rc -eq 5 ]]; then
        echo "[pytest] no tests collected -> treat as OK"
        exit 0
      fi
      exit $rc
    }
    ;;
  help|*)
    echo "Usage:"
    echo "  demo      : run minimal happy-path demo"
    echo "  matrix    : run demo + attacks + pytest + summary"
    echo "  attack-01 : tampered ACK confirm -> fail-closed"
    echo "  attack-02 : replay ACK after commit -> fail-closed"
    echo "  attack-03 : epoch rollback attempt -> fail-closed"
    echo "  test      : run pytest"
    ;;
esac
