#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

mkdir -p out/evidence

# evidence に「提出用に必要な最小セット」を集約
# - raw logs
# - summary
# - config snapshot (存在すれば)
# - version info
echo "[collect] start"

# 1) logs
if [ -d out/logs ]; then
  rm -rf out/evidence/logs
  cp -R out/logs out/evidence/logs
  echo "[collect] copied logs -> out/evidence/logs"
else
  echo "[collect] no out/logs found (skip)"
fi

# 2) reports
if [ -d out/reports ]; then
  rm -rf out/evidence/reports
  cp -R out/reports out/evidence/reports
  echo "[collect] copied reports -> out/evidence/reports"
else
  echo "[collect] no out/reports found (skip)"
fi

# 3) config snapshot (optional)
if [ -d config ]; then
  rm -rf out/evidence/config
  cp -R config out/evidence/config
  echo "[collect] copied config -> out/evidence/config"
fi

# 4) docker + git info (best-effort)
{
  echo "stage=176"
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "docker_version=$(docker --version 2>/dev/null || true)"
  echo "compose_version=$(docker compose version 2>/dev/null || true)"
  echo "git_head=$(git rev-parse HEAD 2>/dev/null || true)"
  echo "git_status=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') files_changed"
} > out/evidence/env_info.txt

echo "[collect] wrote out/evidence/env_info.txt"
echo "[OK] collect complete"
