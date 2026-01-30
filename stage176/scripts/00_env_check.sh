#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

command -v docker >/dev/null 2>&1 || { echo "[ERR] docker not found"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "[ERR] docker command not available"; exit 1; }

# docker compose は新旧があるので両方チェック
if docker compose version >/dev/null 2>&1; then
  echo "[OK] docker compose (plugin) available"
elif command -v docker-compose >/dev/null 2>&1; then
  echo "[OK] docker-compose (legacy) available"
else
  echo "[ERR] docker compose not found (need 'docker compose' or 'docker-compose')"
  exit 1
fi

echo "[OK] environment looks good"
docker --version
docker compose version 2>/dev/null || docker-compose --version
