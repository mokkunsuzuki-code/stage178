#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

# docker compose の新旧を吸収
if docker compose version >/dev/null 2>&1; then
  docker compose -f docker/docker-compose.yml build
else
  docker-compose -f docker/docker-compose.yml build
fi

echo "[OK] build complete"
