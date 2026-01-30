#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail
docker compose -f docker/docker-compose.yml down -v || true
echo "[OK] compose down"
