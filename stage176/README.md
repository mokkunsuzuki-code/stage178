# Stage176 — External PoC Package (Docker-first)
MIT License © 2025 Motohiro Suzuki

## Goal
Make QSP safe to evaluate by external parties (NICT/companies) with:
- reproducible runs (Docker)
- attack scenarios
- evidence logs
- fail-closed expected behavior

## 3-minute Quickstart
```bash
bash scripts/00_env_check.sh
bash scripts/01_build.sh
docker compose -f docker/docker-compose.yml up --abort-on-container-exit
Outputs:

out/logs/ raw logs

out/evidence/ collected evidence

out/reports/ summary

Expected Failures (Fail-Closed)
See: docs/Expected_Failures.md

Attack Scenarios
See: attack_scenarios/README.md

Notes
This PoC focuses on reproducibility + safe failure behaviors.
Rust/C++ interop is intentionally out-of-scope for Stage176.