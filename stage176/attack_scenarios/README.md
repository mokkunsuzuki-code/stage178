# Stage176 Attack Scenarios
MIT License © 2025 Motohiro Suzuki

This directory contains reproducible attack scripts for external PoC evaluation.
Each scenario MUST:
- be runnable by a single command
- leave evidence logs in `out/logs/`
- demonstrate fail-closed behavior

## Scenarios
- attack_01_tamper_sig: tamper signature / transcript -> expected FAIL-CLOSED
