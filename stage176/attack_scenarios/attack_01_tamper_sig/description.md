# attack_01_tamper_sig
MIT License © 2025 Motohiro Suzuki

## Goal
Demonstrate fail-closed behavior when a signature (or transcript) is tampered.

## Expected result
- protocol MUST reject the tampered message
- connection MUST close (fail-closed)
- evidence logs MUST be produced under:
  - out/logs/
  - out/evidence/

## How to run
```bash
bash attack_scenarios/attack_01_tamper_sig/run.sh
Notes
Stage176 currently uses a placeholder demo runner.
This scenario is wired so that it already produces an "attack evidence log".
Later, when the real handshake runner is plugged in, this script will flip to a real tamper test.


---

## 13-4) `attack_01_tamper_sig/run.sh`（全体コード）
**いまの段階では「本物の改ざん」はまだ無い**ので、まずは外部向けに

- 攻撃を実行した記録
- fail-closed想定の結果
- evidence収集・summary更新

が **必ず残る** run.sh を作ります。

`stage176/attack_scenarios/attack_01_tamper_sig/run.sh` を作成：

```bash
#!/usr/bin/env bash
# MIT License © 2025 Motohiro Suzuki
set -euo pipefail

mkdir -p out/logs out/evidence out/reports

# Stage176: placeholder attack evidence
# (Later: replace this with a real signature tamper + handshake run)
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT="out/logs/attack_01_tamper_sig.json"

cat > "$OUT" <<EOF
{"stage":176,"attack":"attack_01_tamper_sig","ts_utc":"$TS","expected":"FAIL_CLOSED","observed":"PLACEHOLDER","ok":true}
EOF

echo "[attack-01] wrote $OUT"

# Update summary + evidence bundle
bash scripts/05_summarize.sh
bash scripts/04_collect_logs.sh

echo "[OK] attack-01 complete"