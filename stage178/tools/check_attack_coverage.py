# MIT License © 2025 Motohiro Suzuki
"""
tools/check_attack_coverage.py

Ensures that every attack defined in attacks/attack_table.yml
has corresponding executable evidence (tests + scripts).

If any attack is missing evidence, CI MUST FAIL.

This makes attack coverage non-optional and non-drifting.
"""

import sys
from pathlib import Path
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ATTACK_TABLE = PROJECT_ROOT / "attacks" / "attack_table.yml"


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def main():
    if not ATTACK_TABLE.exists():
        fail(f"attack table not found: {ATTACK_TABLE}")

    data = yaml.safe_load(ATTACK_TABLE.read_text())

    attacks = data.get("attacks", [])
    if not attacks:
        fail("no attacks defined in attack_table.yml")

    missing = []

    for attack in attacks:
        attack_id = attack.get("attack_id")
        test_ref = attack.get("evidence_test")
        script_ref = attack.get("evidence_script")

        if not attack_id:
            missing.append("attack without attack_id")
            continue

        # Check test existence
        if test_ref:
            test_path = test_ref.split("::")[0]
            if not (PROJECT_ROOT / test_path).exists():
                missing.append(f"{attack_id}: missing test {test_path}")
        else:
            missing.append(f"{attack_id}: evidence_test not defined")

        # Check script existence
        if script_ref:
            if not (PROJECT_ROOT / script_ref).exists():
                missing.append(f"{attack_id}: missing script {script_ref}")
        else:
            missing.append(f"{attack_id}: evidence_script not defined")

    if missing:
        print("[FAIL] attack coverage incomplete:")
        for m in missing:
            print(f"  - {m}")
        sys.exit(1)

    print(f"[OK] attack coverage complete ({len(attacks)} attacks)")


if __name__ == "__main__":
    main()
