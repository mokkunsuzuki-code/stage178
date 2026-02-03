# MIT License © 2025 Motohiro Suzuki
"""
attack_scenarios/attack_06_downgrade/runner.py

Stage178-B Attack A-06: downgrade detected

Demonstration:
- handshake pins mode="PQC+QKD"
- attacker sends REKEY with mode="PQC_ONLY"
Expected: fail-closed "downgrade detected"

Exit code:
- 0 if rejected correctly
- 1 otherwise
"""

from qsp.minicore import MiniCore, ProtocolViolation


def main() -> int:
    c = MiniCore()
    c.accept_frame(
        {"type": "HANDSHAKE_DONE", "session_id": 6060, "epoch": 1, "mode": "PQC+QKD", "payload": b""}
    )

    try:
        c.accept_frame(
            {"type": "REKEY", "session_id": 6060, "epoch": 2, "mode": "PQC_ONLY", "payload": b"x"}
        )
    except ProtocolViolation as e:
        msg = str(e)
        if "downgrade detected" in msg:
            print("[OK] downgrade rejected:", msg)
            return 0
        print("[FAIL] rejected, but unexpected reason:", msg)
        return 1

    print("[FAIL] downgrade accepted (should have been rejected)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
