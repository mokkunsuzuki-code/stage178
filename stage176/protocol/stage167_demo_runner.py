# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


def _ensure_project_root_on_syspath() -> Path:
    """
    Make imports work regardless of where this script is executed from.

    We detect a "project root" as a directory that contains "protocol/".
    Common layouts:
      - project_root/stage167_demo_runner.py
      - project_root/protocol/stage167_demo_runner.py

    Then we add that project_root to sys.path so that:
      import protocol.xxx
    works reliably.
    """
    here = Path(__file__).resolve().parent

    # Case 1: script is in project root and project root contains protocol/
    if (here / "protocol").is_dir():
        project_root = here
    # Case 2: script is inside protocol/ and parent contains protocol/
    elif (here.name == "protocol") and (here.parent / "protocol").is_dir():
        project_root = here.parent
    # Fallback: try parent anyway
    elif (here.parent / "protocol").is_dir():
        project_root = here.parent
    else:
        project_root = here  # last resort

    sys.path.insert(0, str(project_root))
    return project_root


def _make_config_for_demo() -> Any:
    """
    Project-specific config factory.
    """
    try:
        from protocol.config import ProtocolConfig
        from crypto.algorithms import AlgorithmSuite
    except Exception as e:
        print("[demo] ERROR: failed to import ProtocolConfig / AlgorithmSuite.")
        print("        Check that these exist relative to project root:")
        print("          - protocol/config.py (ProtocolConfig)")
        print("          - crypto/algorithms.py (AlgorithmSuite)")
        print(f"        Details: {e}")
        raise

    suite = AlgorithmSuite(
        supported_sigs=["ed25519"],
        supported_kems=["toy_kem"],
        supported_aeads=["aes-gcm"],
    )

    cfg = ProtocolConfig(
        suite=suite,
        sig_alg="ed25519",
        kem_alg="toy_kem",
        key_len=32,
        enable_qkd=True,
        qkd_seed=1234,
        qkd_qber_threshold=0.11,
        qkd_min_budget_bytes=32,
        stage167_force_case=None,
    )
    return cfg


def _make_core(cfg: Any) -> Any:
    try:
        from protocol.session import ProtocolCore
    except Exception as e:
        print("[demo] ERROR: failed to import ProtocolCore from protocol.session")
        print("        Please ensure protocol/session.py exports ProtocolCore.")
        print(f"        Details: {e}")
        raise
    return ProtocolCore(cfg)


def run_all_three_cases_once() -> int:
    cases = [
        "QKD_UNAVAILABLE",
        "QBER_EXCEEDED",
        "BUDGET_DEPLETED",
    ]

    project_root = _ensure_project_root_on_syspath()

    print("=== Stage167-A Demo Runner (3 cases / single run) ===")
    print("This runner prints three evidence logs in one execution.")
    print("-----------------------------------------------------")
    print(f"[demo] detected project_root = {project_root}")

    for idx, case in enumerate(cases, start=1):
        cfg = _make_config_for_demo()
        cfg.stage167_force_case = case

        core = _make_core(cfg)

        print(f"\n--- Case {idx}/3: stage167_force_case={case} ---")

        try:
            qkd_bytes, decision = core.try_get_qkd_for_rekey()
        except Exception as e:
            print("[demo] ERROR: try_get_qkd_for_rekey() raised exception:")
            print(f"       {e}")
            return 1

        reason = getattr(decision, "reason", None)
        used_qkd = getattr(decision, "used_qkd", None)
        qber = getattr(decision, "qber", None)
        remaining = getattr(decision, "remaining_budget_bytes", None)
        mixed_len = len(qkd_bytes) if isinstance(qkd_bytes, (bytes, bytearray)) else None

        print(
            "[demo] summary "
            f"used_qkd={used_qkd} "
            f"reason={reason} "
            f"qber={qber} "
            f"remaining_budget_bytes={remaining} "
            f"mixed_qkd_len={mixed_len}"
        )

        if reason != case:
            print("[demo] FAIL: reason mismatch!")
            print(f"       expected reason={case}, got reason={reason}")
            return 2

    print("\n=== DONE: all 3 Stage167-A cases produced expected reasons ===")
    return 0


if __name__ == "__main__":
    try:
        rc = run_all_three_cases_once()
    except Exception:
        rc = 99
    sys.exit(rc)
