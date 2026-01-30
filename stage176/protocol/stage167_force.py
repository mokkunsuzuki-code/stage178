# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


class QKDFailoverReason:
    QKD_UNAVAILABLE = "QKD_UNAVAILABLE"
    QBER_EXCEEDED = "QBER_EXCEEDED"
    BUDGET_DEPLETED = "BUDGET_DEPLETED"
    OK = "OK"


@dataclass(frozen=True)
class QKDProbe:
    """
    Result of attempting to obtain/validate QKD material for (re)key mixing.
    """
    ok: bool
    reason: str
    qkd_bytes: bytes
    qber: Optional[float]
    remaining_budget_bytes: Optional[int]


def _get_force_case(cfg) -> str:
    """
    Priority:
      1) cfg.stage167_force_case (explicit programmatic override)
      2) env QSP_STAGE167_FORCE
      3) "" (no force)
    """
    case = (getattr(cfg, "stage167_force_case", None) or "").strip()
    if case:
        return case
    return (os.environ.get("QSP_STAGE167_FORCE", "") or "").strip()


def apply_stage167_force_case(cfg, base: QKDProbe) -> QKDProbe:
    """
    If force case is set, override the probe result so that Stage167-A can
    deterministically generate all evidence logs.

    Supported:
      - QKD_UNAVAILABLE
      - QBER_EXCEEDED
      - BUDGET_DEPLETED

    Set via either:
      - cfg.stage167_force_case = "..."
      - env QSP_STAGE167_FORCE="..."
    """
    case = _get_force_case(cfg)
    if not case:
        return base

    if case == QKDFailoverReason.QKD_UNAVAILABLE:
        return QKDProbe(
            ok=False,
            reason=QKDFailoverReason.QKD_UNAVAILABLE,
            qkd_bytes=b"",
            qber=None,
            remaining_budget_bytes=None,
        )

    # For the other two cases, we want QKD "available" (qkd_bytes present),
    # but fail due to policy checks.
    dummy_len = int(getattr(cfg, "stage167_dummy_qkd_len", 32))
    dummy_qkd = bytes([0xA7]) * max(0, dummy_len)

    if case == QKDFailoverReason.QBER_EXCEEDED:
        bad_qber = float(getattr(cfg, "stage167_dummy_qber_bad", 0.25))
        ok_budget = int(getattr(cfg, "stage167_dummy_budget_ok", 1024))
        return QKDProbe(
            ok=False,
            reason=QKDFailoverReason.QBER_EXCEEDED,
            qkd_bytes=dummy_qkd,
            qber=bad_qber,
            remaining_budget_bytes=ok_budget,
        )

    if case == QKDFailoverReason.BUDGET_DEPLETED:
        ok_qber = float(getattr(cfg, "stage167_dummy_qber_ok", 0.02))
        bad_budget = int(getattr(cfg, "stage167_dummy_budget_bad", 0))
        return QKDProbe(
            ok=False,
            reason=QKDFailoverReason.BUDGET_DEPLETED,
            qkd_bytes=dummy_qkd,
            qber=ok_qber,
            remaining_budget_bytes=bad_budget,
        )

    # Unknown value: do not break runtime, just return base.
    return base
