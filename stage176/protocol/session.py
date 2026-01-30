# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from protocol.stage167_force import (
    QKDProbe,
    QKDFailoverReason,
    apply_stage167_force_case,
)


@dataclass
class RekeyQKDDecision:
    """
    What Stage167-A wants to evidence:
      - Whether we used QKD in the mix
      - If not used, which failover reason
      - Observed qber / remaining_budget
    """
    used_qkd: bool
    reason: str
    qber: Optional[float]
    remaining_budget_bytes: Optional[int]
    qkd_len: int


class ProtocolCore:
    """
    NOTE:
    This file shows the Stage167-A core logic (QKD rekey gating + evidence logs).
    Integrate the try_get_qkd_for_rekey() into your existing ProtocolCore if needed.
    """

    def __init__(self, cfg) -> None:
        self.cfg = cfg

    # --------------------------
    # Stage167-A: QKD probe + gating
    # --------------------------
    def _probe_qkd_material(self) -> QKDProbe:
        """
        Get QKD bytes and metadata from your QKD subsystem.

        In your project, this likely calls:
          - cfg.enable_qkd check
          - a KeySource (E91KeySource) or QKD service
          - returns qkd_bytes, qber, remaining_budget

        Here we implement a conservative baseline:
          - If QKD disabled -> unavailable
          - Otherwise -> (placeholder) unavailable by default
        """
        if not bool(getattr(self.cfg, "enable_qkd", False)):
            return QKDProbe(
                ok=False,
                reason=QKDFailoverReason.QKD_UNAVAILABLE,
                qkd_bytes=b"",
                qber=None,
                remaining_budget_bytes=None,
            )

        # ---- Replace this block with your real QKD fetch ----
        # Example: qkd_bytes, qber, remaining_budget = self.qkd_source.get_for_rekey(...)
        qkd_bytes = b""
        qber = None
        remaining_budget = 0
        # ----------------------------------------------------

        if not qkd_bytes:
            return QKDProbe(
                ok=False,
                reason=QKDFailoverReason.QKD_UNAVAILABLE,
                qkd_bytes=b"",
                qber=qber,
                remaining_budget_bytes=remaining_budget,
            )

        return QKDProbe(
            ok=True,
            reason=QKDFailoverReason.OK,
            qkd_bytes=qkd_bytes,
            qber=qber,
            remaining_budget_bytes=remaining_budget,
        )

    def try_get_qkd_for_rekey(self) -> Tuple[bytes, RekeyQKDDecision]:
        """
        Stage167-A “paper-grade” function.

        Returns:
          (qkd_bytes_to_mix, decision)

        Rules:
          - If forced case set -> override probe output deterministically
          - Else use real probe
          - Then apply policy gating:
              1) UNAVAILABLE if no qkd_bytes
              2) BUDGET_DEPLETED if remaining_budget < min
              3) QBER_EXCEEDED if qber > threshold
              else OK
        """
        base = self._probe_qkd_material()
        probe = apply_stage167_force_case(self.cfg, base)

        # ---- normalize fields ----
        qkd_bytes = probe.qkd_bytes or b""
        qber = probe.qber
        remaining = probe.remaining_budget_bytes

        # ---- policy thresholds ----
        qber_th = float(getattr(self.cfg, "qkd_qber_threshold", 0.11))
        min_budget = int(getattr(self.cfg, "qkd_min_budget_bytes", 32))

        # ---- gating ----
        if not qkd_bytes:
            decision = RekeyQKDDecision(
                used_qkd=False,
                reason=QKDFailoverReason.QKD_UNAVAILABLE,
                qber=qber,
                remaining_budget_bytes=remaining,
                qkd_len=0,
            )
            self._log_stage167_decision(decision)
            return b"", decision

        # Budget check (if remaining is known)
        if remaining is not None and remaining < min_budget:
            decision = RekeyQKDDecision(
                used_qkd=False,
                reason=QKDFailoverReason.BUDGET_DEPLETED,
                qber=qber,
                remaining_budget_bytes=remaining,
                qkd_len=len(qkd_bytes),
            )
            self._log_stage167_decision(decision)
            return b"", decision

        # QBER check (if qber is known)
        if qber is not None and qber > qber_th:
            decision = RekeyQKDDecision(
                used_qkd=False,
                reason=QKDFailoverReason.QBER_EXCEEDED,
                qber=qber,
                remaining_budget_bytes=remaining,
                qkd_len=len(qkd_bytes),
            )
            self._log_stage167_decision(decision)
            return b"", decision

        decision = RekeyQKDDecision(
            used_qkd=True,
            reason=QKDFailoverReason.OK,
            qber=qber,
            remaining_budget_bytes=remaining,
            qkd_len=len(qkd_bytes),
        )
        self._log_stage167_decision(decision)
        return qkd_bytes, decision

    def _log_stage167_decision(self, d: RekeyQKDDecision) -> None:
        """
        Evidence log line for Stage167-A.

        This line is what you want to quote in spec/paper screenshots:
          - reason: QKD_UNAVAILABLE / QBER_EXCEEDED / BUDGET_DEPLETED / OK
        """
        print(
            "[stage167-a] qkd_failover_decision "
            f"used_qkd={d.used_qkd} "
            f"reason={d.reason} "
            f"qber={d.qber} "
            f"remaining_budget_bytes={d.remaining_budget_bytes} "
            f"qkd_len={d.qkd_len}"
        )
