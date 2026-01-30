# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import hashlib
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
    Stage167-A core logic (QKD rekey gating + evidence logs).

    NOTE (Stage167-B demo):
      This implementation produces deterministic QKD bytes from cfg.qkd_seed,
      so you can demonstrate:
        - used_qkd=True
        - qkd_len>0
        - different rekey session_key due to QKD mix
      This is NOT a secure QKD source. It is for reproducible testing only.
    """

    def __init__(self, cfg) -> None:
        self.cfg = cfg

    def _probe_qkd_material(self) -> QKDProbe:
        """
        Deterministic probe:
          - If QKD disabled -> unavailable
          - Else derive qkd_bytes from cfg.qkd_seed via SHA256
          - Provide dummy qber / remaining budget for gating
        """
        if not bool(getattr(self.cfg, "enable_qkd", False)):
            return QKDProbe(
                ok=False,
                reason=QKDFailoverReason.QKD_UNAVAILABLE,
                qkd_bytes=b"",
                qber=None,
                remaining_budget_bytes=None,
            )

        # Deterministic "QKD-like" bytes (TEST ONLY)
        seed = getattr(self.cfg, "qkd_seed", None)
        if seed is None:
            # still deterministic-ish: treat as unavailable unless seed is set
            return QKDProbe(
                ok=False,
                reason=QKDFailoverReason.QKD_UNAVAILABLE,
                qkd_bytes=b"",
                qber=None,
                remaining_budget_bytes=0,
            )

        # derive 32 bytes from seed
        seed_bytes = str(seed).encode("utf-8")
        qkd_bytes = hashlib.sha256(b"stage167-demo-qkd|" + seed_bytes).digest()

        # Dummy metrics (chosen to PASS default thresholds)
        qber = 0.01
        remaining_budget = 1024

        return QKDProbe(
            ok=True,
            reason=QKDFailoverReason.OK,
            qkd_bytes=qkd_bytes,
            qber=qber,
            remaining_budget_bytes=remaining_budget,
        )

    def try_get_qkd_for_rekey(self) -> Tuple[bytes, RekeyQKDDecision]:
        """
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

        qkd_bytes = probe.qkd_bytes or b""
        qber = probe.qber
        remaining = probe.remaining_budget_bytes

        qber_th = float(getattr(self.cfg, "qkd_qber_threshold", 0.11))
        min_budget = int(getattr(self.cfg, "qkd_min_budget_bytes", 32))

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
        print(
            "[stage167-a] qkd_failover_decision "
            f"used_qkd={d.used_qkd} "
            f"reason={d.reason} "
            f"qber={d.qber} "
            f"remaining_budget_bytes={d.remaining_budget_bytes} "
            f"qkd_len={d.qkd_len}"
        )
