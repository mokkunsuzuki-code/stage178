# MIT License © 2025 Motohiro Suzuki
"""
policy/key_policy.py  (Stage166)

KeyPolicy:
- Decide whether to use QKD material (evaluate_qkd)
- Decide whether to trigger rekey during a session (should_rekey)

Design goals:
- QKD can be UNAVAILABLE (outage/slow) -> protocol must continue (PQC-only)
- Rekey trigger depends on time and/or bytes since last rekey
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class QKDState(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class QKDMetrics:
    qber: Optional[float] = None
    chsh: Optional[float] = None


@dataclass(frozen=True)
class QKDDecision:
    allow_qkd: bool
    reason: str


@dataclass
class KeyPolicy:
    """
    Stage166 policy knobs

    Rekey triggers:
      - rekey_max_seconds: trigger if elapsed time exceeds this (>0)
      - rekey_max_bytes  : trigger if bytes since last rekey exceeds this (>0)

    QKD gating:
      - qber_max, chsh_min: quality thresholds
      - budget_high/budget_low: remaining budget thresholds
    """

    rekey_max_seconds: int = 60
    rekey_max_bytes: int = 1024 * 1024

    qber_max: float = 0.05
    chsh_min: float = 2.4

    budget_high: int = 32
    budget_low: int = 16

    def should_rekey(self, *, elapsed_sec: float, bytes_since_rekey: int) -> bool:
        """
        Stage166: policy-driven rekey decision.

        Returns True if:
          - elapsed_sec >= rekey_max_seconds (when rekey_max_seconds > 0), OR
          - bytes_since_rekey >= rekey_max_bytes (when rekey_max_bytes > 0)
        """
        try:
            e = float(elapsed_sec)
        except Exception:
            e = 0.0

        try:
            b = int(bytes_since_rekey)
        except Exception:
            b = 0

        if self.rekey_max_seconds and self.rekey_max_seconds > 0:
            if e >= float(self.rekey_max_seconds):
                return True

        if self.rekey_max_bytes and self.rekey_max_bytes > 0:
            if b >= int(self.rekey_max_bytes):
                return True

        return False

    def evaluate_qkd(
        self,
        *,
        qkd_state: QKDState,
        metrics: Optional[QKDMetrics],
        remaining_budget: int,
    ) -> QKDDecision:
        """
        Stage166: decide whether QKD bytes are permitted for this usage.

        Conservative rules:
          - If QKD is UNAVAILABLE -> deny (PQC-only)
          - If metrics provided:
              - qber must be <= qber_max (when qber is not None)
              - chsh must be >= chsh_min (when chsh is not None)
          - If remaining_budget is too low -> deny
        """
        # Availability
        if qkd_state != QKDState.AVAILABLE:
            return QKDDecision(False, "QKD unavailable")

        # Budget gating (simple, interpretable)
        try:
            rem = int(remaining_budget)
        except Exception:
            rem = 0

        if rem <= 0:
            return QKDDecision(False, "QKD budget exhausted")
        if rem < self.budget_low:
            return QKDDecision(False, f"QKD budget low (<{self.budget_low})")

        # Quality gating
        if metrics is not None:
            if metrics.qber is not None and float(metrics.qber) > float(self.qber_max):
                return QKDDecision(False, f"QKD qber too high (>{self.qber_max})")
            if metrics.chsh is not None and float(metrics.chsh) < float(self.chsh_min):
                return QKDDecision(False, f"QKD chsh too low (<{self.chsh_min})")

        return QKDDecision(True, "QKD permitted")
