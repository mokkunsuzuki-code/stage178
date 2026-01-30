# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class QKDStatus(str, Enum):
    OK = "OK"
    UNAVAILABLE = "UNAVAILABLE"


class BudgetStatus(str, Enum):
    OK = "OK"
    DEPLETED = "DEPLETED"
    UNKNOWN = "UNKNOWN"


class QBERStatus(str, Enum):
    OK = "OK"
    EXCEEDED = "EXCEEDED"
    UNKNOWN = "UNKNOWN"


class FailoverMode(str, Enum):
    PQC_QKD = "PQC_QKD"
    PQC_ONLY = "PQC_ONLY"


class FailoverReason(str, Enum):
    QKD_UNAVAILABLE = "QKD_UNAVAILABLE"
    QBER_EXCEEDED = "QBER_EXCEEDED"
    BUDGET_DEPLETED = "BUDGET_DEPLETED"
    QBER_UNKNOWN = "QBER_UNKNOWN"
    BUDGET_UNKNOWN = "BUDGET_UNKNOWN"


@dataclass(frozen=True)
class FailoverDecision:
    mode: FailoverMode
    reason: Optional[FailoverReason] = None


@dataclass(frozen=True)
class FailoverPolicy:
    """
    Stage167-A Failover policy.

    Core idea:
    - If QKD is unavailable OR QBER exceeded OR budget depleted -> PQC_ONLY
    - If QBER/budget unknown -> treat as failover (conservative)
      (you can relax this later, but Stage167-A emphasizes fail-closed)
    """

    qber_max: float = 0.11
    qkd_min_budget_bytes: int = 32

    def decide(
        self,
        *,
        qkd_status: QKDStatus,
        qber: Optional[float],
        budget_bytes: Optional[int],
        qber_status: Optional[QBERStatus] = None,
        budget_status: Optional[BudgetStatus] = None,
    ) -> FailoverDecision:
        # 1) QKD unavailable
        if qkd_status == QKDStatus.UNAVAILABLE:
            return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.QKD_UNAVAILABLE)

        # 2) QBER handling
        if qber_status is not None:
            if qber_status == QBERStatus.EXCEEDED:
                return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.QBER_EXCEEDED)
            if qber_status == QBERStatus.UNKNOWN:
                return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.QBER_UNKNOWN)
        else:
            if qber is None:
                return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.QBER_UNKNOWN)
            if qber > self.qber_max:
                return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.QBER_EXCEEDED)

        # 3) Budget handling
        if budget_status is not None:
            if budget_status == BudgetStatus.DEPLETED:
                return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.BUDGET_DEPLETED)
            if budget_status == BudgetStatus.UNKNOWN:
                return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.BUDGET_UNKNOWN)
        else:
            if budget_bytes is None:
                return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.BUDGET_UNKNOWN)
            if budget_bytes < self.qkd_min_budget_bytes:
                return FailoverDecision(FailoverMode.PQC_ONLY, FailoverReason.BUDGET_DEPLETED)

        # Otherwise keep PQC+QKD
        return FailoverDecision(FailoverMode.PQC_QKD, None)

    @staticmethod
    def mode_str(mode: FailoverMode) -> str:
        return mode.value

    @staticmethod
    def reason_str(reason: Optional[FailoverReason]) -> Optional[str]:
        return None if reason is None else reason.value
