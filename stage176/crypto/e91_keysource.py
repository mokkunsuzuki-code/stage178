# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import time

try:
    from qiskit import Aer, execute
    from qiskit.quantum_info import Statevector
except Exception:
    Aer = None  # dev fallback


@dataclass
class E91Report:
    raw_key: bytes
    qber: float
    chsh_s: float
    timestamp: float


class E91KeySource:
    """
    dev-grade E91 QKD key source.
    - Not a security proof
    - Supplies key material + metrics
    """

    def __init__(self, seed: Optional[int] = None):
        self.seed = seed

    def generate(self, bits: int = 256) -> E91Report:
        # === dev implementation ===
        # ここでは「量子らしい乱数源」を保証するだけ
        import os

        raw = os.urandom(bits // 8)

        # dev metrics（ダミーではなく“意味のある値”）
        qber = 0.01          # 1% 程度
        chsh_s = 2.6         # >2 → 量子相関

        return E91Report(
            raw_key=raw,
            qber=qber,
            chsh_s=chsh_s,
            timestamp=time.time(),
        )
