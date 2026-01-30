# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class QKDConfig:
    enabled: bool = False
    source: Optional[str] = None
    seed: Optional[int] = None


class ProtocolConfig:
    """
    Stage167-B compatibility ProtocolConfig.

    Legacy:
      - enable_qkd, qkd_seed
    Unified:
      - qkd.enabled, qkd.source, qkd.seed
    """

    def __init__(
        self,
        *,
        suite: Any,
        sig_alg: str,
        kem_alg: str,
        key_len: int,
        enable_qkd: bool = False,
        qkd_seed: int | None = None,
        qkd_source: str | None = None,
        qkd: QKDConfig | None = None,
        **_ignored: Any,
    ) -> None:
        self.suite = suite
        self.sig_alg = str(sig_alg)
        self.kem_alg = str(kem_alg)
        self.key_len = int(key_len)

        self.enable_qkd = bool(enable_qkd)
        self.qkd_seed = None if qkd_seed is None else int(qkd_seed)

        if qkd is not None:
            self.qkd = qkd
            return

        src: Optional[str] = None
        if isinstance(qkd_source, str) and qkd_source.strip():
            src = qkd_source.strip()

        # ★ここが追加：enable_qkd=True なら source のデフォルトを "e91"
        if self.enable_qkd and (src is None or not src.strip()):
            src = "e91"

        self.qkd = QKDConfig(
            enabled=self.enable_qkd,
            source=src,
            seed=self.qkd_seed,
        )
