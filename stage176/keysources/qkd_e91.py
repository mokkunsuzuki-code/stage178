# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import os
import hashlib
from keysources.base import KeySource, KeyMaterial


class QKDE91KeySource(KeySource):
    """
    Stage155 dev QKD source (placeholder).
    Stage159: keep it simple for now.

    Stage161 deterministic mode:
      env QSP_QKD_SEED (string)
    Then qkd = SHA256(seed||"qkd"|counter)[:32], counter fixed to 1 for vectors.
    """
    name = "qkd_e91_dev"

    def __init__(self, seed: str | None = None) -> None:
        self._seed = (seed if seed is not None else os.getenv("QSP_QKD_SEED", "").strip()) or None

    def provide(self, context: bytes) -> KeyMaterial:
        if self._seed is None:
            raw = os.urandom(32)
        else:
            raw = hashlib.sha256(self._seed.encode("utf-8") + b"|qkd|1").digest()[:32]
        return KeyMaterial(qkd=raw, kem=None)


# ---- IMPORTANT ALIAS (Stage159/160 expects this name) ----
E91KeySource = QKDE91KeySource
