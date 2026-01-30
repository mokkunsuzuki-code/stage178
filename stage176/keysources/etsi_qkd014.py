# MIT License © 2025 Motohiro Suzuki
"""
keysources/etsi_qkd014.py  (Stage165)

QSP KeySource adapter for ETSI GS QKD 014 KME REST API.
Uses etsi_qkd014.client + models (already in Stage165 tree).

Fail-closed: any malformed response or transport error raises RuntimeError.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from etsi_qkd014.client import ETSI014Client
from keysources.base import KeySource, KeyMaterial


@dataclass(frozen=True)
class ETSI014Config:
    kme_base_url: str
    master_sae_id: str
    slave_sae_id: str
    tls_verify: bool = False


class ETSI014KeySource(KeySource):
    name = "etsi_qkd014"

    def __init__(self, cfg: ETSI014Config) -> None:
        self.cfg = cfg
        self.client = ETSI014Client(base_url=cfg.kme_base_url, tls_verify=cfg.tls_verify)
        self.last_key_id: Optional[str] = None

    def provide(self, context: bytes) -> KeyMaterial:
        # ETSI 014 doesn't define transcript binding; we keep `context` for future receipts.
        st = self.client.get_status(self.cfg.slave_sae_id)
        key_size_bits = st.key_size_bits

        enc = self.client.enc_keys(
            slave_sae_id=self.cfg.slave_sae_id,
            number=1,
            size_bits=key_size_bits,
            extension_mandatory=None,
            extension_optional=None,
        )

        if not enc.keys:
            raise RuntimeError("ETSI014KeySource: enc_keys returned empty keys")

        k = enc.keys[0]
        self.last_key_id = k.key_id

        if not k.key_bytes:
            raise RuntimeError("ETSI014KeySource: key bytes missing")

        return KeyMaterial(qkd=k.key_bytes, kem=None)
