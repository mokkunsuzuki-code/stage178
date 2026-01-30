# MIT License © 2025 Motohiro Suzuki
"""
crypto/algorithms.py

Stage159 fix:
- Provide AlgorithmSuite.get_sig / get_kem.
- Avoid circular import by importing modules lazily.
"""

from __future__ import annotations

from dataclasses import dataclass


class SigAlg:
    def __init__(self, name: str) -> None:
        self.name = name

        # Import module (not symbol) to avoid "cannot import name" problems.
        import crypto.sig_backends as sb

        self._b = sb.get_sig_backend(name)
        kp = self._b.keypair()
        self._pk = kp.public_key
        self._sk = kp.secret_key

    def sign(self, msg: bytes) -> bytes:
        return self._b.sign(self._sk, msg)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        return self._b.verify(self._pk, msg, sig)

    def public_key_bytes(self) -> bytes:
        return bytes(self._pk)


class KemAlg:
    def __init__(self, name: str) -> None:
        self.name = name

        from crypto.kem import get_kem_backend

        self._b = get_kem_backend(name)

    def encap(self):
        return self._b.encap()

    def decap(self, ct: bytes) -> bytes:
        return self._b.decap(ct)


@dataclass(frozen=True)
class AlgorithmSuite:
    supported_sigs: list[str]
    supported_kems: list[str]
    supported_aeads: list[str]

    def get_sig(self, name: str) -> SigAlg:
        return SigAlg(name)

    def get_kem(self, name: str) -> KemAlg:
        return KemAlg(name)
