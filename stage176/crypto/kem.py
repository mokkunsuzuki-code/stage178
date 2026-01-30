# MIT License © 2025 Motohiro Suzuki
"""
crypto/kem.py

Stage159:
- Provide a unified KEM backend interface that supports BOTH:
    - encap()/decap()
    - encapsulate()/decapsulate()

Backends:
- mlkem : ctypes wrapper via env QSP_MLKEM_LIB (required for real ML-KEM)
- toy_kem : deterministic-ish demo fallback (NOT secure)

Stage161:
- toy_kem becomes deterministic when env QSP_TOY_KEM_SEED is set.
"""

from __future__ import annotations

import os
import ctypes
import hashlib
from dataclasses import dataclass


class KemError(RuntimeError):
    pass


@dataclass(frozen=True)
class KemEncapResult:
    ciphertext: bytes
    shared_secret: bytes


class KemBackend:
    name: str

    def encap(self) -> tuple[bytes, bytes]:
        raise NotImplementedError

    def decap(self, ct: bytes) -> bytes:
        raise NotImplementedError

    def encapsulate(self) -> KemEncapResult:
        ct, ss = self.encap()
        return KemEncapResult(ciphertext=ct, shared_secret=ss)

    def decapsulate(self, ct: bytes) -> bytes:
        return self.decap(ct)


class _ToyKEM(KemBackend):
    """
    NOT secure. Demo only.

    Stage161 deterministic mode:
      env QSP_TOY_KEM_SEED (string)
    Then ct = SHA256(seed||"ct"||counter)[:32], counter fixed to 1 for vectors.
    """
    def __init__(self) -> None:
        self.name = "toy_kem"
        self._seed = os.getenv("QSP_TOY_KEM_SEED", "").encode("utf-8") or None

    def _det_ct(self) -> bytes:
        assert self._seed is not None
        return hashlib.sha256(self._seed + b"|ct|1").digest()[:32]

    def encap(self) -> tuple[bytes, bytes]:
        if self._seed is None:
            ct = os.urandom(32)
        else:
            ct = self._det_ct()
        ss = hashlib.sha256(ct + b"toy_kem").digest()
        return ct, ss

    def decap(self, ct: bytes) -> bytes:
        ct = bytes(ct)
        return hashlib.sha256(ct + b"toy_kem").digest()


class _MLKEMCTypes(KemBackend):
    def __init__(self) -> None:
        self.name = "mlkem"
        lib_path = os.getenv("QSP_MLKEM_LIB", "").strip()
        if not lib_path:
            raise KemError("QSP_MLKEM_LIB is not set (ML-KEM library path required)")

        try:
            self._lib = ctypes.CDLL(lib_path)
        except Exception as e:
            raise KemError(f"cannot load ML-KEM library: {lib_path}") from e

        for fn in ("qsp_mlkem_keypair", "qsp_mlkem_encaps", "qsp_mlkem_decaps"):
            if not hasattr(self._lib, fn):
                raise KemError(f"ML-KEM dylib missing symbol: {fn}")

        self.PK_MAX = 4096
        self.SK_MAX = 4096
        self.CT_MAX = 4096
        self.SS_MAX = 128

    def encap(self) -> tuple[bytes, bytes]:
        pk_buf = (ctypes.c_ubyte * self.PK_MAX)()
        sk_buf = (ctypes.c_ubyte * self.SK_MAX)()
        pk_len = ctypes.c_size_t(self.PK_MAX)
        sk_len = ctypes.c_size_t(self.SK_MAX)

        rc = self._lib.qsp_mlkem_keypair(
            ctypes.byref(pk_buf),
            ctypes.byref(pk_len),
            ctypes.byref(sk_buf),
            ctypes.byref(sk_len),
        )
        if int(rc) != 0:
            raise KemError(f"qsp_mlkem_keypair failed rc={rc}")

        ct_buf = (ctypes.c_ubyte * self.CT_MAX)()
        ss_buf = (ctypes.c_ubyte * self.SS_MAX)()
        ct_len = ctypes.c_size_t(self.CT_MAX)
        ss_len = ctypes.c_size_t(self.SS_MAX)

        rc2 = self._lib.qsp_mlkem_encaps(
            ctypes.byref(ct_buf),
            ctypes.byref(ct_len),
            ctypes.byref(ss_buf),
            ctypes.byref(ss_len),
            ctypes.byref(pk_buf),
            pk_len,
        )
        if int(rc2) != 0:
            raise KemError(f"qsp_mlkem_encaps failed rc={rc2}")

        ct = bytes(bytearray(ct_buf)[: int(ct_len.value)])
        ss = bytes(bytearray(ss_buf)[: int(ss_len.value)])
        if not ct or not ss:
            raise KemError("mlkem encaps returned empty ct/ss")
        return ct, ss

    def decap(self, ct: bytes) -> bytes:
        raise KemError(
            "mlkem.decap is not implemented because it requires the secret key from keypair(). "
            "Stage159/160 handshake must be updated to store sk."
        )


def get_kem_backend(name: str) -> KemBackend:
    n = name.strip().lower()
    if n in ("mlkem", "ml-kem", "kyber"):
        return _MLKEMCTypes()
    if n in ("toy_kem", "toy-kem"):
        return _ToyKEM()
    return _ToyKEM()
