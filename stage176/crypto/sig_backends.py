# MIT License © 2025 Motohiro Suzuki
"""
crypto/sig_backends.py

Stage159 fix:
- Avoid import-time failure that prevents get_sig_backend from being defined.
- Heavy deps (cryptography / Dilithium ctypes) are imported lazily INSIDE classes.
- Fail-closed for Dilithium: if library missing/unloadable -> RuntimeError.

Stage161 fix:
- Support deterministic Ed25519 key via env:
    QSP_ED25519_SK_B64 = base64(32-byte seed)
  If set, keypair() returns deterministic pk/sk derived from that seed.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import hmac
import hashlib
import base64


@dataclass(frozen=True)
class SigKeyPair:
    public_key: bytes
    secret_key: bytes


class SigBackend:
    name: str

    def keypair(self) -> SigKeyPair:
        raise NotImplementedError

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        raise NotImplementedError


class _HmacStubSig(SigBackend):
    """
    STUB signature (NOT secure).
    Public key == secret key.
    Use only when explicitly selected.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def keypair(self) -> SigKeyPair:
        sk = os.urandom(32)
        pk = sk
        return SigKeyPair(public_key=pk, secret_key=sk)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return hmac.new(sk, msg, hashlib.sha256).digest()

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        exp = hmac.new(pk, msg, hashlib.sha256).digest()
        return hmac.compare_digest(exp, sig)


class _Ed25519Sig(SigBackend):
    """
    Ed25519:
    - Uses cryptography if available.
    - If cryptography missing -> fallback stub (dev convenience).
    - Stage161: deterministic key if env QSP_ED25519_SK_B64 is set.

    NOTE:
    - cryptography Ed25519PrivateKey.from_private_bytes expects 32 bytes seed.
    """

    def __init__(self) -> None:
        self.name = "ed25519"
        self._ok = False
        self._stub = _HmacStubSig("ed25519_stub")

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
            self.Ed25519PrivateKey = Ed25519PrivateKey
            self.Ed25519PublicKey = Ed25519PublicKey
            self._ok = True
        except Exception:
            self._ok = False

    def _env_seed32(self) -> bytes | None:
        s = os.getenv("QSP_ED25519_SK_B64", "").strip()
        if not s:
            return None
        try:
            raw = base64.b64decode(s, validate=True)
        except Exception as e:
            raise RuntimeError("QSP_ED25519_SK_B64 is not valid base64") from e
        if len(raw) != 32:
            raise RuntimeError("QSP_ED25519_SK_B64 must decode to 32 bytes")
        return raw

    def keypair(self) -> SigKeyPair:
        seed = self._env_seed32()
        if not self._ok:
            # deterministic stub if env present
            if seed is not None:
                sk = seed
                pk = sk
                return SigKeyPair(public_key=pk, secret_key=sk)
            return self._stub.keypair()

        if seed is not None:
            sk_obj = self.Ed25519PrivateKey.from_private_bytes(seed)
            pk_obj = sk_obj.public_key()
            return SigKeyPair(
                public_key=pk_obj.public_bytes_raw(),
                secret_key=seed,
            )

        sk_obj = self.Ed25519PrivateKey.generate()
        pk_obj = sk_obj.public_key()
        return SigKeyPair(
            public_key=pk_obj.public_bytes_raw(),
            secret_key=sk_obj.private_bytes_raw(),
        )

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        if not self._ok:
            return self._stub.sign(sk, msg)
        sk_obj = self.Ed25519PrivateKey.from_private_bytes(sk)
        return sk_obj.sign(msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        if not self._ok:
            return self._stub.verify(pk, msg, sig)
        try:
            pk_obj = self.Ed25519PublicKey.from_public_bytes(pk)
            pk_obj.verify(sig, msg)
            return True
        except Exception:
            return False


class _DilithiumSig(SigBackend):
    """
    REAL PQC signature (Dilithium / ML-DSA family) via ctypes.

    Fail-closed:
    - If shared library is missing/unloadable => RuntimeError (no stub fallback).
    """

    def __init__(self, name: str = "dilithium") -> None:
        self.name = name
        from crypto.pqc_dilithium_ctypes import DilithiumCTypes
        self._pqc = DilithiumCTypes()

    def keypair(self) -> SigKeyPair:
        pk, sk = self._pqc.keypair()
        return SigKeyPair(public_key=pk, secret_key=sk)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return self._pqc.sign(sk=sk, msg=msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        return self._pqc.verify(pk=pk, msg=msg, sig=sig)


def get_sig_backend(name: str) -> SigBackend:
    """
    Factory.
    NOTE: This function MUST be available even if PQC libs are missing.
    """
    n = name.strip().lower()

    if n in (
        "dilithium",
        "ml-dsa",
        "ml-dsa-65",
        "mldsa",
        "mldsa65",
        "dilithium2",
        "dilithium3",
        "dilithium5",
    ):
        return _DilithiumSig("dilithium")  # fail-closed inside ctor

    if n == "ed25519":
        return _Ed25519Sig()

    if n in ("sphincs+", "sphincs", "sphincsplus"):
        return _HmacStubSig("sphincs+_stub")

    return _HmacStubSig(n)
