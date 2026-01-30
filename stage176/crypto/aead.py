# MIT License © 2025 Motohiro Suzuki
"""
crypto/aead.py

Stage157C–159 AEAD backends.
"""

from __future__ import annotations
import os


# =========================
# Base
# =========================

class AEADBackend:
    name: str

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        raise NotImplementedError


# =========================
# AES-GCM (real)
# =========================

class _AESGCM(AEADBackend):
    def __init__(self) -> None:
        self.name = "aes-gcm"
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._AESGCM = AESGCM
        except Exception as e:
            raise RuntimeError("cryptography AESGCM not available") from e

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._AESGCM(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return self._AESGCM(key).decrypt(nonce, ciphertext, aad)


# =========================
# Demo XOR (dev only)
# =========================

class _XorDemo(AEADBackend):
    """
    NOT secure. For boundary testing only.
    """
    def __init__(self) -> None:
        self.name = "demo-xor"

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return bytes(p ^ key[i % len(key)] for i, p in enumerate(plaintext))

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))


# =========================
# Resolver
# =========================

def get_aead_backend(name: str) -> AEADBackend:
    n = name.strip().lower()

    if n in ("aesgcm", "aes-gcm"):
        return _AESGCM()

    if n in ("demo-xor", "xor"):
        return _XorDemo()

    raise ValueError(f"unknown aead backend: {name}")
