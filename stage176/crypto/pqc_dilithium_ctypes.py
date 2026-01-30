# MIT License © 2025 Motohiro Suzuki
"""
crypto/pqc_dilithium_ctypes.py

Stage157A: Real PQC signature backend (Dilithium / ML-DSA-65 family) via ctypes.

Assumption:
- You have a shared library built from PQClean (or your Stage144 wrapper) that exports
  Dilithium-style symbols.

We intentionally FAIL-CLOSED:
- If the library cannot be loaded or required symbols are missing, we raise RuntimeError.
- NO silent fallback to stub for "dilithium" in Stage157A.

Expected exported symbols (Stage144 wrapper style):
- qsp_dilithium_publickeybytes()  -> int
- qsp_dilithium_secretkeybytes()  -> int
- qsp_dilithium_signaturebytes()  -> int
- qsp_dilithium_keypair(pk_ptr, sk_ptr) -> int (0 success)
- qsp_dilithium_sign(sig_ptr, siglen_ptr, msg_ptr, mlen, sk_ptr) -> int (0 success)
- qsp_dilithium_verify(sig_ptr, siglen, msg_ptr, mlen, pk_ptr) -> int (0 success)

If your library uses slightly different symbol names, adjust _SYM_* constants below.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from typing import Iterable


# --------
# Symbol names (adjust here if your dylib exports different names)
# --------
_SYM_PK_BYTES = "qsp_dilithium_publickeybytes"
_SYM_SK_BYTES = "qsp_dilithium_secretkeybytes"
_SYM_SIG_BYTES = "qsp_dilithium_signaturebytes"
_SYM_KEYPAIR = "qsp_dilithium_keypair"
_SYM_SIGN = "qsp_dilithium_sign"
_SYM_VERIFY = "qsp_dilithium_verify"


def _candidate_lib_paths() -> list[str]:
    """
    Search order:
    1) env QSP_DILITHIUM_LIB
    2) local common paths (repo root / lib / build)
    """
    env = os.environ.get("QSP_DILITHIUM_LIB", "").strip()
    out: list[str] = []
    if env:
        out.append(env)

    names = [
        "libqsp_dilithium.dylib",
        "libqsp_dilithium.so",
        "qsp_dilithium.dylib",
        "qsp_dilithium.so",
        "libdilithium.dylib",
        "libdilithium.so",
    ]

    bases = [
        os.getcwd(),
        os.path.join(os.getcwd(), "lib"),
        os.path.join(os.getcwd(), "build"),
        os.path.join(os.getcwd(), "dist"),
        os.path.join(os.getcwd(), "crypto"),
    ]

    for b in bases:
        for n in names:
            out.append(os.path.join(b, n))

    # de-dup while preserving order
    seen = set()
    uniq: list[str] = []
    for p in out:
        if p and p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


def _load_cdll(paths: Iterable[str]) -> ctypes.CDLL:
    last_err: Exception | None = None
    for p in paths:
        try:
            if os.path.exists(p):
                return ctypes.CDLL(p)
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(
        "Dilithium(PQC) library not found / not loadable. "
        "Set env QSP_DILITHIUM_LIB to the full path of your dylib/so."
        + (f" last_err={last_err!r}" if last_err else "")
    )


@dataclass(frozen=True)
class DilithiumSizes:
    pk_bytes: int
    sk_bytes: int
    sig_bytes: int


class DilithiumCTypes:
    """
    Thin wrapper over your PQC shared library.
    """

    def __init__(self) -> None:
        self._lib = _load_cdll(_candidate_lib_paths())
        self._bind()

    def _must(self, name: str):
        try:
            return getattr(self._lib, name)
        except AttributeError as e:
            raise RuntimeError(f"Dilithium library missing symbol: {name}") from e

    def _bind(self) -> None:
        pkb = self._must(_SYM_PK_BYTES)
        skb = self._must(_SYM_SK_BYTES)
        sgb = self._must(_SYM_SIG_BYTES)
        kp = self._must(_SYM_KEYPAIR)
        sg = self._must(_SYM_SIGN)
        vf = self._must(_SYM_VERIFY)

        # sizes() => int
        pkb.restype = ctypes.c_size_t
        skb.restype = ctypes.c_size_t
        sgb.restype = ctypes.c_size_t

        self.sizes = DilithiumSizes(
            pk_bytes=int(pkb()),
            sk_bytes=int(skb()),
            sig_bytes=int(sgb()),
        )

        # int keypair(uint8_t* pk, uint8_t* sk)
        kp.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kp.restype = ctypes.c_int

        # int sign(uint8_t* sig, size_t* siglen, const uint8_t* msg, size_t mlen, const uint8_t* sk)
        sg.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        sg.restype = ctypes.c_int

        # int verify(const uint8_t* sig, size_t siglen, const uint8_t* msg, size_t mlen, const uint8_t* pk)
        vf.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        vf.restype = ctypes.c_int

        self._keypair_fn = kp
        self._sign_fn = sg
        self._verify_fn = vf

    def keypair(self) -> tuple[bytes, bytes]:
        pk = (ctypes.c_ubyte * self.sizes.pk_bytes)()
        sk = (ctypes.c_ubyte * self.sizes.sk_bytes)()
        rc = int(self._keypair_fn(ctypes.byref(pk), ctypes.byref(sk)))
        if rc != 0:
            raise RuntimeError(f"dilithium_keypair failed rc={rc}")
        return bytes(pk), bytes(sk)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        if not isinstance(sk, (bytes, bytearray)):
            raise TypeError("sk must be bytes")
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError("msg must be bytes")

        sk_b = bytes(sk)
        msg_b = bytes(msg)

        sig = (ctypes.c_ubyte * (self.sizes.sig_bytes + 16))()  # a bit extra safety
        siglen = ctypes.c_size_t(0)

        rc = int(
            self._sign_fn(
                ctypes.byref(sig),
                ctypes.byref(siglen),
                ctypes.c_char_p(msg_b),
                ctypes.c_size_t(len(msg_b)),
                ctypes.c_char_p(sk_b),
            )
        )
        if rc != 0:
            raise RuntimeError(f"dilithium_sign failed rc={rc}")

        n = int(siglen.value)
        if n <= 0 or n > len(sig):
            raise RuntimeError(f"dilithium_sign returned invalid siglen={n}")
        return bytes(sig[:n])

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        if not isinstance(pk, (bytes, bytearray)):
            raise TypeError("pk must be bytes")
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError("msg must be bytes")
        if not isinstance(sig, (bytes, bytearray)):
            raise TypeError("sig must be bytes")

        pk_b = bytes(pk)
        msg_b = bytes(msg)
        sig_b = bytes(sig)

        rc = int(
            self._verify_fn(
                ctypes.c_char_p(sig_b),
                ctypes.c_size_t(len(sig_b)),
                ctypes.c_char_p(msg_b),
                ctypes.c_size_t(len(msg_b)),
                ctypes.c_char_p(pk_b),
            )
        )
        return rc == 0
