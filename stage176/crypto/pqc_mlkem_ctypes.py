# MIT License © 2025 Motohiro Suzuki
"""
crypto/pqc_mlkem_ctypes.py

Stage157B: REAL ML-KEM (Kyber) via ctypes.

Fail-closed:
- If the library cannot be loaded or required symbols are missing, raise RuntimeError.
- No silent fallback when "mlkem/kyber" is selected.

Expected exported symbols (Stage144-like wrapper style):
- qsp_mlkem_publickeybytes()   -> int
- qsp_mlkem_secretkeybytes()   -> int
- qsp_mlkem_ciphertextbytes()  -> int
- qsp_mlkem_sharedsecretbytes()-> int
- qsp_mlkem_keypair(pk_ptr, sk_ptr) -> int
- qsp_mlkem_encaps(ct_ptr, ss_ptr, pk_ptr) -> int
- qsp_mlkem_decaps(ss_ptr, ct_ptr, sk_ptr) -> int

If your library uses different symbols, adjust _SYM_* constants below.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from typing import Iterable


_SYM_PK_BYTES = "qsp_mlkem_publickeybytes"
_SYM_SK_BYTES = "qsp_mlkem_secretkeybytes"
_SYM_CT_BYTES = "qsp_mlkem_ciphertextbytes"
_SYM_SS_BYTES = "qsp_mlkem_sharedsecretbytes"
_SYM_KEYPAIR = "qsp_mlkem_keypair"
_SYM_ENCAPS = "qsp_mlkem_encaps"
_SYM_DECAPS = "qsp_mlkem_decaps"


def _candidate_lib_paths() -> list[str]:
    env = os.environ.get("QSP_MLKEM_LIB", "").strip()
    out: list[str] = []
    if env:
        out.append(env)

    names = [
        "libqsp_mlkem.dylib",
        "libqsp_mlkem.so",
        "qsp_mlkem.dylib",
        "qsp_mlkem.so",
        "libmlkem.dylib",
        "libmlkem.so",
        "libkyber.dylib",
        "libkyber.so",
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
        "ML-KEM(Kyber) library not found / not loadable. "
        "Set env QSP_MLKEM_LIB to the full path of your dylib/so."
        + (f" last_err={last_err!r}" if last_err else "")
    )


@dataclass(frozen=True)
class MLKEMSizes:
    pk_bytes: int
    sk_bytes: int
    ct_bytes: int
    ss_bytes: int


class MLKEMCTypes:
    def __init__(self) -> None:
        self._lib = _load_cdll(_candidate_lib_paths())
        self._bind()

    def _must(self, name: str):
        try:
            return getattr(self._lib, name)
        except AttributeError as e:
            raise RuntimeError(f"ML-KEM library missing symbol: {name}") from e

    def _bind(self) -> None:
        pkb = self._must(_SYM_PK_BYTES)
        skb = self._must(_SYM_SK_BYTES)
        ctb = self._must(_SYM_CT_BYTES)
        ssb = self._must(_SYM_SS_BYTES)
        kp = self._must(_SYM_KEYPAIR)
        en = self._must(_SYM_ENCAPS)
        de = self._must(_SYM_DECAPS)

        pkb.restype = ctypes.c_size_t
        skb.restype = ctypes.c_size_t
        ctb.restype = ctypes.c_size_t
        ssb.restype = ctypes.c_size_t

        self.sizes = MLKEMSizes(
            pk_bytes=int(pkb()),
            sk_bytes=int(skb()),
            ct_bytes=int(ctb()),
            ss_bytes=int(ssb()),
        )

        # int keypair(uint8_t* pk, uint8_t* sk)
        kp.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kp.restype = ctypes.c_int

        # int encaps(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
        en.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        en.restype = ctypes.c_int

        # int decaps(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
        de.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        de.restype = ctypes.c_int

        self._keypair_fn = kp
        self._encaps_fn = en
        self._decaps_fn = de

    def keypair(self) -> tuple[bytes, bytes]:
        pk = (ctypes.c_ubyte * self.sizes.pk_bytes)()
        sk = (ctypes.c_ubyte * self.sizes.sk_bytes)()
        rc = int(self._keypair_fn(ctypes.byref(pk), ctypes.byref(sk)))
        if rc != 0:
            raise RuntimeError(f"mlkem_keypair failed rc={rc}")
        return bytes(pk), bytes(sk)

    def encapsulate(self, pk: bytes) -> tuple[bytes, bytes]:
        if not isinstance(pk, (bytes, bytearray)):
            raise TypeError("pk must be bytes")
        pk_b = bytes(pk)

        ct = (ctypes.c_ubyte * self.sizes.ct_bytes)()
        ss = (ctypes.c_ubyte * self.sizes.ss_bytes)()

        rc = int(self._encaps_fn(ctypes.byref(ct), ctypes.byref(ss), ctypes.c_char_p(pk_b)))
        if rc != 0:
            raise RuntimeError(f"mlkem_encaps failed rc={rc}")
        return bytes(ss), bytes(ct)

    def decapsulate(self, sk: bytes, ct: bytes) -> bytes:
        if not isinstance(sk, (bytes, bytearray)):
            raise TypeError("sk must be bytes")
        if not isinstance(ct, (bytes, bytearray)):
            raise TypeError("ct must be bytes")
        sk_b = bytes(sk)
        ct_b = bytes(ct)

        ss = (ctypes.c_ubyte * self.sizes.ss_bytes)()
        rc = int(self._decaps_fn(ctypes.byref(ss), ctypes.c_char_p(ct_b), ctypes.c_char_p(sk_b)))
        if rc != 0:
            raise RuntimeError(f"mlkem_decaps failed rc={rc}")
        return bytes(ss)
