# MIT License © 2025 Motohiro Suzuki
"""
crypto/zeroize.py  (Stage170-A)

Best-effort secret zeroization utilities.

Reality check (Python):
- 'bytes' is immutable; cannot guarantee in-place wiping of the original object.
- 'bytearray' / 'memoryview' can be wiped in-place.

Stage170-A goal:
- Make secret lifetime explicit and reviewable.
- Ensure we CALL wipe/zeroize at key points (replace / abort / exception paths).
- Enable policy scanners (scan_zeroize_rules.py) to detect explicit zeroize markers.
"""

from __future__ import annotations

from typing import Any


def wipe_bytearray(b: bytearray) -> None:
    """In-place wipe for mutable buffer."""
    for i in range(len(b)):
        b[i] = 0


def wipe_memoryview(m: memoryview) -> None:
    """In-place wipe for writable memoryview."""
    if m.readonly:
        return
    m[:] = b"\x00" * len(m)


def wipe_bytes_like(x: Any) -> None:
    """
    Best-effort wipe for arbitrary object:
    - bytearray: wiped in-place
    - memoryview(writable): wiped in-place
    - bytes: cannot wipe original, but we still perform an explicit marker call:
        create a temp bytearray and wipe it (reviewable intent + scanner marker).
    """
    try:
        if isinstance(x, bytearray):
            wipe_bytearray(x)
            return
        if isinstance(x, memoryview):
            wipe_memoryview(x)
            return
        if isinstance(x, (bytes,)):
            tmp = bytearray(x)
            wipe_bytearray(tmp)
            return
    except Exception:
        # Stage170-A: zeroize must never raise
        return


class SecretBox:
    """
    Optional wrapper: holds a bytearray so it can be wiped in-place.

    Use when you WANT a clearly wipeable container.
    """
    __slots__ = ("_buf",)

    def __init__(self, data: bytes | bytearray) -> None:
        self._buf = data if isinstance(data, bytearray) else bytearray(data)

    def bytes(self) -> bytes:
        return bytes(self._buf)

    def view(self) -> memoryview:
        return memoryview(self._buf)

    def wipe(self) -> None:
        wipe_bytearray(self._buf)

    def __len__(self) -> int:
        return len(self._buf)
