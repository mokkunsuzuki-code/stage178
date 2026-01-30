# MIT License © 2025 Motohiro Suzuki
"""
protocol/rekey.py

Stage159:
- Rekey = new QKD event
- REKEY_INIT carries:
    - new_epoch (u32)
    - material (32 bytes)
    - qkd_len (u16)
    - qkd_bytes (qkd_len bytes)

- REKEY_ACK carries:
    - new_epoch (u32)
    - confirm (32 bytes)

Stage167-B:
- Add REKEY_COMMIT:
    - new_epoch (u32)
  Client MUST commit only after receiving REKEY_COMMIT.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from protocol.errors import RekeyError


def should_rekey(seq: int, threshold: int) -> bool:
    return threshold > 0 and seq > 0 and (seq % threshold == 0)


_MAGIC = b"RK55"
_T_INIT = 1
_T_ACK = 2
_T_COMMIT = 3


def _u16(x: int) -> bytes:
    return int(x & 0xFFFF).to_bytes(2, "big")


def _u32(x: int) -> bytes:
    return int(x & 0xFFFFFFFF).to_bytes(4, "big")


def _read_u16(b: bytes, off: int) -> tuple[int, int]:
    if off + 2 > len(b):
        raise RekeyError("rekey decode overflow u16")
    return int.from_bytes(b[off : off + 2], "big"), off + 2


def _read_u32(b: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(b):
        raise RekeyError("rekey decode overflow u32")
    return int.from_bytes(b[off : off + 4], "big"), off + 4


def make_material(n: int = 32) -> bytes:
    return os.urandom(n)


def confirm_material(material: bytes, qkd_bytes: bytes) -> bytes:
    m = bytes(material)
    q = bytes(qkd_bytes)
    return hashlib.sha256(m + b"|qkd|" + q + b"|ack").digest()


def encode_rekey_init(new_epoch: int, material: bytes, qkd_bytes: bytes) -> bytes:
    m = bytes(material)
    q = bytes(qkd_bytes)

    if len(m) != 32:
        raise RekeyError("rekey_init material must be 32 bytes")
    if len(q) > 65535:
        raise RekeyError("rekey_init qkd_bytes too long")

    return _MAGIC + bytes([_T_INIT]) + _u32(new_epoch) + m + _u16(len(q)) + q


def encode_rekey_ack(new_epoch: int, confirm: bytes) -> bytes:
    c = bytes(confirm)
    if len(c) != 32:
        raise RekeyError("rekey_ack confirm must be 32 bytes")
    return _MAGIC + bytes([_T_ACK]) + _u32(new_epoch) + c


def encode_rekey_commit(new_epoch: int) -> bytes:
    return _MAGIC + bytes([_T_COMMIT]) + _u32(new_epoch)


@dataclass
class RekeyInit:
    new_epoch: int
    material: bytes
    qkd_bytes: bytes


@dataclass
class RekeyAck:
    new_epoch: int
    confirm: bytes


@dataclass
class RekeyCommit:
    new_epoch: int


def decode_rekey_plaintext(pt: bytes) -> RekeyInit | RekeyAck | RekeyCommit:
    b = bytes(pt)
    if len(b) < 4 + 1 + 4:
        raise RekeyError("rekey plaintext too short")
    if b[:4] != _MAGIC:
        raise RekeyError("rekey bad magic")

    t = b[4]
    off = 5
    new_epoch, off = _read_u32(b, off)

    if t == _T_INIT:
        if off + 32 + 2 > len(b):
            raise RekeyError("rekey_init too short")
        material = b[off : off + 32]
        off += 32
        qlen, off = _read_u16(b, off)
        if off + qlen > len(b):
            raise RekeyError("rekey_init qkd overflow")
        qkd_bytes = b[off : off + qlen]
        off += qlen
        if off != len(b):
            raise RekeyError("rekey_init trailing bytes")
        return RekeyInit(new_epoch=new_epoch, material=material, qkd_bytes=qkd_bytes)

    if t == _T_ACK:
        if len(b) != (4 + 1 + 4 + 32):
            raise RekeyError("rekey_ack length mismatch")
        confirm = b[off:]
        if len(confirm) != 32:
            raise RekeyError("rekey_ack confirm len mismatch")
        return RekeyAck(new_epoch=new_epoch, confirm=confirm)

    if t == _T_COMMIT:
        if len(b) != (4 + 1 + 4):
            raise RekeyError("rekey_commit length mismatch")
        return RekeyCommit(new_epoch=new_epoch)

    raise RekeyError("rekey unknown type")
