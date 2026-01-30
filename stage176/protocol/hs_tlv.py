# MIT License © 2025 Motohiro Suzuki
"""
protocol/hs_tlv.py  (Stage160-1)

Handshake is now TLV (Type=u16, Length=u32, Value=bytes), network byte order.

Message Types:
- CHLO = 1
- SHLO = 2

Fields (TLV types):
- 0x0001 : MSG_TYPE (u8)
- 0x0002 : CLIENT_NONCE (bytes, recommended 16)
- 0x0003 : SESSION_ID (u64 bytes)
- 0x0004 : KEM_CT (bytes)
- 0x0005 : QKD_KEY (bytes)
- 0x0010 : SIG_PUB (bytes)
- 0x0011 : SIGNATURE (bytes)

Signing rule (canonical):
- Sign the "body TLVs" excluding SIG_PUB and SIGNATURE.
- Canonical bytes = concatenation of TLV encodings sorted by TLV type ascending.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Tuple

_TLV_HDR = struct.Struct("!HI")  # type(u16), len(u32)


# ---- Message types ----
HS_CHLO = 1
HS_SHLO = 2

# ---- TLV types ----
T_MSG_TYPE = 0x0001
T_CLIENT_NONCE = 0x0002
T_SESSION_ID = 0x0003
T_KEM_CT = 0x0004
T_QKD_KEY = 0x0005

T_SIG_PUB = 0x0010
T_SIGNATURE = 0x0011


def _u64_to_bytes(x: int) -> bytes:
    if x < 0 or x > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("u64 out of range")
    return x.to_bytes(8, "big")


def _u64_from_bytes(b: bytes) -> int:
    if len(b) != 8:
        raise ValueError("SESSION_ID must be 8 bytes (u64)")
    return int.from_bytes(b, "big")


def enc_tlv(t: int, v: bytes) -> bytes:
    vb = bytes(v)
    if t < 0 or t > 0xFFFF:
        raise ValueError("tlv type out of range")
    if len(vb) > 0xFFFFFFFF:
        raise ValueError("tlv too long")
    return _TLV_HDR.pack(t & 0xFFFF, len(vb) & 0xFFFFFFFF) + vb


def dec_tlvs(blob: bytes) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    i = 0
    b = bytes(blob)
    while i < len(b):
        if i + _TLV_HDR.size > len(b):
            raise ValueError("truncated tlv header")
        t, ln = _TLV_HDR.unpack_from(b, i)
        i += _TLV_HDR.size
        if i + ln > len(b):
            raise ValueError("truncated tlv value")
        v = b[i : i + ln]
        i += ln
        out.append((int(t), bytes(v)))
    return out


def canonical_body_bytes(fields: Dict[int, bytes]) -> bytes:
    """
    Canonical ordering: sort by TLV type ascending, then encode.
    Excludes signature fields by design (caller must omit them).
    """
    items = sorted(fields.items(), key=lambda kv: kv[0])
    return b"".join(enc_tlv(t, v) for t, v in items)


@dataclass(frozen=True)
class CHLO:
    client_nonce: bytes
    sig_pub: bytes
    signature: bytes

    def body_fields(self) -> Dict[int, bytes]:
        return {
            T_MSG_TYPE: bytes([HS_CHLO]),
            T_CLIENT_NONCE: bytes(self.client_nonce),
        }

    def to_bytes(self) -> bytes:
        body = self.body_fields()
        blob = canonical_body_bytes(body)
        blob += enc_tlv(T_SIG_PUB, self.sig_pub)
        blob += enc_tlv(T_SIGNATURE, self.signature)
        return blob

    @staticmethod
    def parse(blob: bytes) -> "CHLO":
        tlvs = dec_tlvs(blob)
        m: Dict[int, bytes] = {}
        for t, v in tlvs:
            m[t] = v

        if T_MSG_TYPE not in m or len(m[T_MSG_TYPE]) != 1 or m[T_MSG_TYPE][0] != HS_CHLO:
            raise ValueError("not CHLO")
        if T_CLIENT_NONCE not in m:
            raise ValueError("missing client nonce")
        if T_SIG_PUB not in m:
            raise ValueError("missing sig pub")
        if T_SIGNATURE not in m:
            raise ValueError("missing signature")

        return CHLO(
            client_nonce=m[T_CLIENT_NONCE],
            sig_pub=m[T_SIG_PUB],
            signature=m[T_SIGNATURE],
        )


@dataclass(frozen=True)
class SHLO:
    session_id: int
    kem_ct: bytes
    qkd_key: bytes | None
    sig_pub: bytes
    signature: bytes

    def body_fields(self) -> Dict[int, bytes]:
        d: Dict[int, bytes] = {
            T_MSG_TYPE: bytes([HS_SHLO]),
            T_SESSION_ID: _u64_to_bytes(self.session_id),
            T_KEM_CT: bytes(self.kem_ct),
        }
        if self.qkd_key is not None:
            d[T_QKD_KEY] = bytes(self.qkd_key)
        return d

    def to_bytes(self) -> bytes:
        body = self.body_fields()
        blob = canonical_body_bytes(body)
        blob += enc_tlv(T_SIG_PUB, self.sig_pub)
        blob += enc_tlv(T_SIGNATURE, self.signature)
        return blob

    @staticmethod
    def parse(blob: bytes) -> "SHLO":
        tlvs = dec_tlvs(blob)
        m: Dict[int, bytes] = {}
        for t, v in tlvs:
            m[t] = v

        if T_MSG_TYPE not in m or len(m[T_MSG_TYPE]) != 1 or m[T_MSG_TYPE][0] != HS_SHLO:
            raise ValueError("not SHLO")
        if T_SESSION_ID not in m:
            raise ValueError("missing session id")
        if T_KEM_CT not in m:
            raise ValueError("missing kem ct")
        if T_SIG_PUB not in m:
            raise ValueError("missing sig pub")
        if T_SIGNATURE not in m:
            raise ValueError("missing signature")

        qkd = m.get(T_QKD_KEY, None)
        return SHLO(
            session_id=_u64_from_bytes(m[T_SESSION_ID]),
            kem_ct=m[T_KEM_CT],
            qkd_key=qkd,
            sig_pub=m[T_SIG_PUB],
            signature=m[T_SIGNATURE],
        )
