# MIT License © 2025 Motohiro Suzuki
"""
transport/message_frame.py  (Stage160)

Stage160:
- Wire header is now versioned and self-identifying.
- Keep frame structure close to Stage155, but add:
    - magic: 4 bytes ("QSP0")
    - version: u8
    - reserved: u8  (for future)
- Payload is opaque bytes (handshake payload is now TLV in Stage160-1).

Stage167-B:
- FT_CLOSE payload is ClosePayload (see protocol/failure.py):
    close_code(u8) + epoch(u32) + msg_len(u16) + msg(utf-8)
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

FT_HANDSHAKE = 1
FT_APP_DATA = 2
FT_REKEY = 3
FT_CLOSE = 4

_MAGIC = b"QSP0"
_VERSION = 1

# magic(4), version(u8), rsv(u8), type(u8), flags(u8), session_id(u64), epoch(u32), seq(u32), payload_len(u32)
_HDR = struct.Struct("!4sBBBBQIII")


@dataclass(frozen=True)
class MessageFrame:
    frame_type: int
    flags: int
    session_id: int
    epoch: int
    seq: int
    payload: bytes

    def to_bytes(self) -> bytes:
        p = bytes(self.payload)
        header = _HDR.pack(
            _MAGIC,
            _VERSION,
            0,  # reserved
            int(self.frame_type) & 0xFF,
            int(self.flags) & 0xFF,
            int(self.session_id) & 0xFFFFFFFFFFFFFFFF,
            int(self.epoch) & 0xFFFFFFFF,
            int(self.seq) & 0xFFFFFFFF,
            len(p) & 0xFFFFFFFF,
        )
        return header + p

    @staticmethod
    async def read_from(reader: asyncio.StreamReader) -> "MessageFrame | None":
        try:
            hdr = await reader.readexactly(_HDR.size)
        except asyncio.IncompleteReadError:
            return None

        magic, ver, _rsv, ftype, flags, sid, epoch, seq, plen = _HDR.unpack(hdr)

        if magic != _MAGIC:
            raise ValueError("bad magic (not QSP0)")
        if ver != _VERSION:
            raise ValueError(f"unsupported wire version: {ver}")

        if plen < 0 or plen > (64 * 1024 * 1024):
            raise ValueError("payload too large")

        payload = await reader.readexactly(plen) if plen else b""
        return MessageFrame(
            frame_type=int(ftype),
            flags=int(flags),
            session_id=int(sid),
            epoch=int(epoch),
            seq=int(seq),
            payload=bytes(payload),
        )
