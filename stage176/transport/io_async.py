# MIT License © 2025 Motohiro Suzuki
"""
transport/io_async.py

Stage160:
- Still uses MessageFrame, but MessageFrame is now versioned wire (QSP0 + version).
- Handshake helpers send/recv raw payload bytes (payload itself is Stage160-1 TLV).

Stage166:
- Add helpers for REKEY and APP_DATA frames (FT_REKEY / FT_APP_DATA).

Stage167-B:
- Add FT_CLOSE helpers (send_close / recv_close)
- If FT_CLOSE is received while waiting for another type, raise ConnectionError
  (protocol layer converts it to Failure deterministically)
"""

from __future__ import annotations

import asyncio

from transport.message_frame import (
    MessageFrame,
    FT_HANDSHAKE,
    FT_REKEY,
    FT_APP_DATA,
    FT_CLOSE,
)

from protocol.failure import ClosePayload


class AsyncFrameIO:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._r = reader
        self._w = writer
        self._closed = False

    async def read_frame(self) -> MessageFrame | None:
        return await MessageFrame.read_from(self._r)

    async def write_frame(self, frame: MessageFrame) -> None:
        if self._closed:
            return
        self._w.write(frame.to_bytes())
        await self._w.drain()

    # -------------------------
    # Close helpers (Stage167-B)
    # -------------------------
    async def send_close(
        self,
        *,
        session_id: int,
        epoch: int,
        close_code: int,
        message: str | None = None,
        flags: int = 0,
    ) -> None:
        payload = ClosePayload(close_code=int(close_code), epoch=int(epoch), message=message).encode()
        f = MessageFrame(
            frame_type=FT_CLOSE,
            flags=int(flags) & 0xFF,
            session_id=int(session_id),
            epoch=int(epoch),
            seq=0,
            payload=payload,
        )
        await self.write_frame(f)

    async def recv_close(self) -> ClosePayload:
        while True:
            f = await self.read_frame()
            if f is None:
                raise ConnectionError("connection closed while waiting close")
            if f.frame_type != FT_CLOSE:
                continue
            return ClosePayload.decode(bytes(f.payload))

    # -------------------------
    # Handshake helpers
    # -------------------------
    async def send_handshake(self, payload: bytes) -> None:
        f = MessageFrame(
            frame_type=FT_HANDSHAKE,
            flags=0,
            session_id=0,
            epoch=0,
            seq=0,
            payload=bytes(payload),
        )
        await self.write_frame(f)

    async def recv_handshake(self) -> bytes:
        while True:
            f = await self.read_frame()
            if f is None:
                raise ConnectionError("connection closed while waiting handshake")
            if f.frame_type == FT_CLOSE:
                cp = ClosePayload.decode(bytes(f.payload))
                raise ConnectionError(f"peer sent CLOSE code={cp.close_code} epoch={cp.epoch}")
            if f.frame_type != FT_HANDSHAKE:
                continue
            return bytes(f.payload)

    # -------------------------
    # Rekey helpers (Stage166)
    # -------------------------
    async def send_rekey(self, session_id: int, epoch: int, seq: int, payload: bytes, flags: int = 0) -> None:
        f = MessageFrame(
            frame_type=FT_REKEY,
            flags=int(flags) & 0xFF,
            session_id=int(session_id),
            epoch=int(epoch),
            seq=int(seq),
            payload=bytes(payload),
        )
        await self.write_frame(f)

    async def recv_rekey(self) -> MessageFrame:
        while True:
            f = await self.read_frame()
            if f is None:
                raise ConnectionError("connection closed while waiting rekey")
            if f.frame_type == FT_CLOSE:
                cp = ClosePayload.decode(bytes(f.payload))
                raise ConnectionError(f"peer sent CLOSE code={cp.close_code} epoch={cp.epoch}")
            if f.frame_type != FT_REKEY:
                continue
            return f

    # -------------------------
    # App-data helpers (Stage166 demo loop)
    # -------------------------
    async def send_app_data(self, session_id: int, epoch: int, seq: int, payload: bytes, flags: int = 0) -> None:
        f = MessageFrame(
            frame_type=FT_APP_DATA,
            flags=int(flags) & 0xFF,
            session_id=int(session_id),
            epoch=int(epoch),
            seq=int(seq),
            payload=bytes(payload),
        )
        await self.write_frame(f)

    async def recv_app_data(self) -> MessageFrame:
        while True:
            f = await self.read_frame()
            if f is None:
                raise ConnectionError("connection closed while waiting app_data")
            if f.frame_type == FT_CLOSE:
                cp = ClosePayload.decode(bytes(f.payload))
                raise ConnectionError(f"peer sent CLOSE code={cp.close_code} epoch={cp.epoch}")
            if f.frame_type != FT_APP_DATA:
                continue
            return f

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._w.close()
            await self._w.wait_closed()
        except Exception:
            pass


async def open_connection(host: str, port: int) -> AsyncFrameIO:
    reader, writer = await asyncio.open_connection(host, port)
    return AsyncFrameIO(reader, writer)


async def open_client(host: str, port: int) -> AsyncFrameIO:
    return await open_connection(host, port)
