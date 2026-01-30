# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from crypto.zeroize import wipe_bytes_like  # Stage170-A


class FailureLayer(str, Enum):
    PROTOCOL = "protocol"
    CRYPTO = "crypto"
    TRANSPORT = "transport"
    POLICY = "policy"


class FailurePhase(str, Enum):
    HANDSHAKE = "handshake"
    REKEY = "rekey"
    DATA = "data"
    CLOSE = "close"


class FailureCode(str, Enum):
    # Stage167-B minimum set
    ERR_PARSE = "ERR_PARSE"
    ERR_VERSION_UNSUPPORTED = "ERR_VERSION_UNSUPPORTED"
    ERR_STATE_VIOLATION = "ERR_STATE_VIOLATION"
    ERR_AUTH_FAILED = "ERR_AUTH_FAILED"
    ERR_KEM_FAILED = "ERR_KEM_FAILED"
    ERR_QKD_FAILED = "ERR_QKD_FAILED"
    ERR_TRANSCRIPT_MISMATCH = "ERR_TRANSCRIPT_MISMATCH"
    ERR_EPOCH_MISMATCH = "ERR_EPOCH_MISMATCH"
    ERR_REKEY_IN_PROGRESS = "ERR_REKEY_IN_PROGRESS"
    ERR_TIMEOUT = "ERR_TIMEOUT"
    ERR_INTERNAL = "ERR_INTERNAL"

    # Practical extension (remote closed first)
    ERR_REMOTE_CLOSE = "ERR_REMOTE_CLOSE"


@dataclass(frozen=True)
class Failure:
    """
    Unified error carrier (Stage167-B).
    detail is LOCAL-ONLY by default (MUST NOT be sent on wire).
    """
    layer: FailureLayer
    phase: FailurePhase
    code: FailureCode
    fatal: bool
    detail: Optional[str] = None

    def redacted(self) -> "Failure":
        return Failure(
            layer=self.layer,
            phase=self.phase,
            code=self.code,
            fatal=self.fatal,
            detail=None,
        )


class CloseReason(int, Enum):
    """
    Wire-stable close codes. Keep values stable once published.
    """
    PARSE = 1
    VERSION_UNSUPPORTED = 2
    STATE_VIOLATION = 3
    AUTH_FAILED = 4
    KEM_FAILED = 5
    QKD_FAILED = 6
    TRANSCRIPT_MISMATCH = 7
    EPOCH_MISMATCH = 8
    REKEY_IN_PROGRESS = 9
    TIMEOUT = 10
    REMOTE_CLOSE = 11
    INTERNAL = 255

    @staticmethod
    def from_failure_code(code: FailureCode) -> "CloseReason":
        m = {
            FailureCode.ERR_PARSE: CloseReason.PARSE,
            FailureCode.ERR_VERSION_UNSUPPORTED: CloseReason.VERSION_UNSUPPORTED,
            FailureCode.ERR_STATE_VIOLATION: CloseReason.STATE_VIOLATION,
            FailureCode.ERR_AUTH_FAILED: CloseReason.AUTH_FAILED,
            FailureCode.ERR_KEM_FAILED: CloseReason.KEM_FAILED,
            FailureCode.ERR_QKD_FAILED: CloseReason.QKD_FAILED,
            FailureCode.ERR_TRANSCRIPT_MISMATCH: CloseReason.TRANSCRIPT_MISMATCH,
            FailureCode.ERR_EPOCH_MISMATCH: CloseReason.EPOCH_MISMATCH,
            FailureCode.ERR_REKEY_IN_PROGRESS: CloseReason.REKEY_IN_PROGRESS,
            FailureCode.ERR_TIMEOUT: CloseReason.TIMEOUT,
            FailureCode.ERR_REMOTE_CLOSE: CloseReason.REMOTE_CLOSE,
            FailureCode.ERR_INTERNAL: CloseReason.INTERNAL,
        }
        return m.get(code, CloseReason.INTERNAL)


@dataclass(frozen=True)
class ClosePayload:
    """
    Payload format for FT_CLOSE (transport/message_frame.py):
      - 1 byte: close_code (0..255)
      - 4 bytes: epoch (u32 big-endian)
      - 2 bytes: msg_len (u16 big-endian)
      - msg bytes: utf-8 (optional, non-secret)
    """
    close_code: int
    epoch: int
    message: Optional[str] = None

    def encode(self) -> bytes:
        code_b = bytes([int(self.close_code) & 0xFF])
        epoch_b = int(self.epoch).to_bytes(4, "big", signed=False)
        msg = (self.message or "").encode("utf-8")
        if len(msg) > 65535:
            msg = msg[:65535]
        ln_b = len(msg).to_bytes(2, "big", signed=False)
        return code_b + epoch_b + ln_b + msg

    @staticmethod
    def decode(b: bytes) -> "ClosePayload":
        if len(b) < 1 + 4 + 2:
            raise ValueError("close payload too short")
        code = b[0]
        epoch = int.from_bytes(b[1:5], "big", signed=False)
        ln = int.from_bytes(b[5:7], "big", signed=False)
        msg_b = b[7:7 + ln]
        msg: Optional[str]
        try:
            s = msg_b.decode("utf-8")
            msg = s if s else None
        except Exception:
            msg = None
        return ClosePayload(close_code=code, epoch=epoch, message=msg)


# -------------------------
# Rekey pre-commit/commit helper (Stage167-B -> Stage170-A)
# -------------------------
@dataclass
class RekeyContext:
    """
    Implementation rule:
      - precommit derives next keys, but does NOT install them
      - commit() is the ONLY place where epoch/keys switch happens
    """
    base_epoch: int
    next_epoch: int
    next_session_key: bytes
    committed: bool = False

    def commit(self, state: "RekeyableState") -> None:
        if self.committed:
            return  # idempotent

        # Stage170-A: explicitly wipe old key material (marker; bytes are immutable)
        wipe_bytes_like(state.session_key)

        state.session_key = self.next_session_key
        state.epoch = self.next_epoch
        self.committed = True

        # Stage170-A: optionally wipe next_session_key holder after install?
        # Do NOT wipe next_session_key here because it is the installed key in state.


@dataclass
class RekeyableState:
    """
    Minimal state interface your session layer should expose.
    (You can wrap your existing session object to match this shape.)
    """
    epoch: int
    session_key: bytes
