# MIT License © 2025 Motohiro Suzuki
"""
protocol/handshake_types.py

Stage159: shared handshake types.

This module exists because protocol/handshake.py imports it.
"""

from __future__ import annotations

from dataclasses import dataclass


HS_CHLO = "CHLO"
HS_SHLO = "SHLO"


@dataclass(frozen=True)
class HandshakeResult:
    session_id: str
    epoch: int
    session_key: bytes
