# MIT License © 2025 Motohiro Suzuki
import pytest

from qsp.minicore import MiniCore, ProtocolViolation


def test_rekey_rejected_before_handshake():
    c = MiniCore()
    with pytest.raises(ProtocolViolation):
        c.accept_frame({"type": "REKEY", "session_id": 123, "epoch": 1, "payload": b"x"})
