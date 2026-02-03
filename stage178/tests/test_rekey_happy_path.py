# MIT License © 2025 Motohiro Suzuki
from qsp.minicore import MiniCore


def test_rekey_happy_path():
    c = MiniCore()

    r1 = c.accept_frame({"type": "HANDSHAKE_DONE", "session_id": 777, "epoch": 1, "payload": b""})
    fp1 = r1.key_fingerprint_hex

    r2 = c.accept_frame({"type": "REKEY", "session_id": 777, "epoch": 2, "payload": b"rekey"})
    fp2 = r2.key_fingerprint_hex

    assert r2.ok is True
    assert r2.epoch == 2
    assert fp1 != fp2
