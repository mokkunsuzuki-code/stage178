# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import asyncio
import os

from protocol.config import ProtocolConfig
from crypto.algorithms import AlgorithmSuite
from transport.io_async import open_client, AsyncFrameIO

from protocol.handshake import client_handshake
from protocol.rekey import (
    decode_rekey_plaintext,
    RekeyInit,
    RekeyCommit,
    encode_rekey_ack,
    confirm_material,
)

from crypto.kdf import hkdf_sha256, build_ikm

HOST = "127.0.0.1"
PORT = 9000

REKEY_INFO = b"qsp-rekey-key-v1"
REKEY_SALT = b"QSP-167"


def derive_rekey_key(material: bytes, qkd_bytes: bytes, key_len: int) -> bytes:
    ikm = build_ikm(qkd=qkd_bytes if qkd_bytes else None, kem=material)
    return hkdf_sha256(ikm=ikm, salt=REKEY_SALT, info=REKEY_INFO, length=int(key_len))


def make_config() -> ProtocolConfig:
    suite = AlgorithmSuite(
        supported_sigs=["ed25519"],
        supported_kems=["toy_kem"],
        supported_aeads=["aes-gcm"],
    )
    return ProtocolConfig(
        suite=suite,
        sig_alg="ed25519",
        kem_alg="toy_kem",
        key_len=32,
        enable_qkd=True,
        qkd_seed=1234,
    )


def _do_epoch_rollback() -> bool:
    return os.environ.get("QSP_ATTACK03_EPOCH_ROLLBACK", "").strip() == "1"


async def main() -> None:
    io = await open_client(HOST, PORT)
    cfg = make_config()

    try:
        r = await client_handshake(io, cfg)

        if hasattr(r, "ok"):
            if not r.ok:
                print("[client167] handshake FAILED")
                print("failure =", r.failure)
                return
            hr = r.value
        else:
            hr = r

        print("[client167] handshake OK")
        print(f"session_id={hr.session_id}")
        print(f"epoch={hr.epoch}")

        # ---- Receive INIT ----
        f = await io.recv_rekey()
        msg = decode_rekey_plaintext(f.payload)
        if not isinstance(msg, RekeyInit):
            raise RuntimeError("expected RekeyInit, got something else")

        # PRE-COMMIT derive (client side)
        next_key = derive_rekey_key(msg.material, msg.qkd_bytes, cfg.key_len)
        print(f"[client167] [rekey] PRE-COMMIT ok new_epoch={msg.new_epoch} qkd_len={len(msg.qkd_bytes)}")

        # Send normal ACK
        conf = confirm_material(msg.material, msg.qkd_bytes)
        ack_pt = encode_rekey_ack(new_epoch=msg.new_epoch, confirm=conf)
        await io.send_rekey(session_id=hr.session_id, epoch=hr.epoch, seq=1, payload=ack_pt, flags=0)
        print("[client167] [rekey] sent ACK")

        # Wait COMMIT
        f2 = await asyncio.wait_for(io.recv_rekey(), timeout=5.0)
        msg2 = decode_rekey_plaintext(f2.payload)
        if not isinstance(msg2, RekeyCommit):
            raise RuntimeError("expected RekeyCommit, got something else")

        if msg2.new_epoch != msg.new_epoch:
            raise RuntimeError(f"commit epoch mismatch: expected {msg.new_epoch}, got {msg2.new_epoch}")

        # COMMIT
        committed_epoch = msg2.new_epoch
        _session_key = next_key
        print(f"[client167] [rekey] COMMIT ok epoch={committed_epoch} session_key_len={len(_session_key)}")

        # ---- Attack-03: send a rollback ACK AFTER COMMIT ----
        if _do_epoch_rollback():
            rollback_epoch = committed_epoch - 1  # intentionally older
            bad_ack = encode_rekey_ack(new_epoch=rollback_epoch, confirm=conf)
            await io.send_rekey(session_id=hr.session_id, epoch=committed_epoch, seq=2, payload=bad_ack, flags=0)
            print(
                "[client167] [attack-03] sent ROLLBACK ACK after commit "
                f"(ack.new_epoch={rollback_epoch}, current_epoch={committed_epoch})"
            )

        # let server process
        await asyncio.sleep(0.3)

    finally:
        await io.close()


if __name__ == "__main__":
    asyncio.run(main())
