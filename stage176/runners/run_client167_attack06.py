# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import asyncio

from protocol.config import ProtocolConfig
from crypto.algorithms import AlgorithmSuite
from transport.io_async import open_client

from protocol.handshake import client_handshake
from protocol.rekey import decode_rekey_plaintext, RekeyInit, encode_rekey_commit

HOST = "127.0.0.1"
PORT = 9000


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


async def main() -> None:
    cfg = make_config()
    io = await open_client(HOST, PORT)

    try:
        r = await client_handshake(io, cfg)
        hr = r.value if hasattr(r, "ok") and r.ok else r

        f = await asyncio.wait_for(io.recv_rekey(), timeout=5.0)
        msg = decode_rekey_plaintext(f.payload)
        if not isinstance(msg, RekeyInit):
            raise RuntimeError("expected RekeyInit from server")

        bad_commit = encode_rekey_commit(new_epoch=msg.new_epoch)

        await io.send_rekey(
            session_id=hr.session_id,
            epoch=hr.epoch,
            seq=1,
            payload=bad_commit,
            flags=0,
        )

        try:
            await asyncio.wait_for(io.recv_close(), timeout=2.0)
        except Exception:
            pass
    finally:
        await io.close()


if __name__ == "__main__":
    asyncio.run(main())
