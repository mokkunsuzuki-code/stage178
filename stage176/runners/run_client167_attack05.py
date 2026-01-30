# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import asyncio

from transport.io_async import open_client
from transport.io_async import AsyncFrameIO

from protocol.config import ProtocolConfig
from crypto.algorithms import AlgorithmSuite

from protocol.handshake import client_handshake
from protocol.rekey import (
    decode_rekey_plaintext,
    encode_rekey_ack,
    RekeyInit,
    confirm_material,
)

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
    io: AsyncFrameIO = await open_client(HOST, PORT)
    cfg = make_config()

    try:
        r = await client_handshake(io, cfg)
        hr = r.value if hasattr(r, "ok") and r.ok else r

        session_id = hr.session_id
        epoch = hr.epoch

        f = await io.recv_rekey()
        msg = decode_rekey_plaintext(f.payload)
        if not isinstance(msg, RekeyInit):
            raise RuntimeError("expected RekeyInit")

        new_epoch = int(msg.new_epoch)

        c = confirm_material(msg.material, bytes(msg.qkd_bytes))
        ack_pt = encode_rekey_ack(new_epoch=new_epoch, confirm=c)

        # Attack-05: confuse header epoch/seq (payload is correct)
        bad_epoch = new_epoch          # should be old epoch
        bad_seq = 99                  # should be expected seq
        await io.send_rekey(session_id=session_id, epoch=bad_epoch, seq=bad_seq, payload=ack_pt, flags=0)

        await asyncio.sleep(0.2)

    finally:
        await io.close()


if __name__ == "__main__":
    asyncio.run(main())
