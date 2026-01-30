# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import asyncio

from protocol.config import ProtocolConfig
from crypto.algorithms import AlgorithmSuite
from transport.io_async import AsyncFrameIO

from protocol.handshake import server_handshake
from protocol.rekey import (
    make_material,
    encode_rekey_init,
    encode_rekey_commit,
    decode_rekey_plaintext,
    RekeyAck,
    confirm_material,
)

from crypto.kdf import hkdf_sha256, build_ikm
from protocol.stage167_a_core import ProtocolCore

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


async def do_one_rekey_as_server(io: AsyncFrameIO, *, session_id: int, epoch: int, cfg: ProtocolConfig) -> tuple[int, bytes]:
    new_epoch = epoch + 1
    material = make_material(32)

    core = ProtocolCore(cfg)
    qkd_bytes, decision = core.try_get_qkd_for_rekey()

    init_pt = encode_rekey_init(new_epoch=new_epoch, material=material, qkd_bytes=qkd_bytes)

    print(
        f"[server167] [rekey] send INIT new_epoch={new_epoch} "
        f"qkd_len={len(qkd_bytes)} used_qkd={decision.used_qkd} reason={decision.reason}"
    )
    await io.send_rekey(session_id=session_id, epoch=epoch, seq=1, payload=init_pt, flags=0)

    next_key = derive_rekey_key(material, qkd_bytes, cfg.key_len)
    print("[server167] [rekey] PRE-COMMIT ok (derived next_key) -> waiting ACK")

    f = await asyncio.wait_for(io.recv_rekey(), timeout=5.0)
    msg = decode_rekey_plaintext(f.payload)
    if not isinstance(msg, RekeyAck):
        raise RuntimeError("expected RekeyAck, got something else")

    expect = confirm_material(material, qkd_bytes)
    if msg.new_epoch != new_epoch:
        raise RuntimeError(f"ack epoch mismatch: expected {new_epoch}, got {msg.new_epoch}")
    if msg.confirm != expect:
        raise RuntimeError("ack confirm mismatch")

    commit_pt = encode_rekey_commit(new_epoch=new_epoch)
    await io.send_rekey(session_id=session_id, epoch=epoch, seq=2, payload=commit_pt, flags=0)

    epoch = new_epoch
    session_key = next_key
    print(f"[server167] [rekey] COMMIT ok epoch={epoch} session_key_len={len(session_key)}")

    # ---- Attack-03 detector: after COMMIT, observe one extra REKEY and detect rollback ----
    try:
        f_extra = await asyncio.wait_for(io.recv_rekey(), timeout=1.2)
        extra = decode_rekey_plaintext(f_extra.payload)
        if isinstance(extra, RekeyAck):
            # rollback definition for PoC: payload's new_epoch < current epoch
            if extra.new_epoch < epoch:
                print(
                    f"[server167] EPOCH ROLLBACK DETECTED: post-commit extra REKEY "
                    f"(epoch={epoch}) ack.new_epoch={extra.new_epoch}"
                )
                raise RuntimeError("EPOCH ROLLBACK DETECTED")
            else:
                # not rollback, but still "unexpected extra REKEY"
                print(
                    f"[server167] UNEXPECTED EXTRA REKEY: post-commit extra REKEY "
                    f"(epoch={epoch}) type=RekeyAck ack.new_epoch={extra.new_epoch}"
                )
        else:
            print(
                f"[server167] UNEXPECTED EXTRA REKEY: post-commit extra REKEY "
                f"(epoch={epoch}) type={type(extra).__name__}"
            )
    except asyncio.TimeoutError:
        # No extra frame => normal
        pass

    return epoch, session_key


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    io = AsyncFrameIO(reader, writer)
    cfg = make_config()

    try:
        r = await server_handshake(io, cfg)
        if hasattr(r, "ok"):
            if not r.ok:
                print("[server167] handshake FAILED")
                print("failure =", r.failure)
                return
            hr = r.value
        else:
            hr = r

        print("[server167] handshake OK")
        print(f"session_id={hr.session_id}")
        print(f"epoch={hr.epoch}")

        try:
            new_epoch, _new_key = await do_one_rekey_as_server(
                io,
                session_id=hr.session_id,
                epoch=hr.epoch,
                cfg=cfg,
            )
            print(f"[server167] rekey done -> epoch={new_epoch}")
        except Exception as e:
            print("[server167] rekey FAILED")
            print("error =", f"{type(e).__name__}: {e}")
            try:
                await io.send_close(session_id=hr.session_id, epoch=hr.epoch, close_code=255, message=str(e))
            except Exception:
                pass

    finally:
        await io.close()


async def main() -> None:
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    print(f"[server167] listening on {addrs}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
