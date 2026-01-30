# MIT License © 2025 Motohiro Suzuki
from __future__ import annotations

import os
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any

from crypto.kdf import hkdf_sha256, build_ikm
from crypto.zeroize import wipe_bytes_like  # Stage170-A
from protocol.hs_tlv import (
    CHLO,
    SHLO,
    canonical_body_bytes,
    HS_CHLO,
    HS_SHLO,
    T_MSG_TYPE,
    T_CLIENT_NONCE,
    T_SESSION_ID,
    T_KEM_CT,
    T_QKD_KEY,
)
import crypto.sig_backends as sb
from keysources.qkd_factory import make_qkd_source

# Stage166: Key Policy
from policy.key_policy import KeyPolicy, QKDState, QKDMetrics

# Stage167-A: Failover policy + audit (optional; attached by ProtocolCore)
from policy.failover import QKDStatus, FailoverMode

from protocol.result import Result
from protocol.failure import (
    Failure,
    FailureLayer,
    FailurePhase,
    FailureCode,
    CloseReason,
)

HKDF_SALT = b"QSP-160"
HKDF_INFO = b"qsp-session-key-v1"


def derive_session_key(kem_ss: bytes, qkd_key: Optional[bytes], key_len: int) -> bytes:
    # Stage170-A: build_ikm returns bytes; cannot guarantee in-place wipe,
    # but still explicit marker calls around derived secret material lifetime.
    ikm = build_ikm(qkd=qkd_key, kem=kem_ss)
    try:
        return hkdf_sha256(
            ikm=ikm,
            salt=HKDF_SALT,
            info=HKDF_INFO,
            length=int(key_len),
        )
    finally:
        wipe_bytes_like(ikm)  # Stage170-A marker


@dataclass(frozen=True)
class HandshakeResult:
    session_id: int
    epoch: int
    session_key: bytes
    qkd_source: str | None = None
    qkd_key_id: str | None = None


# =========================
# Config compatibility (Stage167-B)
# =========================
def _qkd_enabled(cfg: Any) -> bool:
    """
    Your current ProtocolConfig style:
      - enable_qkd: bool
    (No cfg.qkd object exists)
    """
    return bool(getattr(cfg, "enable_qkd", False))


def _qkd_source_name(cfg: Any) -> str | None:
    """
    Optional: if you later add qkd_source, we pick it up.
    Otherwise None (safe).
    """
    v = getattr(cfg, "qkd_source", None)
    return str(v) if isinstance(v, str) and v.strip() else None


# =========================
# Stage166 helpers
# =========================
def _get_policy(cfg: Any) -> KeyPolicy:
    kp = getattr(cfg, "key_policy", None)
    if isinstance(kp, KeyPolicy):
        return kp

    return KeyPolicy(
        rekey_max_seconds=int(getattr(cfg, "rekey_max_seconds", 60)),
        rekey_max_bytes=int(getattr(cfg, "rekey_max_bytes", 1024 * 1024)),
        qber_max=float(getattr(cfg, "qber_max", 0.05)),
        chsh_min=float(getattr(cfg, "chsh_min", 2.4)),
        budget_high=int(getattr(cfg, "qkd_budget_high", 32)),
        budget_low=int(getattr(cfg, "qkd_budget_low", 16)),
    )


def _qkd_metrics_from_source(ks: Any, km: Any) -> QKDMetrics | None:
    qber = getattr(ks, "last_qber", None)
    chsh = getattr(ks, "last_chsh", None)

    if qber is None and chsh is None:
        qber = getattr(km, "qber", None)
        chsh = getattr(km, "chsh", None)

    if qber is None and chsh is None:
        return None

    return QKDMetrics(
        qber=None if qber is None else float(qber),
        chsh=None if chsh is None else float(chsh),
    )


def _qkd_remaining_budget(ks: Any, qkd_key: bytes | None) -> int:
    rem = getattr(ks, "remaining_budget", None)
    if rem is not None:
        try:
            return int(rem)
        except Exception:
            pass
    return int(len(qkd_key)) if qkd_key is not None else 0


def _emit_audit(cfg: Any, record: dict) -> None:
    path = getattr(cfg, "audit_log_path", None)
    if isinstance(path, str) and path.strip():
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False)
            f.write("\n")


def _emit_stage167_failover(
    cfg: Any,
    *,
    epoch: int,
    reason: str,
    qber: float | None,
    budget_bytes: int | None,
    detail: str,
) -> None:
    audit = getattr(cfg, "audit", None)
    if audit is None:
        return
    try:
        audit.failover(
            epoch=epoch,
            reason=reason,
            qber=qber,
            budget_bytes=budget_bytes,
            detail=detail,
        )
    except Exception:
        pass


def _emit_stage167_info(
    cfg: Any,
    *,
    epoch: int,
    mode: str,
    detail: str,
    qber: float | None,
    budget_bytes: int | None,
) -> None:
    audit = getattr(cfg, "audit", None)
    if audit is None:
        return
    try:
        audit.info(
            epoch=epoch,
            mode=mode,
            detail=detail,
            qber=qber,
            budget_bytes=budget_bytes,
        )
    except Exception:
        pass


# =========================
# Stage167-B: failure helpers
# =========================
async def _send_close_from_failure(io, *, session_id: int, epoch: int, failure: Failure) -> None:
    try:
        cr = CloseReason.from_failure_code(failure.code)
        await io.send_close(
            session_id=int(session_id),
            epoch=int(epoch),
            close_code=int(cr.value),
            message=None,
        )
    except Exception:
        pass


def _failure(
    *,
    layer: FailureLayer,
    phase: FailurePhase,
    code: FailureCode,
    fatal: bool,
    detail: str | None = None,
) -> Failure:
    return Failure(layer=layer, phase=phase, code=code, fatal=fatal, detail=detail)


# =========================
# Client
# =========================
async def client_handshake(io, cfg) -> Result[HandshakeResult]:
    epoch = 1
    session_id_for_close = 0

    cn = b""
    kem_ss = b""
    qkd_key: bytes | None = None

    try:
        sig = cfg.suite.get_sig(cfg.sig_alg)
        kem = cfg.suite.get_kem(cfg.kem_alg)

        cn = os.urandom(16)
        body = {
            T_MSG_TYPE: bytes([HS_CHLO]),
            T_CLIENT_NONCE: cn,
        }
        body_bytes = canonical_body_bytes(body)
        signature = sig.sign(body_bytes)

        chlo = CHLO(
            client_nonce=cn,
            sig_pub=sig.public_key_bytes(),
            signature=signature,
        )
        await io.send_handshake(chlo.to_bytes())

        shlo_blob = await io.recv_handshake()
        shlo = SHLO.parse(shlo_blob)

        backend = sb.get_sig_backend(cfg.sig_alg)
        shlo_body_bytes = canonical_body_bytes(shlo.body_fields())
        if not backend.verify(shlo.sig_pub, shlo_body_bytes, shlo.signature):
            fail = _failure(
                layer=FailureLayer.CRYPTO,
                phase=FailurePhase.HANDSHAKE,
                code=FailureCode.ERR_AUTH_FAILED,
                fatal=True,
                detail="server signature verify failed",
            )
            await _send_close_from_failure(io, session_id=session_id_for_close, epoch=epoch, failure=fail)
            return Result.Err(fail)

        kem_ss = kem.decap(shlo.kem_ct)

        # ---- FIX: do not assume cfg.qkd exists ----
        enable_qkd = _qkd_enabled(cfg)
        qkd_key = shlo.qkd_key if (enable_qkd and shlo.qkd_key) else None

        sk = derive_session_key(kem_ss, qkd_key, cfg.key_len)

        # Stage170-A: explicit wipe markers for handshake material
        wipe_bytes_like(kem_ss)
        wipe_bytes_like(qkd_key)
        wipe_bytes_like(cn)

        return Result.Ok(
            HandshakeResult(
                session_id=shlo.session_id,
                epoch=1,
                session_key=sk,
                qkd_source=_qkd_source_name(cfg) if enable_qkd else None,
            )
        )

    except ValueError as e:
        msg = f"{type(e).__name__}: {e}"
        code = FailureCode.ERR_PARSE
        if "unsupported wire version" in msg:
            code = FailureCode.ERR_VERSION_UNSUPPORTED
        fail = _failure(
            layer=FailureLayer.TRANSPORT,
            phase=FailurePhase.HANDSHAKE,
            code=code,
            fatal=True,
            detail=msg,
        )
        await _send_close_from_failure(io, session_id=session_id_for_close, epoch=epoch, failure=fail)
        return Result.Err(fail)

    except ConnectionError as e:
        msg = f"{type(e).__name__}: {e}"
        fail = _failure(
            layer=FailureLayer.TRANSPORT,
            phase=FailurePhase.HANDSHAKE,
            code=FailureCode.ERR_REMOTE_CLOSE if "peer sent CLOSE" in msg else FailureCode.ERR_INTERNAL,
            fatal=True,
            detail=msg,
        )
        await _send_close_from_failure(io, session_id=session_id_for_close, epoch=epoch, failure=fail)
        return Result.Err(fail)

    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        fail = _failure(
            layer=FailureLayer.PROTOCOL,
            phase=FailurePhase.HANDSHAKE,
            code=FailureCode.ERR_INTERNAL,
            fatal=True,
            detail=msg,
        )
        await _send_close_from_failure(io, session_id=session_id_for_close, epoch=epoch, failure=fail)
        return Result.Err(fail)

    finally:
        # Stage170-A: wipe on all exits
        wipe_bytes_like(cn)
        wipe_bytes_like(kem_ss)
        wipe_bytes_like(qkd_key)


# =========================
# Server
# =========================
async def server_handshake(io, cfg) -> Result[HandshakeResult]:
    epoch = 1
    session_id_for_close = 0

    kem_ss = b""
    qkd_key: bytes | None = None

    try:
        sig = cfg.suite.get_sig(cfg.sig_alg)
        kem = cfg.suite.get_kem(cfg.kem_alg)

        chlo_blob = await io.recv_handshake()
        chlo = CHLO.parse(chlo_blob)

        backend = sb.get_sig_backend(cfg.sig_alg)
        chlo_body_bytes = canonical_body_bytes(chlo.body_fields())
        if not backend.verify(chlo.sig_pub, chlo_body_bytes, chlo.signature):
            fail = _failure(
                layer=FailureLayer.CRYPTO,
                phase=FailurePhase.HANDSHAKE,
                code=FailureCode.ERR_AUTH_FAILED,
                fatal=True,
                detail="client signature verify failed",
            )
            await _send_close_from_failure(io, session_id=session_id_for_close, epoch=epoch, failure=fail)
            return Result.Err(fail)

        ct, kem_ss = kem.encap()

        qkd_key_id: str | None = None

        qkd_state = QKDState.UNAVAILABLE
        qkd_metrics: QKDMetrics | None = None
        remaining_budget = 0
        qkd_error: str | None = None

        enable_qkd = _qkd_enabled(cfg)

        if enable_qkd:
            policy = _get_policy(cfg)
            ks = make_qkd_source(cfg)

            km = None
            try:
                km = ks.provide(b"handshake")
                qkd_key = km.qkd
                qkd_key_id = getattr(ks, "last_key_id", None)
                qkd_state = QKDState.AVAILABLE if qkd_key is not None else QKDState.UNAVAILABLE
            except Exception as e:
                qkd_error = f"{type(e).__name__}: {e}"
                qkd_key = None
                qkd_key_id = None
                qkd_state = QKDState.UNAVAILABLE

            try:
                qkd_metrics = _qkd_metrics_from_source(ks, km) if km is not None else None
            except Exception:
                qkd_metrics = None
            try:
                remaining_budget = _qkd_remaining_budget(ks, qkd_key)
            except Exception:
                remaining_budget = 0

            decision = policy.evaluate_qkd(
                qkd_state=qkd_state,
                metrics=qkd_metrics,
                remaining_budget=remaining_budget,
            )

            if not decision.allow_qkd:
                qkd_key = None

            fo_policy = getattr(cfg, "failover_policy", None)

            qber_val: float | None = None if (qkd_metrics is None) else qkd_metrics.qber
            budget_val: int | None = int(remaining_budget)

            qkd_status = QKDStatus.OK if (qkd_key is not None and len(qkd_key) > 0) else QKDStatus.UNAVAILABLE

            if fo_policy is not None:
                fo = fo_policy.decide(
                    qkd_status=qkd_status,
                    qber=qber_val,
                    budget_bytes=budget_val,
                )
                if fo.mode == FailoverMode.PQC_ONLY:
                    qkd_key = None
                    _emit_stage167_failover(
                        cfg,
                        epoch=epoch,
                        reason=(fo.reason.value if fo.reason else "UNKNOWN"),
                        qber=qber_val,
                        budget_bytes=budget_val,
                        detail="Stage167-A: handshake derive keys WITHOUT QKD mix",
                    )
                else:
                    _emit_stage167_info(
                        cfg,
                        epoch=epoch,
                        mode=fo.mode.value,
                        detail="Stage167-A: handshake continues with PQC+QKD",
                        qber=qber_val,
                        budget_bytes=budget_val,
                    )

            audit_record = {
                "key_id": str(uuid.uuid4()),
                "source": "QKD+PQC" if decision.allow_qkd else "PQC-only",
                "qkd_metrics": None
                if qkd_metrics is None
                else {"qber": qkd_metrics.qber, "chsh": qkd_metrics.chsh},
                "decision": decision.reason,
                "timestamp": time.time(),
                "usage": "HANDSHAKE",
                "qkd_state": qkd_state.value,
                "remaining_budget": remaining_budget,
                "qkd_error": qkd_error,
            }
            _emit_audit(cfg, audit_record)

        sid = int.from_bytes(os.urandom(8), "big")
        session_id_for_close = sid

        body = {
            T_MSG_TYPE: bytes([HS_SHLO]),
            T_SESSION_ID: sid.to_bytes(8, "big"),
            T_KEM_CT: bytes(ct),
        }
        if qkd_key is not None:
            body[T_QKD_KEY] = bytes(qkd_key)

        body_bytes = canonical_body_bytes(body)
        signature = sig.sign(body_bytes)

        shlo = SHLO(
            session_id=sid,
            kem_ct=ct,
            qkd_key=qkd_key,
            sig_pub=sig.public_key_bytes(),
            signature=signature,
        )
        await io.send_handshake(shlo.to_bytes())

        sk = derive_session_key(kem_ss, qkd_key, cfg.key_len)

        # Stage170-A: explicit wipe markers for handshake material
        wipe_bytes_like(kem_ss)
        wipe_bytes_like(qkd_key)

        return Result.Ok(
            HandshakeResult(
                session_id=sid,
                epoch=1,
                session_key=sk,
                qkd_source=_qkd_source_name(cfg) if enable_qkd else None,
                qkd_key_id=qkd_key_id,
            )
        )

    except ValueError as e:
        msg = f"{type(e).__name__}: {e}"
        code = FailureCode.ERR_PARSE
        if "unsupported wire version" in msg:
            code = FailureCode.ERR_VERSION_UNSUPPORTED
        fail = _failure(
            layer=FailureLayer.TRANSPORT,
            phase=FailurePhase.HANDSHAKE,
            code=code,
            fatal=True,
            detail=msg,
        )
        await _send_close_from_failure(io, session_id=session_id_for_close, epoch=epoch, failure=fail)
        return Result.Err(fail)

    except ConnectionError as e:
        msg = f"{type(e).__name__}: {e}"
        fail = _failure(
            layer=FailureLayer.TRANSPORT,
            phase=FailurePhase.HANDSHAKE,
            code=FailureCode.ERR_REMOTE_CLOSE if "peer sent CLOSE" in msg else FailureCode.ERR_INTERNAL,
            fatal=True,
            detail=msg,
        )
        await _send_close_from_failure(io, session_id=session_id_for_close, epoch=epoch, failure=fail)
        return Result.Err(fail)

    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        fail = _failure(
            layer=FailureLayer.PROTOCOL,
            phase=FailurePhase.HANDSHAKE,
            code=FailureCode.ERR_INTERNAL,
            fatal=True,
            detail=msg,
        )
        await _send_close_from_failure(io, session_id=session_id_for_close, epoch=epoch, failure=fail)
        return Result.Err(fail)

    finally:
        # Stage170-A: wipe on all exits
        wipe_bytes_like(kem_ss)
        wipe_bytes_like(qkd_key)
