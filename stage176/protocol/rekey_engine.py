# MIT License © 2025 Motohiro Suzuki
"""
protocol/rekey_engine.py  (Stage166 -> Stage167-A -> Stage170-A)

Purpose:
- Make REKEY runnable over FT_REKEY frames.
- Connect KeyPolicy.should_rekey() to a live loop (time/bytes trigger).
- Tolerate QKD outage: if QKD fetch fails, fall back to PQC-only and continue.
- Emit audit record for REKEY when possible.

Stage167-A additions:
- Explicit PQC↔QKD failover decision for REKEY (using cfg.failover_policy if present)
- Emit Stage167 audit evidence (cfg.audit -> out/stage167_audit.jsonl) on FAILOVER

Stage170-A additions:
- Explicit secret zeroize/wipe markers for secret lifetime management.
  (Best-effort in Python; bytes are immutable, but calls are reviewable + scanner-detectable.)

Stage176 fix:
- Detect WRONG SESSION_ID on REKEY/ACK paths (fail-closed).
  (Attack-04: wrong session_id NOT detected -> fixed by checking frame.session_id.)

NOTE:
- This is a research-grade demo rekey. The FT_REKEY payload is plaintext here.
  (Stage167-B can add AEAD protection and transcript binding.)
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from crypto.kdf import hkdf_sha256
from crypto.zeroize import wipe_bytes_like  # Stage170-A
from keysources.qkd_factory import make_qkd_source
from policy.key_policy import KeyPolicy, QKDState, QKDMetrics
from protocol.rekey import (
    make_material,
    encode_rekey_init,
    encode_rekey_ack,
    decode_rekey_plaintext,
    RekeyInit,
    RekeyAck,
    confirm_material,
)

# Stage167-A (optional hook; attached by ProtocolCore)
from policy.failover import QKDStatus, FailoverMode

_REKEY_SALT = b"QSP-REKEY-166"
_REKEY_INFO = b"qsp-rekey-v1"


@dataclass
class RekeyRuntimeState:
    session_id: int
    epoch: int
    session_key: bytes

    last_rekey_ts: float
    bytes_since_rekey: int
    seq: int  # monotonic per-session sequence (for frames)


def _must_match_session_id(observed: int, expected: int, *, phase: str) -> None:
    if int(observed) != int(expected):
        # log string should be grep-able for evidence
        print(f"[rekey_engine] WRONG SESSION_ID DETECTED: phase={phase} expected={expected} got={observed}")
        raise RuntimeError("WRONG SESSION_ID")


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
    """
    Stage167-A audit evidence sink:
      - cfg.audit (Stage167AuditLog) if attached by ProtocolCore
      - else: no-op
    """
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
        # Must NOT break rekey due to logging
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


def _qkd_metrics_from_source(ks: Any, km: Any) -> QKDMetrics | None:
    qber = getattr(ks, "last_qber", None)
    chsh = getattr(ks, "last_chsh", None)
    if qber is None and chsh is None and km is not None:
        qber = getattr(km, "qber", None)
        chsh = getattr(km, "chsh", None)
    if qber is None and chsh is None:
        return None
    return QKDMetrics(
        qber=None if qber is None else float(qber),
        chsh=None if chsh is None else float(chsh),
    )


def _qkd_remaining_budget(ks: Any, qkd_key: Optional[bytes]) -> int:
    rem = getattr(ks, "remaining_budget", None)
    if rem is not None:
        try:
            return int(rem)
        except Exception:
            pass
    return int(len(qkd_key)) if qkd_key is not None else 0


def _fallback_should_rekey_from_cfg(cfg: Any, elapsed_sec: float, bytes_since_rekey: int) -> bool:
    """
    Safety net:
    If KeyPolicy.should_rekey() is missing or signature mismatch, fall back to:
      - cfg.rekey_max_seconds
      - cfg.rekey_max_bytes
    """
    try:
        e = float(elapsed_sec)
    except Exception:
        e = 0.0
    try:
        b = int(bytes_since_rekey)
    except Exception:
        b = 0

    sec = getattr(cfg, "rekey_max_seconds", None)
    byt = getattr(cfg, "rekey_max_bytes", None)

    try:
        sec_i = int(sec) if sec is not None else 0
    except Exception:
        sec_i = 0
    try:
        byt_i = int(byt) if byt is not None else 0
    except Exception:
        byt_i = 0

    if sec_i > 0 and e >= float(sec_i):
        return True
    if byt_i > 0 and b >= byt_i:
        return True
    return False


def _policy_should_rekey(policy: Any, cfg: Any, *, elapsed_sec: float, bytes_since_rekey: int) -> bool:
    """
    Call KeyPolicy.should_rekey() in a signature-tolerant way.

    - If policy.should_rekey exists, try common keyword signatures + positional.
    - If it doesn't exist or all attempts fail, use fallback based on cfg thresholds.
    """
    fn = getattr(policy, "should_rekey", None)
    if not callable(fn):
        return _fallback_should_rekey_from_cfg(cfg, elapsed_sec, bytes_since_rekey)

    for kwargs in (
        {"elapsed_sec": elapsed_sec, "bytes_since_rekey": bytes_since_rekey},
        {"elapsed_seconds": elapsed_sec, "bytes_since_rekey": bytes_since_rekey},
        {"elapsed": elapsed_sec, "bytes": bytes_since_rekey},
    ):
        try:
            return bool(fn(**kwargs))
        except TypeError:
            pass
        except Exception:
            return _fallback_should_rekey_from_cfg(cfg, elapsed_sec, bytes_since_rekey)

    try:
        return bool(fn(elapsed_sec, bytes_since_rekey))
    except TypeError:
        return _fallback_should_rekey_from_cfg(cfg, elapsed_sec, bytes_since_rekey)
    except Exception:
        return _fallback_should_rekey_from_cfg(cfg, elapsed_sec, bytes_since_rekey)


def _derive_rekeyed_session_key(old_key: bytes, material: bytes, qkd_bytes: bytes, out_len: int) -> bytes:
    """
    Research/demo rekey KDF:
      new_key = HKDF( ikm = old_key || material || b"|qkd|" || qkd_bytes )

    Stage170-A:
      - wipe temporary IKM buffer (best-effort).
    """
    ikm = bytearray(bytes(old_key) + bytes(material) + b"|qkd|" + bytes(qkd_bytes))
    try:
        return hkdf_sha256(ikm=bytes(ikm), salt=_REKEY_SALT, info=_REKEY_INFO, length=int(out_len))
    finally:
        wipe_bytes_like(ikm)  # Stage170-A explicit marker


def try_get_qkd_for_rekey(cfg: Any) -> tuple[bytes, QKDState, QKDMetrics | None, int, str | None, str | None]:
    """
    Returns:
      qkd_bytes, qkd_state, metrics, remaining_budget, qkd_error, qkd_key_id
    """
    qkd_bytes: bytes = b""
    qkd_state = QKDState.UNAVAILABLE
    metrics: QKDMetrics | None = None
    remaining = 0
    qkd_error: str | None = None
    qkd_key_id: str | None = None

    ks = make_qkd_source(cfg)
    km = None
    try:
        km = ks.provide(b"rekey")
        qkd_bytes = bytes(km.qkd) if getattr(km, "qkd", None) is not None else b""
        qkd_key_id = getattr(ks, "last_key_id", None)
        qkd_state = QKDState.AVAILABLE if qkd_bytes else QKDState.UNAVAILABLE
    except Exception as e:
        qkd_error = f"{type(e).__name__}: {e}"
        qkd_bytes = b""
        qkd_state = QKDState.UNAVAILABLE
        qkd_key_id = None

    try:
        metrics = _qkd_metrics_from_source(ks, km)
    except Exception:
        metrics = None

    try:
        remaining = _qkd_remaining_budget(ks, qkd_bytes if qkd_bytes else None)
    except Exception:
        remaining = 0

    return qkd_bytes, qkd_state, metrics, remaining, qkd_error, qkd_key_id


async def client_maybe_rekey(io, cfg: Any, st: RekeyRuntimeState) -> RekeyRuntimeState:
    """
    Client-side rekey trigger:
    - Evaluate policy.should_rekey(elapsed, bytes)
    - If True: send REKEY_INIT, wait REKEY_ACK, then commit new epoch/key.

    Stage167-A:
    - Evaluate cfg.failover_policy (if present) and emit cfg.audit FAILOVER evidence.

    Stage170-A:
    - Explicit wipe markers for secrets once committed / once decisions are finalized.

    Stage176 fix:
    - Verify ACK frame session_id matches current session (Attack-04).
    """
    policy = _get_policy(cfg)
    elapsed = time.time() - st.last_rekey_ts

    if not _policy_should_rekey(policy, cfg, elapsed_sec=elapsed, bytes_since_rekey=st.bytes_since_rekey):
        return st

    # Prepare material + optional QKD (policy-gated)
    material = make_material(32)

    qkd_bytes, qkd_state, metrics, remaining, qkd_error, qkd_key_id = (b"", QKDState.UNAVAILABLE, None, 0, None, None)
    allow_qkd = False
    reason = "QKD disabled (cfg)"

    if getattr(cfg, "qkd", None) is not None and getattr(cfg.qkd, "enabled", False):
        qkd_bytes, qkd_state, metrics, remaining, qkd_error, qkd_key_id = try_get_qkd_for_rekey(cfg)
        decision = policy.evaluate_qkd(qkd_state=qkd_state, metrics=metrics, remaining_budget=remaining)
        allow_qkd = bool(decision.allow_qkd)
        reason = decision.reason
        if not allow_qkd:
            qkd_bytes = b""
    else:
        qkd_bytes = b""
        qkd_state = QKDState.UNAVAILABLE

    # ---- Stage167-A failover (client-side) ----
    fo_policy = getattr(cfg, "failover_policy", None)
    new_epoch = int(st.epoch) + 1

    qber_val: float | None
    if metrics is None or metrics.qber is None:
        qber_val = 0.0  # unknown treated as "not exceeded" for demo stability
    else:
        qber_val = float(metrics.qber)

    budget_val: int | None = int(remaining)
    qkd_status = QKDStatus.OK if (qkd_bytes is not None and len(qkd_bytes) > 0) else QKDStatus.UNAVAILABLE

    if fo_policy is not None:
        fo = fo_policy.decide(
            qkd_status=qkd_status,
            qber=qber_val,
            budget_bytes=budget_val,
        )
        if fo.mode == FailoverMode.PQC_ONLY:
            qkd_bytes = b""
            allow_qkd = False
            _emit_stage167_failover(
                cfg,
                epoch=new_epoch,
                reason=(fo.reason.value if fo.reason else "UNKNOWN"),
                qber=qber_val,
                budget_bytes=budget_val,
                detail="Stage167-A: rekey derive keys WITHOUT QKD mix (client)",
            )
        else:
            _emit_stage167_info(
                cfg,
                epoch=new_epoch,
                mode=fo.mode.value,
                detail="Stage167-A: rekey continues with PQC+QKD (client)",
                qber=qber_val,
                budget_bytes=budget_val,
            )

    # Encode INIT after qkd_bytes is finalized
    init_pt = encode_rekey_init(new_epoch=new_epoch, material=material, qkd_bytes=qkd_bytes)

    st.seq += 1
    await io.send_rekey(session_id=st.session_id, epoch=st.epoch, seq=st.seq, payload=init_pt)

    # Wait for ACK
    f = await io.recv_rekey()

    # ★ Stage176: wrong session_id must fail-closed
    _must_match_session_id(f.session_id, st.session_id, phase="CLIENT_WAIT_ACK")

    msg = decode_rekey_plaintext(f.payload)
    if not isinstance(msg, RekeyAck):
        # Stage170-A: wipe before raising
        wipe_bytes_like(material)
        wipe_bytes_like(qkd_bytes)
        raise RuntimeError("expected REKEY_ACK")

    expected = confirm_material(material, qkd_bytes)
    if msg.new_epoch != new_epoch or msg.confirm != expected:
        # Stage170-A: wipe before raising
        wipe_bytes_like(material)
        wipe_bytes_like(qkd_bytes)
        wipe_bytes_like(expected)
        raise RuntimeError("rekey confirm mismatch")

    # Commit: update session key + epoch
    old_key = st.session_key
    new_key = _derive_rekeyed_session_key(old_key, material, qkd_bytes, out_len=len(old_key))

    audit = {
        "key_id": str(uuid.uuid4()),
        "source": "QKD+PQC" if allow_qkd else "PQC-only",
        "qkd_metrics": None if metrics is None else {"qber": metrics.qber, "chsh": metrics.chsh},
        "decision": reason,
        "timestamp": time.time(),
        "usage": "REKEY",
        "qkd_state": qkd_state.value,
        "remaining_budget": remaining,
        "qkd_error": qkd_error,
        "qkd_key_id": qkd_key_id,
        "new_epoch": new_epoch,
    }
    _emit_audit(cfg, audit)

    # Stage170-A: wipe secrets that should not live past commit decision
    # (best-effort markers)
    wipe_bytes_like(material)
    wipe_bytes_like(qkd_bytes)
    wipe_bytes_like(expected)
    wipe_bytes_like(old_key)  # cannot wipe immutable bytes, but explicit marker

    return RekeyRuntimeState(
        session_id=st.session_id,
        epoch=new_epoch,
        session_key=new_key,
        last_rekey_ts=time.time(),
        bytes_since_rekey=0,
        seq=st.seq,
    )


async def server_handle_rekey_frame(
    io,
    cfg: Any,
    st: RekeyRuntimeState,
    payload: bytes,
    *,
    frame_session_id: int | None = None,
) -> RekeyRuntimeState:
    """
    Server-side: process ONE REKEY frame payload (INIT expected), send ACK, commit epoch/key.

    Stage167-A:
    - Evaluate cfg.failover_policy (if present) based on qkd_bytes / budget signals
    - Emit cfg.audit FAILOVER evidence when switching to PQC-only

    Stage170-A:
    - Explicit wipe markers for secrets once committed / once rejecting.

    Stage176 fix:
    - Verify REKEY frame session_id matches current session (Attack-04).
      NOTE: payload alone does not carry session_id; caller should pass frame_session_id=f.session_id.
    """
    if frame_session_id is not None:
        _must_match_session_id(frame_session_id, st.session_id, phase="SERVER_RECV_REKEY")

    msg = decode_rekey_plaintext(payload)
    if not isinstance(msg, RekeyInit):
        raise RuntimeError("expected REKEY_INIT")

    if msg.new_epoch != int(st.epoch) + 1:
        raise RuntimeError("rekey epoch mismatch")

    policy = _get_policy(cfg)

    # Demo: server enforces policy on the qkd_bytes provided in INIT payload.
    qkd_bytes = bytes(msg.qkd_bytes)
    qkd_state = QKDState.AVAILABLE if qkd_bytes else QKDState.UNAVAILABLE
    metrics = None
    remaining = len(qkd_bytes)

    decision = policy.evaluate_qkd(qkd_state=qkd_state, metrics=metrics, remaining_budget=remaining)
    allow_qkd = bool(decision.allow_qkd)
    if not allow_qkd:
        qkd_bytes = b""

    # ---- Stage167-A failover (server-side) ----
    fo_policy = getattr(cfg, "failover_policy", None)

    # Server may not have qber here; treat unknown as 0.0 for demo stability
    qber_val: float | None = 0.0
    budget_val: int | None = int(remaining)

    qkd_status = QKDStatus.OK if (qkd_bytes is not None and len(qkd_bytes) > 0) else QKDStatus.UNAVAILABLE

    if fo_policy is not None:
        fo = fo_policy.decide(
            qkd_status=qkd_status,
            qber=qber_val,
            budget_bytes=budget_val,
        )
        if fo.mode == FailoverMode.PQC_ONLY:
            qkd_bytes = b""
            allow_qkd = False
            _emit_stage167_failover(
                cfg,
                epoch=msg.new_epoch,
                reason=(fo.reason.value if fo.reason else "UNKNOWN"),
                qber=qber_val,
                budget_bytes=budget_val,
                detail="Stage167-A: rekey derive keys WITHOUT QKD mix (server)",
            )
        else:
            _emit_stage167_info(
                cfg,
                epoch=msg.new_epoch,
                mode=fo.mode.value,
                detail="Stage167-A: rekey continues with PQC+QKD (server)",
                qber=qber_val,
                budget_bytes=budget_val,
            )

    c = confirm_material(msg.material, qkd_bytes)
    ack_pt = encode_rekey_ack(new_epoch=msg.new_epoch, confirm=c)

    st.seq += 1
    await io.send_rekey(session_id=st.session_id, epoch=st.epoch, seq=st.seq, payload=ack_pt)

    old_key = st.session_key
    new_key = _derive_rekeyed_session_key(old_key, msg.material, qkd_bytes, out_len=len(old_key))

    audit = {
        "key_id": str(uuid.uuid4()),
        "source": "QKD+PQC" if allow_qkd else "PQC-only",
        "qkd_metrics": None,
        "decision": decision.reason,
        "timestamp": time.time(),
        "usage": "REKEY",
        "qkd_state": qkd_state.value,
        "remaining_budget": remaining,
        "qkd_error": None,
        "qkd_key_id": None,
        "new_epoch": msg.new_epoch,
    }
    _emit_audit(cfg, audit)

    # Stage170-A: wipe secrets after commit decision (markers)
    wipe_bytes_like(msg.material)
    wipe_bytes_like(qkd_bytes)
    wipe_bytes_like(c)
    wipe_bytes_like(old_key)

    return RekeyRuntimeState(
        session_id=st.session_id,
        epoch=msg.new_epoch,
        session_key=new_key,
        last_rekey_ts=time.time(),
        bytes_since_rekey=0,
        seq=st.seq,
    )
