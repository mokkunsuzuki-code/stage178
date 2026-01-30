# Expected Failures (Fail-Closed) — Stage176
MIT License © 2025 Motohiro Suzuki

This document defines **expected and correct failure behaviors** for Stage176.
When an anomaly or attack is triggered, the protocol MUST fail closed.

Fail-closed means:
- invalid input is rejected
- the session/connection is terminated
- auditable evidence logs are produced
- no secret material is leaked

---

## Global Rule: Fail-Closed

If **any** of the following checks fail, the implementation MUST:

1. Reject the operation or handshake
2. Close the session/connection immediately
3. Emit evidence logs under:
   - `out/logs/`
   - bundled into `out/evidence/`

---

## Defined Scenarios

### A1 — Tampered Signature / Transcript

**Trigger**
- Signature verification fails
- Transcript hash mismatch is detected

**Expected Behavior**
- Handshake MUST be rejected
- Connection MUST close (fail-closed)

**Evidence**
- `out/logs/attack_01_tamper_sig.json` (Stage176 placeholder)
- Later stages: audit events such as  
  `HANDSHAKE_REJECTED`, `CLOSE(reason=BAD_SIGNATURE)`

---

### A2 — Replay Attack (CHLO / SHLO)

**Trigger**
- Replayed nonce
- Replayed handshake message

**Expected Behavior**
- Reject replayed message
- Close connection

**Evidence**
- Audit event: `REPLAY_DETECTED`
- Close reason: `CLOSE(reason=REPLAY)`

---

### A3 — Epoch Rollback or Mismatch

**Trigger**
- Remote epoch is lower than local epoch
- Epoch continuity is violated

**Expected Behavior**
- Immediate close
- No rekey, no fallback

**Evidence**
- `CLOSE(reason=EPOCH_MISMATCH)`
- Epoch values recorded in logs

---

### A4 — Truncated or Malformed Frame

**Trigger**
- TLV parse error
- Frame length mismatch

**Expected Behavior**
- Parsing fails
- Connection closes safely

**Evidence**
- `PARSE_FAIL`
- `CLOSE(reason=BAD_FRAME)`

---

### A5 — QKD Mismatch or Unavailability

**Trigger**
- QKD-derived key mismatch
- QKD source unavailable

**Expected Behavior**
- **Mismatch**: close immediately (fail-closed)
- **Unavailable**: safe failover to `PQC_ONLY` mode *if configured*

**Evidence**
- `CLOSE(reason=QKD_MISMATCH)`
- OR `FAILOVER(mode=PQC_ONLY)` with provenance record

---

## Non-Goals (PoC Scope)

This Stage176 PoC does **not** claim:

- production-grade side-channel resistance
- cryptographic strength of toy algorithms
- security guarantees of real QKD hardware

The focus is on:
- reproducibility (Docker + scripts)
- correctness of fail-closed behavior
- auditable evidence for external evaluation
