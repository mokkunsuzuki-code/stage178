# QSP Report Summary

- Generated: `2026-01-30T07:23:22Z`
- Git commit: `5c45f9e`

This page provides a **single-glance PASS/FAIL overview** for both **Demo** and **Attack scenarios**.

## Overview

| Item | Status | Report | Evidence |
|---|---:|---|---|
| Demo | **PASS** | `out/evidence/logs/demo.json` | `out/logs/server167.log:2:[server167] handshake OK` |
| Attack-01 | **PASS** | `out/logs/attack_01_tamper_sig.json` | `out/logs/server167_attack01.log:46:error = RuntimeError: ack confirm mismatch` |
| Attack-02 | **PASS** | `out/logs/attack_02_replay.json` | `out/logs/server167_attack02.log:9:[server167] REPLAY DETECTED: post-commit extra REKEY observed (epoch=2) type=RekeyAck` |
| Attack-03 | **PASS** | `out/logs/attack_03_epoch_rollback.json` | `out/logs/server167_attack03.log:9:[server167] EPOCH ROLLBACK DETECTED: post-commit extra REKEY (epoch=2) ack.new_epoch=1` |
| Attack-04 | **PASS** | `out/logs/attack_04_wrong_session_id.json` | `out/logs/server167_attack04.log:8:[server167] WRONG SESSION_ID DETECTED: phase=WAIT_ACK expected=7986320003376335535 got=7986320003376335536` |
| Attack-05 | **PASS** | `out/logs/attack_05_key_schedule_confusion.json` | `out/logs/server167_attack05.log:8:[server167] BAD REKEY ACK HEADER: expected_epoch=1 got_epoch=2 expected_seq=1 got_seq=99` |
| Attack-06 | **PASS** | `out/logs/attack_06_phase_confusion.json` | `out/logs/server167_attack06.log:8:[server167] PHASE CONFUSION DETECTED: expected=RekeyAck got=RekeyCommit` |

## Demo

- Status: **PASS**
- Report: `out/evidence/logs/demo.json`
- Evidence: `out/logs/server167.log:2:[server167] handshake OK`

### Preview
```
{"stage":176,"case":"demo_real_runner167","ok":true,"client_rc":0,"ts_ms":1769744604315,"artifacts":{"server_log":"out/logs/server167.log","client_log":"out/logs/client167.log"}}

```

## Attack-01

- Status: **PASS**
- Report: `out/logs/attack_01_tamper_sig.json`
- Evidence: `out/logs/server167_attack01.log:46:error = RuntimeError: ack confirm mismatch`

### Preview
```
{"stage":176,"attack":"attack_01_tamper_sig","ts_utc":"2026-01-30T07:23:18Z","expected":"FAIL_CLOSED","observed":"FAIL_CLOSED_REKEY_REJECTED","ok":true,"client_rc":0,"artifacts":{"server_log":"out/logs/server167_attack01.log","client_log":"out/logs/client167_attack01.log"}}

```

## Attack-02

- Status: **PASS**
- Report: `out/logs/attack_02_replay.json`
- Evidence: `out/logs/server167_attack02.log:9:[server167] REPLAY DETECTED: post-commit extra REKEY observed (epoch=2) type=RekeyAck`

### Preview
```
{"stage":176,"attack":"attack_02_replay_ack","ts_utc":"2026-01-30T07:23:19Z","expected":"FAIL_CLOSED","observed":"FAIL_CLOSED_REPLAY_REJECTED","ok":true,"client_rc":0,"artifacts":{"server_log":"out/logs/server167_attack02.log","client_log":"out/logs/client167_attack02.log"}}

```

## Attack-03

- Status: **PASS**
- Report: `out/logs/attack_03_epoch_rollback.json`
- Evidence: `out/logs/server167_attack03.log:9:[server167] EPOCH ROLLBACK DETECTED: post-commit extra REKEY (epoch=2) ack.new_epoch=1`

### Preview
```
{"stage":176,"attack":"attack_03_epoch_rollback","ts_utc":"2026-01-30T07:23:20Z","expected":"FAIL_CLOSED","observed":"FAIL_CLOSED_EPOCH_ROLLBACK_REJECTED","ok":true,"client_rc":0,"artifacts":{"server_log":"out/logs/server167_attack03.log","client_log":"out/logs/client167_attack03.log"}}

```

## Attack-04

- Status: **PASS**
- Report: `out/logs/attack_04_wrong_session_id.json`
- Evidence: `out/logs/server167_attack04.log:8:[server167] WRONG SESSION_ID DETECTED: phase=WAIT_ACK expected=7986320003376335535 got=7986320003376335536`

### Preview
```
{"stage":176,"attack":"attack_04_wrong_session_id","ts_utc":"2026-01-30T07:23:21Z","expected":"FAIL_CLOSED","observed":"FAIL_CLOSED_WRONG_SESSION_ID_REJECTED","ok":true,"client_rc":0,"artifacts":{"server_log":"out/logs/server167_attack04.log","client_log":"out/logs/client167_attack04.log"}}

```

## Attack-05

- Status: **PASS**
- Report: `out/logs/attack_05_key_schedule_confusion.json`
- Evidence: `out/logs/server167_attack05.log:8:[server167] BAD REKEY ACK HEADER: expected_epoch=1 got_epoch=2 expected_seq=1 got_seq=99`

### Preview
```
{"stage":176,"attack":"attack_05_key_schedule_confusion","ts_utc":"2026-01-30T07:23:21Z","expected":"FAIL_CLOSED","observed":"FAIL_CLOSED_BAD_ACK_HEADER_REJECTED","ok":true,"client_rc":0,"artifacts":{"server_log":"out/logs/server167_attack05.log","client_log":"out/logs/client167_attack05.log"}}

```

## Attack-06

- Status: **PASS**
- Report: `out/logs/attack_06_phase_confusion.json`
- Evidence: `out/logs/server167_attack06.log:8:[server167] PHASE CONFUSION DETECTED: expected=RekeyAck got=RekeyCommit`

### Preview
```
{"stage":176,"attack":"attack_06_phase_confusion","ts_utc":"2026-01-30T07:23:22Z","expected":"FAIL_CLOSED","observed":"FAIL_CLOSED_PHASE_CONFUSION_REJECTED","ok":true,"client_rc":0,"artifacts":{"server_log":"out/logs/server167_attack06.log","client_log":"out/logs/client167_attack06.log"}}

```

---

## Next

- Add more scenarios: **attack-07 (phase confusion: INIT instead of ACK / duplicate COMMIT / out-of-order frames)** etc.
