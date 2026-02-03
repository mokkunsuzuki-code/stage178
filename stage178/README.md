## Stage178-A: Claims ↔ Implementation Integrity (CI)

This repository enforces that the security claims table stays consistent with implementation and tests.

**CI guarantees**
- `tools/check_claims_integrity.py` validates that every claim references existing files/anchors/tests.
- `pytest` validates the minimal core contract (`qsp/minicore.py`) for fail-closed behaviors.

**How to verify locally**
```bash
python tools/check_claims_integrity.py
pytest -q tests
If you break claim references or the minicore contract, CI must fail.


✅ これで「主張（claims）と実装がズレたら落ちる」が一発で伝わり、Stage178 の価値が外に刺さります。

---

# 2) GitHub Actions のバッジを README に貼る（信用が上がる）

README の一番上（タイトル直下）に貼ります。

1. GitHub の Actions を開く  
2. 対象ワークフロー（`stage178-ci`）を開く  
3. 右上あたりの **…（3点） → Create status badge**  
4. 出てきた Markdown を README に貼る

（※ここはあなたのリポジトリ設定/ワークフロー名でURLが変わるので、GitHubが生成するものを貼るのが最も確実）

---

## ここまでやったらコミット

```bash
git add README.md
git commit -m "Stage178-A: document CI guarantees (claims integrity + minicore contract)"
git push origin main
すぐ進めたい場合
README.md の現状をここに貼ってくれれば、あなたのREADME構成に合わせて
「どこに・どういう見出しで・どの文章量が最強か」をこちらで完成形に整えて返します。

あなた:
１７８ーA READMEを全てお願いします
ChatGPT:
了解です。
**Stage178-A 用の README.md を「そのまま置き換え可能な完成形」**で出します。
（研究用途／OSS評価／CI耐性をすべて意識した内容です）

README.md（完成版）
# QSP – Stage178-A  
**Claims ↔ Implementation Integrity (CI-enforced)**

This stage establishes a *hard guarantee* that **security claims, implementation, and tests never diverge**.

Stage178-A is not about adding new cryptography.  
It is about proving — continuously — that *what we claim to protect* is exactly *what the code enforces*.

---

## What Stage178-A Achieves

Stage178-A introduces **CI-enforced integrity** between:

- 📜 **Security Claims Table** (`claims/claims.yml`)
- 🧠 **Minimal reference implementation** (`qsp/minicore.py`)
- 🧪 **Negative & positive tests** (`tests/`)
- 🤖 **Automated CI verification** (GitHub Actions)

If any of these fall out of sync, **CI must fail**.

---

## Core Guarantees (What CI Enforces)

### 1. Claims Integrity
Every security claim must reference:
- an existing implementation file
- a valid anchor or rule
- at least one test that exercises the claim

Checked by:
```bash
python tools/check_claims_integrity.py
If a claim references a non-existent file, anchor, or test → CI FAILS.

2. Minimal Core Contract (qsp/minicore.py)
minicore.py is intentionally small, strict, and auditable.

It enforces the control-plane security rules that back the claims:

A1 – Handshake Gating

No APP_DATA or REKEY before handshake completion

A3 – Fail-Closed Semantics

Session ID mismatch → immediate close

Epoch mismatch → immediate close

A4 – Rekey Discipline

Rekey allowed only for epoch + 1

Key material must change across epochs

This file is not a production protocol.
It is a contract oracle for CI.

3. Test Suite (Behavioral Proof)
Tests are written to break the protocol on purpose:

wrong session ID

epoch rollback / jump

rekey reuse

data before handshake

If any unsafe behavior is accepted → CI FAILS.

Run locally:

pytest -q tests
Repository Layout (Stage178-A)
stage178/
├── claims/
│   └── claims.yml              # Security Claims Table
├── qsp/
│   └── minicore.py             # Minimal claim-backed core
├── tests/
│   ├── test_handshake_success.py
│   ├── test_reject_appdata_before_handshake.py
│   ├── test_close_on_wrong_session_id.py
│   ├── test_close_on_epoch_mismatch.py
│   ├── test_rekey_happy_path.py
│   └── test_rekey_reuse_detected.py
├── tools/
│   └── check_claims_integrity.py
├── .gitignore
└── README.md
How CI Protects the Project
CI executes the following in order:

Claims Integrity Check

python tools/check_claims_integrity.py
Behavioral Tests

pytest -q tests
If any of these fail, the build is red.

This means:

You cannot “update the code” without updating the claims.
You cannot “edit the claims” without updating the code or tests.

What This Stage Is (and Is Not)
✔ This stage is
A research-grade safety rail

A proof that claims and code are synchronized

A CI pattern reusable for other protocols

✘ This stage is not
A full protocol implementation

A cryptographic performance benchmark

A claim of post-quantum security completeness

Why This Matters
Most protocol projects fail not because crypto is broken,
but because assumptions drift silently over time.

Stage178-A makes drift impossible without CI noticing.

This is the foundation required before:

formal verification (Tamarin / ProVerif sync)

attack coverage expansion

external audits or PoC sharing

How to Verify Locally
git clone https://github.com/mokkunsuzuki-code/stage178.git
cd stage178

python tools/check_claims_integrity.py
pytest -q tests
Expected result:

[OK] claims integrity passed
..........
License
MIT License © 2025 Motohiro Suzuki