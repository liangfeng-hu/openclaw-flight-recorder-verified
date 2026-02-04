# Agent 透明外挂｜安全检测评估记录器（Research Preview）
Agent Transparency Sidecar — Local-only, opt-in, read-only evidence recorder

[![CI](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml?branch=main)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)

**Version:** v0.1.0 (Research Preview)  
**Spec:** RFC-001 `flight-log/1`

> **Zero-intrusion (no business-logic changes), opt-in, local-only, read-only by default.**  
> **零侵入（无需改业务逻辑/工作流），可选接入（opt-in），默认本地只读。**  
>
> This is **not** a blocking firewall. `--policy-sim` is **advisory only**.

---

## What this provides
Given a JSONL flight log, the recorder outputs:
- **badge.json**: behavior summary + risk highlights  
- **receipts.jsonl**: hash-chained, tamper-evident receipts (evidence chain)

This lets users verify: **“What did the agent actually do?”** with replayable evidence.

---

## Repo contents
- `RFC/001-flight-log.md` — minimal JSONL event export contract
- `src/recorder.py` — reference recorder (stdlib-only)
- `examples/*.jsonl` — clean vs risky traces
- `tests/` — CI conformance tests
- `VERIFY.md` — reproducibility & receipt-chain checks
- `PRIVACY.md` / `SECURITY.md` — privacy & security notes
- (Optional) `src/recorder_ext.py` — experimental extension (advisory suggestions via `--suggest`)

---

## Quickstart (Local)
Requirements: Python 3.10+ (stdlib only)

```bash
# Standard mode (observability only)
python src/recorder.py --input examples/clean_run.jsonl --out out_clean
python src/recorder.py --input examples/risky_run.jsonl --out out_risky

# Advisory policy simulation (optional)
python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim

Conformance / Reproducibility

Pass/fail criteria: VERIFY.md
Run tests:

python -m unittest discover -s tests -p "test_*.py" -v

Security / Privacy

Local-only by default; share only digests/summaries

No VS Code extension shipped

No curl|sh installers

See: PRIVACY.md, SECURITY.md, VERIFY.md.

License

MIT — see LICENSE.

If the CI badge doesn’t refresh, reload the page or ensure it points to the correct workflow file under .github/workflows/.


---

# D)（可选但建议）整文件替换：`VERIFY.md`（确保里面不再混入 LICENSE/聊天说明）
你现在 README 已经干净了；VERIFY 也建议保持“纯验收口径”。如果你确认 VERIFY 已经很干净，就不用动；如果里面还有杂质，就用这份整替换：

文件名称：《VERIFY.md》（整份替换，可选）
```markdown
# VERIFY.md — 可复现验收与一致性检查（SSOT）

本文件定义本项目的可复现验收口径：JSONL → badge.json（事实摘要）+ receipts.jsonl（可验证收据链）。
（注：--policy-sim 为 advisory 建议性信号，不是阻断防火墙。）

## 0. 环境要求
- Python 3.10+
- 零依赖（标准库即可）

## 1. 本地快速验收（主线 recorder.py）

### 1.1 Clean（必须干净）
python src/recorder.py --input examples/clean_run.jsonl --out out_clean

必须满足：
- status == OBSERVED
- highlight_count == 0
- evidence_gaps == 0
- risk_highlights 为空

### 1.2 Risky（必须出现核心风险信号）
python src/recorder.py --input examples/risky_run.jsonl --out out_risky --policy-sim

必须满足：
- status 为 ATTENTION（本示例要求 evidence_gaps == 0）
- policy_simulation.would_block == true
- highlight_count >= 7
- policy_simulation.violation_count >= 7

## 2. 一致性测试（CI 同口径）
python -m unittest discover -s tests -p "test_*.py" -v

## 3. receipts.jsonl 收据链要求
- 第一条 prev_hash 是 64 个 0
- 从第二条开始：每条 prev_hash 等于上一条 receipt_hash
- event_hash / prev_hash / receipt_hash 都是 64 位十六进制字符串
