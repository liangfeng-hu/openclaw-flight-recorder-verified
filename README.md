# Agent 透明外挂｜安全检测评估记录器（Research Preview）
Agent Transparency Sidecar — Security Audit & Evidence Recorder (Local-Only)

[![CI](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml?branch=main)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)

**Version:** v0.1.0 (Research Preview)  
**Spec:** RFC-001 `flight-log/1`

> **Zero-intrusion (no business-logic changes), opt-in, local-only, read-only by default.**  
> **零侵入（无需改业务逻辑/工作流），可选接入（opt-in），默认本地只读。**  
> Converts agent event streams (JSONL) into:
> - **badge.json**: human-readable behavior summary + risk highlights  
> - **receipts.jsonl**: hash-chained, tamper-evident receipts (evidence chain)  
>
> This is **not** a blocking firewall. `--policy-sim` is **advisory only**.

---

## What problem this solves
Agents can behave like black boxes. After a skill/agent run, users and developers need to know:

- What files were touched (read/write/delete)?
- What network hosts were contacted?
- Were any processes executed?
- Were any dependencies installed during runtime?

This repo provides a simple, local recorder so you can answer:  
**“What did the agent actually do?”** — with verifiable evidence.

---

## What’s in this repo
1) **RFC-001 Flight Log (JSONL)**: `RFC/001-flight-log.md`  
2) **Recorder (stdlib-only Python)**: `src/recorder.py`  
3) **Examples**: clean vs risky runs: `examples/*.jsonl`  
4) **Reproducibility checks**: `VERIFY.md` + `tests/`  
5) (Optional) **Draft RFCs** under `RFC/drafts/` for experimental extensions  
6) (Optional) **Extension Recorder** (if present): `src/recorder_ext.py` for advisory suggestions (`--suggest`)

---

## Quickstart (Local)
Requirements: Python 3.10+ (stdlib only)

```bash
# Standard mode (observability only)
python src/recorder.py --input examples/clean_run.jsonl --out out_clean
python src/recorder.py --input examples/risky_run.jsonl --out out_risky

# Advisory policy simulation (optional)
python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim

Outputs (per run):

badge.json (facts + highlights)

receipts.jsonl (hash-chained receipts)

Reproducibility / Conformance

See:

VERIFY.md for pass/fail criteria and receipt-chain rules

tests/ for CI-compatible checks

Run tests locally:

python -m unittest discover -s tests -p "test_*.py" -v

Security / Privacy / Verification

SECURITY.md — reporting and scope

PRIVACY.md — local-only & digest-first guidance

VERIFY.md — reproducibility + verification checks

LICENSE — MIT

If the CI badge doesn’t refresh, reload the page or ensure it points to the correct workflow file under .github/workflows/.

Non-goals

Not a malware scanner

Not an enforcement engine

Not an exploit guide

Not a centralized reputation system

This tool is about transparent evidence and safe, local verification.


---

使用方法（iPhone 也可以）：
1) 打开仓库 → 点 `README.md`  
2) 右上角 ✏️ Edit  
3) 全选删掉 → 粘贴上面整份内容  
4) 滑到最下面 → `Commit changes`

如果你愿意，我下一条可以再帮你把 README 的“中英双语比例”调整成更统一的风格（例如：标题/关键口号双语，其余全英文），这样更符合 OpenClaw 国际维护者阅读习惯。
::contentReference[oaicite:0]{index=0}
