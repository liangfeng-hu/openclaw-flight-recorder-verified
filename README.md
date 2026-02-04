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

