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

Outputs:

badge.json (facts + highlights)

receipts.jsonl (hash-chained receipts)

Conformance / Reproducibility

Pass/fail criteria: VERIFY.md
Run tests:

python -m unittest discover -s tests -p "test_*.py" -v

Advisory configuration (optional)

You may provide --config policy.json to override thresholds/paths/rules.
Default advisory rules are built-in; policy.json is optional.

Security / Privacy

Local-only by default; share only digests/summaries

No VS Code extension shipped

No curl|sh installers

See: PRIVACY.md, SECURITY.md, VERIFY.md.

License

MIT — see LICENSE.

If the CI badge doesn’t refresh, reload the page or ensure it points to the correct workflow file under .github/workflows/.


---

# 方案 B：把 RFC/002 补回来（也可以，但不推荐）
如果你坚持保留 RFC-002 的“文件存在且可点开”，那就：
- 新建 `RFC/002-advisory-policy.md`
- 内容写清：policy-sim 输出字段 + policy.json 结构

但你之前策略就是“RFC-002 降级为 draft / optional”，所以现在更合适的是 **方案 A**（删引用/不强依赖）。

---

# 你问“是否需要修正？和上面的补全一并修正最终稿”
✅ **需要修正**，而且建议你用 **方案 A-2（整份替换 README）**一次性封板，最省心、最不容易贴错。

---

## 你现在要做的操作（1 分钟）
1) 打开仓库 → 点 `README.md`  
2) ✏️ Edit  
3) 全选删除  
4) 粘贴我给你的“整份最终 README”  
5) Commit changes  

做完你就达到你说的 **100% 无残留**，可以直接发给对方。
::contentReference[oaicite:0]{index=0}
