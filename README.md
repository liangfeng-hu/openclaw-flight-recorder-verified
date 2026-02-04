# OpenClaw Flight Recorder (Research Preview)

[![CI](https://github.com/liangfeng-hu/openclaw-flight-recorder/actions/workflows/ci.yml/badge.svg)](https://github.com/liangfeng-hu/openclaw-flight-recorder/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)

**Version:** v0.1.0 (Research Preview)  
**Spec:** RFC-001 `flight-log/1`

The "Black Box" for AI Agents. A local, opt-in observability tool that digests agent event streams into human-readable Activity Summaries and Verifiable Receipts.

## What problem this solves
Agents often behave like black boxes. After a skill runs, users and developers need to know:
- What files were touched (read/write/delete)?
- What network hosts were contacted?
- Were any processes executed?
- Were any dependencies installed during runtime?

This project provides a simple, local Flight Recorder so you can answer: "What did the agent actually do?"

## What’s in this repo
1) RFC-001 Flight Log (JSONL): `RFC/001-flight-log.md`  
2) Reference recorder implementation (stdlib-only Python): `src/recorder.py`  
3) Examples: clean vs risky runs: `examples/*.jsonl`  
4) Reproducibility checks: `VERIFY.md` + `tests/`

## Quickstart (Local)
Requirements: Python 3.10+ (stdlib only)

```bash
# Standard mode (observability only)
python src/recorder.py --input examples/risky_run.jsonl --out out_report

# Experimental: policy simulation (advisory only)
python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim

Reproducibility / Conformance

See VERIFY.md for pass/fail criteria and tests/ for CI-compatible checks.

Security / Privacy

SECURITY.md

PRIVACY.md

VERIFY.md (reproducibility + anti-impersonation notes)

License

MIT (see LICENSE).


### 如果你的 CI 徽章显示不出来怎么办？
很简单：  
1）打开仓库 `.github/workflows/` 文件夹  
2）看里面 workflow 文件名（例如 `python-tests.yml`）  
3）把 README 里这段的 `ci.yml` 改成你的真实文件名即可：

.../actions/workflows/ci.yml/badge.svg
.../actions/workflows/ci.yml


---

# 4）你现在要做的最短动作清单
✅ 必做（3 个文件全替换一次就收尾）  
1) LICENSE（去掉 `<YOUR_NAME>`）  
2) VERIFY.md（删除末尾混入的 License + 聊天说明）  
3) README.md（补回徽章 + 版本信息）

SECURITY.md 你现在这份已经没占位符，不用动。

---

如果你愿意，我还能顺手帮你把 **版本号统一**（例如把 v0.1.0 放到一个 `VERSION` 文件里，未来发 Release/Tag 都能自动引用），但这不是必须项。
::contentReference[oaicite:0]{index=0}
