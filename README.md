# OpenClaw Flight Recorder (Research Preview)

The "Black Box" for AI Agents.
A local, opt-in observability tool that digests agent event streams into human-readable Activity Summaries and Verifiable Receipts.

## What problem this solves
Agents often behave like black boxes. After a skill runs, users and developers need to know:
- What files were touched (read/write/delete)?
- What network hosts were contacted?
- Were any processes executed?
- Were any dependencies installed during runtime?

This project provides a simple, local Flight Recorder so you can answer: "What did the agent actually do?"

## What’s in this repo
1) RFC-001 Flight Log (JSONL): a minimal event export contract (`RFC/001-flight-log.md`)
2) Reference recorder implementation (stdlib-only Python): `src/recorder.py`
3) Examples: clean vs risky runs (`examples/*.jsonl`)
4) Reproducibility/Conformance: `VERIFY.md` + `tests/`

## Quickstart (Local)
Requirements: Python 3.10+ (stdlib only)

```bash
# Standard mode (observability only)
python src/recorder.py --input examples/risky_run.jsonl --out out_report --overwrite

# Experimental: policy simulation (advisory only)
python src/recorder.py --input examples/risky_run.jsonl --out out_sim --overwrite --policy-sim

Reproducibility / Conformance

See VERIFY.md for pass/fail criteria and tests/ for CI-compatible checks.

Experimental: Extension Recorder

If you add an extension recorder (e.g., src/recorder_ext.py), you can run:

python src/recorder_ext.py --input examples/risky_run.jsonl --out out_ext --overwrite --policy-sim
python src/recorder_ext.py --input examples/ws_token_demo.jsonl --out out_ws_ext --overwrite

Draft spec: RFC/drafts/003-websocket-token-safety-signals.md

Security / Privacy

See SECURITY.md

See PRIVACY.md

See VERIFY.md for anti-impersonation and reproducibility expectations

License

MIT (see LICENSE).


---

# 4）SECURITY.md 需要替换吗？
不需要。你现在的 SECURITY.md 已经没有占位符，也很干净。([github.com](https://github.com/liangfeng-hu/openclaw-flight-recorder/tree/main))  
如果你非要统一成更短版本，也可以，但不是必须。

---

# 5）你现在“为什么会混进去 MIT License”？
因为你复制粘贴时把聊天里的内容整段贴进了 VERIFY.md。

**规则**（记住这一条就不会再乱）：  
- `LICENSE` 文件里只放 MIT License 纯文本  
- `VERIFY.md` 只放“验收口径/可复现检查”  
- 任何“聊天说明/操作步骤”不要贴进仓库文件

---

如果你愿意，你把你仓库里 **当前的 VERIFY.md 页面截图**发我一张（只要能看到开头和结尾），我可以直接告诉你：你现在仓库里是否已经成功替换干净（有没有还残留 MIT License 在 VERIFY 末尾）。
::contentReference[oaicite:0]{index=0}
