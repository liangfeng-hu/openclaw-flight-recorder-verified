# OpenClaw Flight Recorder (Research Preview)

“AI Agent 的黑盒记录器（离线版）”：把 Agent 的事件流（JSONL）压缩成 **可读的行为摘要**（badge.json）与 **可验证的收据链**（receipts.jsonl），并提供 **CI 一致性验收**（tests + GitHub Actions），确保不漂移。

> 这不是系统级“抓包器/拦截器”。它是一个 **本地、可选接入（opt-in）的离线分析器**：输入事件日志 → 输出摘要 + 收据链。

---

## Quickstart

本地运行（生成报告）：
- `python src/recorder.py --input examples/clean_run.jsonl --out out_clean`
- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim`

本地验收（Conformance Suite）：
- `python -m unittest discover -s tests -p "test_*.py" -v`

CI：
- GitHub Actions 会在每次 push / PR 自动跑一致性验收（Conformance Tests）。

---

## Windows PowerShell（傻瓜化示例）

运行 clean 示例并查看结果：
- `python src/recorder.py --input examples/clean_run.jsonl --out out_clean`
- `dir out_clean`
- `notepad out_clean\badge.json`
- `notepad out_clean\receipts.jsonl`

运行 risky 示例（含 policy-sim）并查看结果：
- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim`
- `notepad out_sim\badge.json`

---

## 你会得到什么输出？

运行后，输出目录（例如 `out_clean/`）至少包含：

- `badge.json`  
  行为摘要 + 风险提示（例如 OBSERVED / ATTENTION），以及（可选）policy simulation 结果。

- `receipts.jsonl`  
  每个事件一条“收据”，包含链式字段：`prev_hash → receipt_hash`，用于证明“日志没有被悄悄改过/删过”。

---

## 核心概念

### 1) Event log（输入：JSONL）
每一行是一个事件 JSON（JSONL = 每行一个 JSON）。事件格式与字段约束见：
- `RFC/001-flight-log.md`

### 2) Badge（输出：摘要）
`badge.json` 会汇总：
- 观测到的行为类别（network out / file write / proc exec / dep install）
- 风险标签（risk_highlights）
- 统计信息（total_events / highlight_count / evidence_gaps）
- 可选：policy simulation（当你加 `--policy-sim`）

### 3) Receipts（输出：可验证链）
`receipts.jsonl` 每行包含（至少）：
- `trace_id`：同一次运行的追踪 ID
- `seq`：事件序号（递增）
- `event_type`：事件类型（例如 FILE_IO / NET_IO / PROC_EXEC / DEP_INSTALL）
- `event_hash`：事件内容摘要哈希
- `prev_hash`：前一条收据哈希
- `receipt_hash`：当前收据哈希（链上的“当前锚点”）

链连续性要求：  
后一条的 `prev_hash` 必须等于前一条的 `receipt_hash`。

---

## Policy Simulation（可选：建议性策略模拟）

运行：
- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim`

这会在 `badge.json` 增加：
- `policy_simulation.would_block`（true/false）
- `violation_count`
- `violations`（可读原因列表）

注意：这是 **advisory（建议性）**，不是强制拦截器。它用于把风险标签压成可判决信号，便于接入更上层的治理/门控系统。

---

## Conformance Suite（一致性验收用例库）

本仓库内置两条“红线用例”：
- `examples/clean_run.jsonl`：应当输出 `status=OBSERVED` 且 `highlight_count=0`
- `examples/risky_run.jsonl`：应当输出 `status=ATTENTION` 且高风险标签完整（并在 policy-sim 下 `would_block=true`）

测试脚本：
- `tests/test_examples.py`

运行：
- `python -m unittest discover -s tests -p "test_*.py" -v`

CI：
- `.github/workflows/ci.yml`

目标：让“定律/合同（RFC）→ 一致性骨架（receipt chain）→ 自动验收（tests+CI）”成为不可漂移的工程现实。

---

## Repository Structure

openclaw-flight-recorder-verified/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── SECURITY.md
├── PRIVACY.md
├── VERIFY.md
├── RFC/
│ ├── 001-flight-log.md
│ └── 002-advisory-policy.md
├── src/
│ └── recorder.py
├── examples/
│ ├── clean_run.jsonl
│ └── risky_run.jsonl
├── tests/
│ └── test_examples.py
└── .github/
└── workflows/
└── ci.yml

---

## Requirements

- Python 3.10+（本项目默认零依赖；见 `requirements.txt`）

---

## Security & Privacy

- 安全建议、披露方式见 `SECURITY.md`
- 隐私/数据处理原则见 `PRIVACY.md`

提示：示例日志中的域名、路径等多为演示用途（synthetic），不代表你的真实系统文件被修改。

---

## Roadmap（建议方向）

- Collector / Exporter：将真实 agent side-effects 自动采集为 RFC-001 JSONL
- 更细粒度的声明/许可模型（declared intent / allowlist / sandbox）
- 更强的可验证性：将 receipt 链与外部签名/时间戳/证明系统对接
- 更完整的 policy profiles：在 advisory 基础上扩展不同环境策略

---

## License

See `LICENSE`.
