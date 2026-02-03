# OpenClaw Flight Recorder (Research Preview)

[![CI](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/liangfeng-hu/openclaw-flight-recorder-verified)](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/releases)

本项目是一个本地可观测性 PoC：输入 RFC-001 JSONL 事件日志，输出 **行为摘要**（badge.json）与 **可验证收据链**（receipts.jsonl），并提供 **CI 一致性验收**（tests + GitHub Actions）来防漂移。

> 定位：诊断工具（dashcam / black box），不是阻断防火墙。  
> `--policy-sim` 仅为 advisory（建议性）信号，用于研究/对齐更高层治理系统。

---

## Quickstart

生成报告（保持主线兼容）：

- `python src/recorder.py --input examples/clean_run.jsonl --out out_clean`
- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim`
- `python src/recorder.py --input examples/ext_run.jsonl --out out_ext --policy-sim`

运行一致性验收（Conformance Suite）：

- `python -m unittest discover -s tests -p "test_*.py" -v`

CI：

- GitHub Actions 会在每次 push / PR 自动跑 Conformance Suite（避免静默漂移）。

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

## 输出说明

输出目录（由 `--out` 指定）至少包含：

- `badge.json`：status / behavior_summary / risk_highlights / stats /（可选）policy_simulation
- `receipts.jsonl`：hash 链收据（prev_hash → receipt_hash），用于回放与篡改检测

---

## 新增能力（v1.1）

1. **扩展事件类型**：`DATABASE_OP / API_CALL / MEMORY_ACCESS`（见 `examples/ext_run.jsonl`）  
2. **证据缺口显式化**：缺 MUST 字段 / 缺关键 details / `data_complete=false` → 产生 `EVIDENCE_GAP`  
3. **未知事件类型显式化**：`UNKNOWN_EVENT_TYPE`（不会静默忽略）  
4. **Advisory policy profiles + 配置**：`--config policy.json` + `--profile advisory|strict_advisory`（见 RFC-002）  
5. **收据链验链器**：`--verify-receipts out_dir/receipts.jsonl`

---

## Policy Simulation（advisory）

运行：

- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim`

可选配置（示例）：

- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim --config policy.json --profile strict_advisory`

配置格式见：`RFC/002-advisory-policy.md`

---

## RFC / Contract

- `RFC/001-flight-log.md`：事件 JSONL 合同（MUST 字段 + details 结构 + 扩展事件）
- `RFC/002-advisory-policy.md`：policy-sim 输出字段与 policy.json 结构

---

## Repository Layout (high level)

openclaw-flight-recorder-verified/
├── RFC/
│ ├── 001-flight-log.md
│ └── 002-advisory-policy.md
├── src/
│ └── recorder.py
├── examples/
│ ├── clean_run.jsonl
│ ├── risky_run.jsonl
│ └── ext_run.jsonl
├── tests/
│ └── test_examples.py
└── .github/workflows/
└── ci.yml

::contentReference[oaicite:0]{index=0}
