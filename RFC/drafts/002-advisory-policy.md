# RFC 002: Advisory Policy Simulation

## Status
Proposal / Research Preview

## Abstract
Defines the advisory (non-enforcing) policy simulation output.

Policy simulation is not a firewall. It converts risk highlights into a conservative `would_block` signal to help research, evaluation, and higher-layer governance.

## badge.json extension
When `--policy-sim` is enabled, `badge.json` includes:
- `policy_simulation.enabled` (true)
- `policy_simulation.profile` (string)
- `policy_simulation.would_block` (bool)
- `policy_simulation.violation_count` (int)
- `policy_simulation.violations` (array[string])

## policy.json (optional) format
`--config policy.json` supports:

```json
{
  "profile": "advisory",
  "profiles": {
    "advisory": {
      "block_unpinned_deps": true,
      "block_undeclared_actions": true,
      "block_sensitive_paths": true,
      "block_remote_script": true,
      "block_sql_risks": true,
      "block_api_exposure": true,
      "block_high_memory": true,
      "block_on_gaps": false,
      "block_on_unknown": false
    },
    "strict_advisory": {
      "block_on_gaps": true,
      "block_on_unknown": true
    }
  },
  "policy_rules": {
    "block_on_gaps": true
  },
  "sensitive_prefixes": ["/etc/", "/var/log/"],
  "memory_threshold_bytes": 1000000000
}

Notes:

profiles defines named rule sets.

profile selects which profile to start from.

policy_rules overrides are applied after profile selection.


---

## 文件名称：README.md（整份替换）
```md
# OpenClaw Flight Recorder (Research Preview)

本项目是一个本地可观测性 PoC：输入 RFC-001 JSONL 事件日志，输出行为摘要（badge.json）与可验证收据链（receipts.jsonl），并提供 CI 一致性验收（tests + GitHub Actions）防止漂移。

定位：诊断工具（dashcam/black box），不是阻断防火墙。  
`--policy-sim` 仅为 advisory（建议性）信号。

---

## Quickstart

生成报告：
- `python src/recorder.py --input examples/clean_run.jsonl --out out_clean`
- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim`
- `python src/recorder.py --input examples/ext_run.jsonl --out out_ext --policy-sim`

运行一致性验收（本机）：
- `python -m unittest discover -s tests -p "test_*.py" -v`

CI：
- 每次 push / PR 会自动跑 tests。

---

## 额外命令

验链（验证 receipts.jsonl 是否链连续、hash 是否可复算）：
- `python src/recorder.py --verify-receipts out_sim/receipts.jsonl`

policy.json（可选）：
- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim --config policy.json --profile strict_advisory`

---

## Outputs
- badge.json：status / behavior_summary / risk_highlights / stats / (optional) policy_simulation
- receipts.jsonl：hash 链收据（prev_hash -> receipt_hash）

---

## RFC
- RFC/001-flight-log.md
- RFC/002-advisory-policy.md
