# RFC 002: Advisory Policy Simulation

## Status
Proposal / Research Preview

## Abstract
Defines the **advisory (non-enforcing)** policy simulation output.

Policy simulation is not a firewall. It converts risk highlights into a conservative "would_block" signal to help research, evaluation, and higher-layer governance.

## badge.json extension
When `--policy-sim` is enabled, `badge.json` includes:

- `policy_simulation` (object)
  - `enabled` (bool): true
  - `profile` (string): active profile name
  - `would_block` (bool)
  - `violation_count` (int)
  - `violations` (array[string])

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

profiles is a named map of rule sets.

profile chooses which profile to start from.

policy_rules are explicit overrides applied after profile selection.


---

## 文件名称：examples/ext_run.jsonl（新增文件，整份粘贴）

```jsonl
{"v":"flight-log/1","ts":"2026-02-03T00:00:01Z","trace_id":"demo-ext","seq":1,"actor":"demo","event_type":"DATABASE_OP","payload_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","domain_class":"DB","declared":false,"data_complete":true,"details":{"db_type":"mysql","query":"DELETE FROM users"}}
{"v":"flight-log/1","ts":"2026-02-03T00:00:02Z","trace_id":"demo-ext","seq":2,"actor":"demo","event_type":"API_CALL","payload_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","domain_class":"NET","declared":true,"data_complete":true,"details":{"endpoint":"https://api.example.com/v1","headers":{"authorization":"Bearer sk_test_123"}}}
{"v":"flight-log/1","ts":"2026-02-03T00:00:03Z","trace_id":"demo-ext","seq":3,"actor":"demo","event_type":"MEMORY_ACCESS","payload_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","domain_class":"MEM","declared":true,"data_complete":true,"details":{"size":2000000000}}
