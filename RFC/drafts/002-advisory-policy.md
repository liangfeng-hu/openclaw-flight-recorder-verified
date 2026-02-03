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
