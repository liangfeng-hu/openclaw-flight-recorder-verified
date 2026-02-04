# Draft 004: Remediation Advice Contract (Advisory-Only)

## Status
Draft / Optional / Not part of RFC-001 standard

## Purpose
Defines a minimal, tool-agnostic JSON contract for **advisory remediation guidance** generated from:
- `badge.json` (behavior summary + risk highlights)
- `receipts.jsonl` (tamper-evident evidence chain)

This is designed to:
- Provide **actionable direction** without auto-fixing
- Preserve the observability-first posture
- Avoid exploit instructions
- Avoid secrets (digest-only references)

## Non-Goals
- No auto-apply / no execution / no configuration changes performed by the tool
- No guarantee of security outcomes (advice is contextual)
- No disclosure of raw tokens, raw URLs with secrets, or private data

---

## 1) Output File
Recommended filename: `suggestions.json` (or `remediation_advice.json`)

## 2) Top-Level Object (MUST)
A remediation advice document MUST contain:

- `v` (string): `"remediation-advice/1"`
- `generated_at` (string): ISO-8601 UTC timestamp
- `source` (object): producer metadata
  - `tool_name` (string) e.g. `"openclaw-flight-recorder"`
  - `tool_version` (string, optional)
  - `policy_profile_id` (string, optional)
  - `policy_profile_digest` (string, optional)  # commit-by-hash anchor
- `input` (object): what was analyzed (digest-first)
  - `flight_log_path` (string, optional)  # local path (may be omitted)
  - `flight_log_digest` (string, optional) # sha256:...
  - `badge_digest` (string, optional)
  - `receipt_chain_tip` (string, optional) # last receipt_hash
- `summary` (object):
  - `status` (string): e.g. `"OBSERVED"`, `"ATTENTION"`, `"ATTENTION_WITH_GAPS"`
  - `total_events` (int, optional)
  - `highlight_count` (int, optional)
  - `evidence_gaps` (int, optional)
  - `tags` (array[string]) unique risk tags
- `safety` (object)  # MUST to avoid misinterpretation
  - `auto_fix` (boolean): MUST be `false`
  - `enforcement` (boolean): MUST be `false`
  - `secrets_logged` (boolean): SHOULD be `false` (digest-only)
- `suggestions` (array[Suggestion])  # advisory actions

## 3) Suggestion Object (MUST)
Each `Suggestion` MUST contain:
- `tag` (string): risk tag that triggered this suggestion (e.g., `UNPINNED_DEP`)
- `priority` (string): `LOW|MEDIUM|HIGH|CRITICAL`
- `title` (string): short human title
- `count` (int): number of occurrences
- `evidence` (array[string]): digest pointers (e.g., event_hash digests), no raw secrets
- `do` (array[string]): safe fix directions (no exploit steps)
- `verify` (array[string]): how to verify the fix using re-run + badge/receipts comparison
- `notes` (string, optional)

## 4) Policy Simulation (Optional)
If the recorder also ran `--policy-sim`, the advice MAY include:
- `policy_simulation_summary` (object):
  - `enabled` (bool)
  - `would_block` (bool)
  - `violation_count` (int)

This remains advisory only.

## 5) Privacy Requirements (MUST)
- `evidence` MUST NOT contain raw tokens, raw credentials, or raw URLs with secrets.
- Prefer digests: `sha256:...`
- Prefer referencing receipts by digest pointers rather than raw payloads.

## 6) Example
```json
{
  "v": "remediation-advice/1",
  "generated_at": "2026-02-03T00:00:00Z",
  "source": {"tool_name": "openclaw-flight-recorder", "policy_profile_id": "default"},
  "input": {"flight_log_digest": "sha256:...", "receipt_chain_tip": "sha256:..."},
  "summary": {"status": "ATTENTION", "highlight_count": 7, "evidence_gaps": 0, "tags": ["REMOTE_SCRIPT","UNPINNED_DEP"]},
  "safety": {"auto_fix": false, "enforcement": false, "secrets_logged": false},
  "suggestions": [
    {
      "tag": "REMOTE_SCRIPT",
      "priority": "CRITICAL",
      "title": "Stop remote script execution patterns (curl|bash / wget|sh)",
      "count": 1,
      "evidence": ["sha256:be38e140..."],
      "do": ["Do NOT run one-liners that fetch remote scripts."],
      "verify": ["Re-run recorder: REMOTE_SCRIPT should disappear."]
    }
  ]
}


---

# 2) （可选但很强）新增 JSON Schema：让 CI 能自动验收 suggestions.json 格式
如果你想把“建议契约”做成真正的标准接口，建议再加一个 schema 文件，未来 CI 可以自动校验。

文件名称：《schemas/remediation_advice_v1.schema.json》
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Remediation Advice Contract v1",
  "type": "object",
  "required": ["v", "generated_at", "source", "summary", "safety", "suggestions"],
  "properties": {
    "v": { "const": "remediation-advice/1" },
    "generated_at": { "type": "string" },
    "source": {
      "type": "object",
      "required": ["tool_name"],
      "properties": {
        "tool_name": { "type": "string" },
        "tool_version": { "type": "string" },
        "policy_profile_id": { "type": "string" },
        "policy_profile_digest": { "type": "string" }
      },
      "additionalProperties": true
    },
    "input": { "type": "object", "additionalProperties": true },
    "summary": {
      "type": "object",
      "required": ["status", "tags"],
      "properties": {
        "status": { "type": "string" },
        "total_events": { "type": "integer" },
        "highlight_count": { "type": "integer" },
        "evidence_gaps": { "type": "integer" },
        "tags": { "type": "array", "items": { "type": "string" } }
      },
      "additionalProperties": true
    },
    "safety": {
      "type": "object",
      "required": ["auto_fix", "enforcement"],
      "properties": {
        "auto_fix": { "const": false },
        "enforcement": { "const": false },
        "secrets_logged": { "type": "boolean" }
      },
      "additionalProperties": true
    },
    "suggestions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["tag", "priority", "title", "count", "evidence", "do", "verify"],
        "properties": {
          "tag": { "type": "string" },
          "priority": { "enum": ["LOW","MEDIUM","HIGH","CRITICAL"] },
          "title": { "type": "string" },
          "count": { "type": "integer" },
          "evidence": { "type": "array", "items": { "type": "string" } },
          "do": { "type": "array", "items": { "type": "string" } },
          "verify": { "type": "array", "items": { "type": "string" } },
          "notes": { "type": "string" }
        },
        "additionalProperties": true
      }
    },
    "policy_simulation_summary": { "type": "object", "additionalProperties": true }
  },
  "additionalProperties": true
}
