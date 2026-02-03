# Verification (Anti-Impersonation)

This project intentionally avoids common high-risk distribution patterns.

## What we do NOT ship
- No VS Code extension
- No one-line installers (curl|sh)
- No marketplace installers

## If you publish releases
Recommended:
1) Publish SHA256 checksums for release artifacts
2) Provide a clear “official channels” list
3) Encourage users to verify checksums before running

## How to verify SHA256 (examples)
macOS/Linux:
```bash
shasum -a 256 <file>
Get-FileHash <file> -Algorithm SHA256

---

## 文件名称：《RFC/001-flight-log.md》
```markdown
# RFC 001: Flight Log Export Contract (JSONL)

## Status
Proposal / Research Preview

## Abstract
Defines a minimal, tool-agnostic **JSONL** format for exporting agent execution events.
Goal: **Observability** — enabling users to see what side effects occurred (Network, File, Exec, Supply Chain)
without relying on centralized reputation systems.

## Format
- UTF-8 JSON Lines (one JSON object per line)
- Ordered by `seq` ascending

## Required Fields (MUST)
Each event MUST contain:
- `v` (string): version, e.g. `"flight-log/1"`
- `ts` (string): ISO-8601 timestamp (UTC recommended)
- `trace_id` (string): unique ID for the run/flow
- `seq` (integer): monotonically increasing sequence number
- `actor` (string): agent/skill identifier
- `event_type` (string): one of the enumerated types below
- `payload_digest` (string): digest of redacted payload (e.g., `sha256:...`)
- `domain_class` (string): coarse label (e.g., `NET`, `FILE`, `EXEC`, `SUPPLY`, `TOOL`, `ID`)

## Optional Fields (SHOULD when available)
- `declared` (boolean): whether this side effect was explicitly declared/expected
- `details` (object): redacted metadata (host, path, op, cmd_digest, package, version, etc.)

## Event Types
- `ID_ROUTE`      : identity/route decision snapshot (if available)
- `TOOL_CALL`     : tool invocation
- `FILE_IO`       : file read/write/delete
- `NET_IO`        : network inbound/outbound
- `PROC_EXEC`     : process/command execution
- `DEP_INSTALL`   : dependency/skill install/update/download
- `TRANSFER`      : agent/thread handoff
- `MESSAGE_IN`    : inbound message surface
- `MESSAGE_OUT`   : outbound message

## Privacy Guidance
Exporters SHOULD:
- Store digests rather than raw prompts/keys/messages
- Redact file contents, secrets, headers, tokens
- Prefer `cmd_digest` over raw `cmd` where possible

## Example
```json
{"v":"flight-log/1","ts":"2026-02-03T00:00:00Z","trace_id":"demo","seq":1,"actor":"agent-main","event_type":"NET_IO","payload_digest":"sha256:...","domain_class":"NET","declared":true,"details":{"direction":"OUT","host":"api.example.com","port":443}}

---

## 文件名称：《RFC/drafts/002-advisory-policy.md》
```markdown
# Draft 002: Advisory Risk Signals (Experimental)

## Status
Draft / Optional / Not part of RFC-001 standard

## Purpose
This document describes optional “advisory” signals used by `--policy-sim`.
It is NOT required for the standard Flight Log, and it should NOT be treated as enforcement.

## Advisory Signals (examples)
If enabled, the recorder may flag these as “would be blocked under strict policy”:

- **Execution Violation**
  - `PROC_EXEC` where `declared: false`
  - or command matches remote script patterns (`curl|bash`, `wget|sh`)

- **Data Egress (Undeclared)**
  - `NET_IO` outbound where `declared: false`

- **System Tampering**
  - `FILE_IO` write/delete to sensitive system paths (e.g., `/etc/`, `System/`, `Windows/`)

- **Supply Chain Risk**
  - `DEP_INSTALL` with unpinned versions (`latest`, `*`)

## Notes
- This mapping is intentionally conservative.
- The default mode of this repo is **observability-only**.

## 仓库评估（可复现）

openclaw-flight-recorder-verified 是一个本地可观测性 PoC：输入 RFC-001 JSONL 事件日志，输出行为摘要 `badge.json` 与 hash 链收据 `receipts.jsonl`；并提供 tests + CI 作为一致性验收红线（防漂移）。

### 复现步骤（本地）
（命令以 README 的 Quickstart 为准）

1) 生成 clean 报告  
- `python src/recorder.py --input examples/clean_run.jsonl --out out_clean`

2) 生成 risky 报告（含 policy sim）  
- `python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim`

3) 运行一致性验收（Conformance Suite）  
- `python -m unittest discover -s tests -p "test_*.py" -v`

### 验收标准（必须满足）
- Clean Run：`status == "OBSERVED"` 且 `highlight_count == 0` 且 `evidence_gaps == 0`
- Risky Run：`status == "ATTENTION"` 且 `highlight_count == 7` 且 `evidence_gaps == 0`
- Risky Run（policy-sim）：`would_block == true` 且 `violation_count == 7`

### Receipts 链一致性（必须满足）
- 第一条 `prev_hash` 为 64 个 “0”
- 对任意 i>1：`prev_hash[i] == receipt_hash[i-1]`（链连续）

### 边界说明
- receipts 的 hash 链用于“事后可检测的完整性”（detect tampering），不是签名系统；如需抵抗“从头重算伪造链”，需要外部签名/时间戳/透明日志（可作为后续增强方向）。

