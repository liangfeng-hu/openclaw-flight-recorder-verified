# RFC 001: Flight Log Export Contract (JSONL)

## Status
Proposal / Research Preview

## Abstract
Defines a minimal, tool-agnostic **JSONL** format for exporting agent execution events.
Goal: **Observability** — enabling users to see side effects (Network, File, Exec, Supply Chain)
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
