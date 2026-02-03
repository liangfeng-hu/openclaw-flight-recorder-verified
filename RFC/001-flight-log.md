# RFC 001: Flight Log Export Contract (JSONL)

## Status
Proposal / Research Preview

## Abstract
Defines a minimal, tool-agnostic JSONL format for exporting agent execution events.

Goal: Observability — enabling users to see side effects (Network / File / Exec / Supply Chain) with replayable, verifiable traces.

## Format
- UTF-8 JSON Lines (one JSON object per line)
- Ordered by `seq` ascending

## Required Fields (MUST)
Each event MUST contain:
- `v` (string): version, e.g. `"flight-log/1"`
- `ts` (string): ISO-8601 timestamp
- `trace_id` (string): run/flow ID
- `seq` (integer): monotonically increasing sequence number
- `actor` (string): agent/skill identifier
- `event_type` (string): see Event Types below
- `payload_digest` (string): digest of redacted payload (e.g., `sha256:...`)
- `domain_class` (string): coarse label (`NET`, `FILE`, `EXEC`, `SUPPLY`, ...)

## Optional Fields (SHOULD when available)
- `declared` (boolean): whether this side effect was explicitly declared/expected
- `details` (object): redacted metadata (host, path, op, cmd_digest, package, version, etc.)
- `data_complete` (boolean): whether event data is fully captured (for evidence gap detection)

## Event Types
Core:
- `ID_ROUTE`
- `TOOL_CALL`
- `FILE_IO`
- `NET_IO`
- `PROC_EXEC`
- `DEP_INSTALL`
- `TRANSFER`
- `MESSAGE_IN`
- `MESSAGE_OUT`

Extensions (optional, backward compatible):
- `DATABASE_OP`
- `API_CALL`
- `MEMORY_ACCESS`

## details schema (recommended)

### NET_IO
- `direction`: `IN` or `OUT`
- `host`
- `port`

### FILE_IO
- `op`: `read` / `write` / `delete`
- `path`

### PROC_EXEC
- `cmd_digest` (preferred)
- `cmd` (optional, redacted)

### DEP_INSTALL
- `package`
- `version` (e.g., `latest`, `1.2.3`)

### DATABASE_OP
- `db_type`
- `query` (redacted if needed)

### API_CALL
- `endpoint`
- `headers` (redacted; do NOT include secrets)

### MEMORY_ACCESS
- `size` (bytes)

## Privacy Guidance
Exporters SHOULD:
- store digests rather than raw prompts/keys/messages
- redact secrets, tokens, sensitive file contents
- prefer digests over raw values where possible
