# RFC 001: Flight Log Export Contract (JSONL)

## Status
Proposal / Research Preview

## Abstract
Defines a minimal, tool-agnostic **JSONL** format for exporting agent execution events.

Goal: **Observability** — enable users to see and audit side effects (Network / File / Exec / Supply Chain / Tool) without relying on opaque reputation systems.

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
- `event_type` (string): one of Event Types below (unknown types are allowed but should be surfaced)
- `payload_digest` (string): digest of redacted payload (e.g., `sha256:...`)
- `domain_class` (string): coarse label (`NET`, `FILE`, `EXEC`, `SUPPLY`, `TOOL`, `ID`, ...)

## Optional Fields (SHOULD when available)
- `declared` (boolean): whether this side effect was explicitly declared/expected
- `details` (object): redacted metadata (host, path, op, cmd_digest, package, version, etc.)
- `data_complete` (boolean): whether the exporter captured enough data (for evidence gap detection)

## Event Types

Core types:
- `ID_ROUTE`
- `TOOL_CALL`
- `FILE_IO`
- `NET_IO`
- `PROC_EXEC`
- `DEP_INSTALL`
- `TRANSFER`
- `MESSAGE_IN`
- `MESSAGE_OUT`

Extension types (optional, backward compatible):
- `DATABASE_OP`
- `API_CALL`
- `MEMORY_ACCESS`

Synthetic (internal to analyzers):
- `EVIDENCE_GAP`

## details schema (recommended)

### NET_IO
- `host` (string)
- `port` (int/string)
- `direction` (string): `IN` or `OUT`

### FILE_IO
- `path` (string)
- `op` (string): `read`/`write`/`delete`

### PROC_EXEC
- `cmd_digest` (string): sha256 hex digest of redacted command
- `cmd` (string, optional): only if safe/redacted (not recommended)

### DEP_INSTALL
- `package` (string)
- `version` (string) e.g. `latest`, `1.2.3`

### DATABASE_OP (extension)
- `db_type` (string) e.g. `mysql`, `sqlite`
- `query` (string, redacted if needed)

### API_CALL (extension)
- `endpoint` (string)
- `headers` (object, redacted) — do NOT include secrets in real logs

### MEMORY_ACCESS (extension)
- `size` (number): bytes

## Privacy Guidance
Exporters SHOULD:
- store digests rather than raw prompts/keys/messages
- redact file contents, secrets, headers, tokens
- prefer `cmd_digest` over raw `cmd`
