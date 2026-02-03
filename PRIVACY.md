# Privacy

## Default Behavior
- Local-only processing by default.
- No upload of prompts, keys, raw messages, or file contents.
- The recorder is designed to work with redacted event logs using digests.

## Recommended Redaction
Exporters SHOULD:
- Replace raw prompts/messages with `payload_digest`
- Avoid exporting API keys, tokens, cookies, full file contents
- Prefer exporting command digests (`cmd_digest`) instead of raw commands (`cmd`)

## Sharing
If you share outputs publicly:
- Share `badge.json` and `receipts.jsonl` only if they contain no sensitive identifiers.
- Prefer sharing only the `badge.json` summary.
