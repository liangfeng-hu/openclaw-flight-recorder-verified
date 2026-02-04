# Draft 003: WebSocket / Token / Gateway URL Safety Signals (Non-Sensitive Extensions)

## Status
Draft / Optional / Not part of RFC-001 standard

## Purpose
Adds non-sensitive observability fields to help diagnose and verify fixes for incidents involving:
- Untrusted gateway URL parameters
- Automatic WebSocket connections
- Authentication token exposure/forwarding
- Remote-control / command execution chains

Design goals:
- Local-only by default
- Digest-based (no raw tokens, no raw URLs)
- Compatible with RFC-001 (fields live in `details`)
- Observability-first (not an exploit guide)

---

## 1) New Optional Event Types

### 1.1 WS_CONNECT
Required:
- event_type: "WS_CONNECT"
- domain_class: "NET"

details (SHOULD):
- direction: "OUT" | "IN"
- protocol: "ws" | "wss"
- host: string
- port: int
- url_digest: "sha256:..."
- origin_digest: "sha256:..."
- gateway_source: "query_param" | "config" | "default" | "unknown"
- auto_connect: bool
- declared: bool

### 1.2 GATEWAY_URL_SET
Required:
- event_type: "GATEWAY_URL_SET"
- domain_class: "NET"

details (SHOULD):
- gateway_source: "query_param" | "config" | "default" | "unknown"
- url_digest: "sha256:..."
- validation_result: "PASS" | "FAIL" | "SKIP" | "UNKNOWN"
- allowlist_hit: bool
- reason_code: string

### 1.3 CRED_SEND (digest only)
Required:
- event_type: "CRED_SEND"
- domain_class: "NET"

details (MUST):
- cred_type: "auth_token" | "api_key" | "session_cookie" | "unknown"
- cred_digest: "sha256:..."  (NEVER raw)
- target_host: string
- target_port: int
- transport: "ws" | "wss" | "http" | "https" | "unknown"
- declared: bool

details (SHOULD):
- scope_digest: "sha256:..."
- auto_send: bool

---

## 2) Suggested Risk Highlights (facts → tags)
Non-enforcing tags a recorder may add:

- UNTRUSTED_GATEWAY_SOURCE:
  gateway_source="query_param" AND validation_result != "PASS"

- AUTO_WS_CONNECT:
  WS_CONNECT.auto_connect=true AND direction="OUT"

- CRED_CROSS_BOUNDARY:
  any CRED_SEND event exists

- UNDECLARED_CRED_SEND:
  CRED_SEND.declared=false

- WS_TO_LOCALHOST:
  WS_CONNECT.host in {"localhost","127.0.0.1","::1"} AND direction="OUT"

---

## 3) Privacy & Safety (MUST)
- Never log raw tokens/credentials; use digests only
- Never log raw URLs if they may contain secrets; use url_digest
- Default local-only; share summaries only
- Not an exploit reproduction document

---

## 4) Example JSONL Lines
```json
{"v":"flight-log/1","ts":"2026-02-03T00:00:00Z","trace_id":"demo-ws","seq":1,"actor":"client","event_type":"GATEWAY_URL_SET","payload_digest":"sha256:...","domain_class":"NET","declared":false,"details":{"gateway_source":"query_param","url_digest":"sha256:abcd...","validation_result":"FAIL","allowlist_hit":false,"reason_code":"URL_NOT_ALLOWLISTED"}}
{"v":"flight-log/1","ts":"2026-02-03T00:00:01Z","trace_id":"demo-ws","seq":2,"actor":"client","event_type":"WS_CONNECT","payload_digest":"sha256:...","domain_class":"NET","declared":false,"details":{"direction":"OUT","protocol":"wss","host":"gateway.example.com","port":443,"url_digest":"sha256:ef01...","origin_digest":"sha256:1234...","gateway_source":"query_param","auto_connect":true}}
{"v":"flight-log/1","ts":"2026-02-03T00:00:02Z","trace_id":"demo-ws","seq":3,"actor":"client","event_type":"CRED_SEND","payload_digest":"sha256:...","domain_class":"NET","declared":false,"details":{"cred_type":"auth_token","cred_digest":"sha256:9999...","target_host":"gateway.example.com","target_port":443,"transport":"wss","auto_send":true}}
