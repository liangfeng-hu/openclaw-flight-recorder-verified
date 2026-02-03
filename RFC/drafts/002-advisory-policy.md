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
