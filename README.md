# Agent 透明外挂｜安全检测评估记录器（Research Preview）
Agent Transparency Sidecar — Local-only, opt-in, read-only evidence recorder

[![CI](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml?branch=main)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)

**Version:** v0.1.0 (Research Preview)  
**Spec:** RFC-001 `flight-log/1`

> **Zero-intrusion (no business-logic changes), opt-in, local-only, read-only by default.**  
> **零侵入（无需改业务逻辑/工作流），可选接入（opt-in），默认本地只读。**  
>
> This is **not** a blocking firewall. `--policy-sim` and remediation outputs are **advisory only** (no auto-fix).

---

## What this provides
Given a JSONL flight log, the recorder outputs:

- **badge.json**: behavior summary + risk highlights  
- **receipts.jsonl**: hash-chained, tamper-evident receipts (evidence chain)  
- *(optional, extension)* **suggestions.json** + **probe_plan.md**: advisory remediation directions (no execution)

This lets users verify: **“What did the agent actually do?”** with replayable evidence.

---

## Repo contents
- `RFC/001-flight-log.md` — minimal JSONL event export contract (Flight Log)
- `RFC/004-remediation-advice-contract.md` — advisory remediation output contract (`suggestions.json`)
- `RFC/drafts/003-websocket-token-safety-signals.md` — digest-only WS/gateway/token safety signals (draft)
- `src/recorder.py` — reference recorder (stdlib-only)
- `src/recorder_ext.py` — experimental extension (advisory suggestions via `--suggest`)
- `examples/*.jsonl` — clean vs risky traces (+ ws_token demo)
- `tests/` — CI conformance tests
- `VERIFY.md` — reproducibility & receipt-chain checks
- `PRIVACY.md` / `SECURITY.md` — privacy & security notes

---

## Quickstart (Local)
Requirements: Python 3.10+ (stdlib only)

```bash
# Standard mode (observability only)
python src/recorder.py --input examples/clean_run.jsonl --out out_clean
python src/recorder.py --input examples/risky_run.jsonl --out out_risky

# Advisory policy simulation (optional)
python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim

Outputs per run:

badge.json

receipts.jsonl

Experimental: advisory suggestions (no auto-fix)

If src/recorder_ext.py is present, you can generate remediation directions:

python src/recorder_ext.py --input examples/risky_run.jsonl --out out_adv --overwrite --policy-sim --suggest

Outputs (extension mode):

suggestions.json (Draft-004 contract)

probe_plan.md (human-friendly verification steps)

policy_template.json (optional helper)

Optional config (policy.json)

You may provide --config policy.json to override thresholds/paths/rules.
Default advisory rules are built-in; policy.json is optional.

Example policy.json:

{
  "sensitive_paths": ["/etc/", "/var/log/"],
  "policy_rules": {
    "block_unpinned_deps": true,
    "block_undeclared_actions": true,
    "block_sensitive_access": true,
    "block_sql_risks": true,
    "block_api_exposure": true,
    "block_high_memory": true,
    "block_evidence_gap": false
  },
  "memory_threshold": 1000000000
}

Conformance / Reproducibility

Pass/fail criteria: VERIFY.md

Run tests:

python -m unittest discover -s tests -p "test_*.py" -v

Receipt-chain rules (summary):

first prev_hash = 64 zeros

each prev_hash == previous receipt_hash

hashes are 64 hex chars

Security / Privacy

Local-only by default; share only digests/summaries

No VS Code extension shipped

No curl|sh installers

No secrets logged (digest-first)

See: PRIVACY.md, SECURITY.md, VERIFY.md.

Non-goals

Not a malware scanner

Not an enforcement engine

Not an exploit guide

Not a centralized reputation system

This tool is about transparent evidence and safe, local verification.

License

MIT — see LICENSE.

If the CI badge doesn’t refresh, reload the page or ensure it points to the correct workflow file under .github/workflows/.

::contentReference[oaicite:0]{index=0}

