# OpenClaw Flight Recorder (Research Preview)

**OpenClaw 飞行记录器（研究预览）**

[![CI](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/liangfeng-hu/openclaw-flight-recorder-verified/actions/workflows/ci.yml?branch=main)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)

**Version:** v0.1.0  
**Spec:** RFC-001 `flight-log/1`

- Local-only / Opt-in / Read-only
- Not a blocking firewall
- `--policy-sim` and remediation outputs are advisory-only (no auto-fix)

## Quickstart
```bash
python src/recorder.py --input examples/clean_run.jsonl --out out_clean
python src/recorder.py --input examples/risky_run.jsonl --out out_risky
python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim

Optional: advisory suggestions (no auto-fix)
python src/recorder_ext.py --input examples/risky_run.jsonl --out out_adv --overwrite --policy-sim --suggest

Optional: config (policy.json)
python src/recorder_ext.py --input examples/risky_run.jsonl --out out_adv --overwrite --policy-sim --suggest --config policy.json

Docs

RFC/001-flight-log.md

RFC/004-remediation-advice-contract.md

RFC/drafts/003-websocket-token-safety-signals.md

PRIVACY.md

SECURITY.md

VERIFY.md

License

MIT — see LICENSE
::contentReference[oaicite:0]{index=0}
