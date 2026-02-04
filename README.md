# OpenClaw Flight Recorder (Research Preview)

[![CI](https://github.com/liangfeng-hu/openclaw-flight-recorder/actions/workflows/ci.yml/badge.svg)](https://github.com/liangfeng-hu/openclaw-flight-recorder/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)

**Version:** v0.1.0 (Research Preview)  
**Spec:** RFC-001 `flight-log/1`

The "Black Box" for AI Agents. A local, opt-in observability tool that digests agent event streams into human-readable Activity Summaries and Verifiable Receipts.

## What problem this solves
Agents often behave like black boxes. After a skill runs, users and developers need to know:
- What files were touched (read/write/delete)?
- What network hosts were contacted?
- Were any processes executed?
- Were any dependencies installed during runtime?

This project provides a simple, local Flight Recorder so you can answer: "What did the agent actually do?"

## What’s in this repo
1) RFC-001 Flight Log (JSONL): `RFC/001-flight-log.md`  
2) Reference recorder implementation (stdlib-only Python): `src/recorder.py`  
3) Examples: clean vs risky runs: `examples/*.jsonl`  
4) Reproducibility checks: `VERIFY.md` + `tests/`

## Quickstart (Local)
Requirements: Python 3.10+ (stdlib only)

```bash
# Standard mode (observability only)
python src/recorder.py --input examples/risky_run.jsonl --out out_report

# Experimental: policy simulation (advisory only)
python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim
