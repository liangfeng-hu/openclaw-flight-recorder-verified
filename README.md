# OpenClaw Flight Recorder (Research Preview)

**The "Black Box" for AI Agents.**
A local, opt-in observability tool that digests agent event streams into human-readable **Activity Summaries** and **Verifiable Receipts**.

## What problem this solves
Agents often behave like black boxes. After a skill runs, users and developers need to know:
- What files were touched (read/write/delete)?
- What network hosts were contacted?
- Were any processes executed?
- Were any dependencies installed during runtime?

This project provides a simple, local **Flight Recorder** so you can answer: **"What did the agent actually do?"**

## What’s in this repo
1) **RFC-001 Flight Log (JSONL)**: a minimal event export contract (`RFC/001-flight-log.md`)
2) **Reference recorder implementation** (stdlib-only Python): `src/recorder.py`
3) **Examples**: clean vs risky runs (`examples/*.jsonl`)

## Quickstart (Local)
Requirements: Python 3.10+ (stdlib only)

```bash
# Standard mode (observability only)
python src/recorder.py --input examples/risky_run.jsonl --out out_report

# Experimental: policy simulation (advisory only)
python src/recorder.py --input examples/risky_run.jsonl --out out_sim --policy-sim
