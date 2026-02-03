#!/usr/bin/env python3
# OpenClaw Flight Recorder
# - Standard Library Only
# - Mode 1 (default): Observability-only -> facts + highlights
# - Mode 2 (--policy-sim): advisory simulation -> adds "policy_simulation" field
#
# This is a PoC. It is NOT a malware scanner.

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List

SUSPICIOUS_CMD = re.compile(r"(curl|wget).*\|.*(sh|bash|zsh)", re.IGNORECASE)
SENSITIVE_FILES = re.compile(r"^/(etc|private|System|Windows|Library)/", re.IGNORECASE)
UNPINNED_VER = re.compile(r"(^latest$)|(\*)", re.IGNORECASE)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def read_jsonl(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # Evidence gap placeholder event
                events.append({
                    "v": "flight-log/1",
                    "ts": "UNKNOWN",
                    "trace_id": "UNKNOWN",
                    "seq": line_no,
                    "actor": "parser",
                    "event_type": "EVIDENCE_GAP",
                    "payload_digest": "parse_error",
                    "domain_class": "EVIDENCE",
                    "declared": False,
                    "details": {"raw_line_no": line_no}
                })
    return events

def analyze_trace(events: List[Dict[str, Any]], sim_policy: bool) -> Dict[str, Any]:
    behavior = {
        "network_out": set(),
        "file_write": set(),
        "proc_exec": set(),
        "dep_install": set(),
    }
    highlights: List[Dict[str, Any]] = []
    evidence_gaps = 0

    policy_sim = {
        "enabled": True,
        "would_block": False,
        "violation_count": 0,
        "violations": []
    }

    for e in events:
        et = e.get("event_type", "")
        details = e.get("details", {}) or {}
        declared = bool(e.get("declared", False))
        seq = e.get("seq", -1)
        ev_hash = sha256_hex(canon_json(e))

        if et == "EVIDENCE_GAP":
            evidence_gaps += 1
            highlights.append({"tag": "EVIDENCE_GAP", "seq": seq, "evidence": ev_hash})
            if sim_policy:
                policy_sim["violations"].append(f"Seq {seq}: Evidence gap (cannot parse/observe event)")
                policy_sim["would_block"] = True
            continue

        # NET_IO (outbound)
        if et == "NET_IO" and str(details.get("direction", "")).upper() == "OUT":
            host = details.get("host", "unknown")
            port = details.get("port", "")
            behavior["network_out"].add(f"HOST:{host}:{port}")

            if not declared:
                highlights.append({"tag": "UNDECLARED_EGRESS", "seq": seq, "evidence": ev_hash})
                if sim_policy:
                    policy_sim["violations"].append(f"Seq {seq}: Undeclared egress to {host}")
                    policy_sim["would_block"] = True

        # FILE_IO (write/delete)
        elif et == "FILE_IO" and str(details.get("op", "")).lower() in ("write", "delete"):
            path = details.get("path", "unknown")
            behavior["file_write"].add(f"PATH:{path}")

            if SENSITIVE_FILES.search(path):
                highlights.append({"tag": "SENSITIVE_PATH", "seq": seq, "evidence": ev_hash})
                if sim_policy:
                    policy_sim["violations"].append(f"Seq {seq}: Sensitive file mutation {path}")
                    policy_sim["would_block"] = True

            if not declared:
                highlights.append({"tag": "UNDECLARED_FILE_MUTATION", "seq": seq, "evidence": ev_hash})
                if sim_policy:
                    policy_sim["violations"].append(f"Seq {seq}: Undeclared file mutation {path}")
                    policy_sim["would_block"] = True

        # PROC_EXEC
        elif et == "PROC_EXEC":
            cmd = details.get("cmd", "")  # optional raw; prefer cmd_digest in real exporters
            cmd_digest = details.get("cmd_digest", "unknown")
            behavior["proc_exec"].add(f"CMD_DIGEST:{cmd_digest[:16]}...")

            if cmd and SUSPICIOUS_CMD.search(cmd):
                highlights.append({"tag": "REMOTE_SCRIPT", "seq": seq, "evidence": ev_hash})
                if sim_policy:
                    policy_sim["violations"].append(f"Seq {seq}: Remote script pattern detected")
                    policy_sim["would_block"] = True

            if not declared:
                highlights.append({"tag": "UNDECLARED_EXEC", "seq": seq, "evidence": ev_hash})
                if sim_policy:
                    policy_sim["violations"].append(f"Seq {seq}: Undeclared execution")
                    policy_sim["would_block"] = True

        # DEP_INSTALL
        elif et == "DEP_INSTALL":
            pkg = str(details.get("package", "unknown"))
            ver = str(details.get("version", "unknown"))
            behavior["dep_install"].add(f"{pkg}@{ver}")

            if UNPINNED_VER.search(ver):
                highlights.append({"tag": "UNPINNED_DEP", "seq": seq, "evidence": ev_hash})
                if sim_policy:
                    policy_sim["violations"].append(f"Seq {seq}: Unpinned dependency {pkg}@{ver}")
                    policy_sim["would_block"] = True

            if not declared:
                highlights.append({"tag": "UNDECLARED_DEP_INSTALL", "seq": seq, "evidence": ev_hash})
                if sim_policy:
                    policy_sim["violations"].append(f"Seq {seq}: Undeclared dependency install {pkg}@{ver}")
                    policy_sim["would_block"] = True

    # status is descriptive, not judgmental
    status = "OBSERVED"
    if highlights:
        status = "ATTENTION"
    if evidence_gaps > 0:
        status = f"{status}_WITH_GAPS"

    report = {
        "status": status,
        "behavior_summary": {k: sorted(list(v)) for k, v in behavior.items()},
        "risk_highlights": highlights,
        "stats": {
            "total_events": len(events),
            "highlight_count": len(highlights),
            "evidence_gaps": evidence_gaps
        }
    }

    if sim_policy:
        policy_sim["violation_count"] = len(policy_sim["violations"])
        report["policy_simulation"] = policy_sim

    return report

def build_receipts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    receipts: List[Dict[str, Any]] = []
    prev_hash = "0" * 64

    for e in events:
        event_hash = sha256_hex(canon_json(e))
        receipt = {
            "trace_id": e.get("trace_id", "UNKNOWN"),
            "seq": e.get("seq", -1),
            "event_type": e.get("event_type", "UNKNOWN"),
            "event_hash": event_hash,
            "prev_hash": prev_hash
        }
        receipt_hash = sha256_hex(canon_json(receipt))
        receipt["receipt_hash"] = receipt_hash

        receipts.append(receipt)
        prev_hash = receipt_hash

    return receipts

def write_json(path: str, obj: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def main() -> None:
    ap = argparse.ArgumentParser(description="OpenClaw Flight Recorder (PoC)")
    ap.add_argument("--input", required=True, help="Path to JSONL flight logs (RFC-001)")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--policy-sim", action="store_true",
                    help="Enable experimental advisory policy simulation (NOT enforcement)")
    ap.add_argument("--overwrite", action="store_true",
                    help="Overwrite output directory if it already contains files")
    args = ap.parse_args()

    if os.path.exists(args.out) and os.path.isdir(args.out):
        if os.listdir(args.out) and not args.overwrite:
            print(f"[!] Output directory not empty: {args.out}", file=sys.stderr)
            print("[!] Choose a new --out directory or pass --overwrite", file=sys.stderr)
            sys.exit(2)
    os.makedirs(args.out, exist_ok=True)

    events = read_jsonl(args.input)
    report = analyze_trace(events, sim_policy=args.policy_sim)
    receipts = build_receipts(events)

    write_json(os.path.join(args.out, "badge.json"), report)
    write_jsonl(os.path.join(args.out, "receipts.jsonl"), receipts)

    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
