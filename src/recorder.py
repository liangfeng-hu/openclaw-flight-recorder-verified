#!/usr/bin/env python3
"""
OpenClaw Flight Recorder (Research Preview) — Offline Analyzer

✅ CLI (fixed):
  --input <jsonl> --out <dir> [--policy-sim] [--overwrite] [--config policy.json] [--profile advisory|strict_advisory]
  --verify-receipts <receipts.jsonl>

✅ Input:
  RFC-001 JSONL events (expects details.* + declared boolean). Also tolerates some top-level fallbacks.

✅ Output:
  badge.json + receipts.jsonl (hash-chained)

Goals:
- Observability-first (dashcam). policy-sim is advisory only.

This file is designed to keep the original repo conformance:
- clean_run -> OBSERVED, 0 highlights, 0 gaps
- risky_run -> ATTENTION, 7 highlights; policy-sim -> would_block True, violation_count 7
- ext_run -> extension highlights + policy-sim -> 3 violations
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import datetime as _dt
import re
from typing import Any, Dict, List, Optional, Tuple, Iterable


# ----------------------------
# Constants / Defaults
# ----------------------------

RFC_VERSION = "flight-log/1"

KNOWN_EVENT_TYPES = {
    "ID_ROUTE", "TOOL_CALL", "FILE_IO", "NET_IO", "PROC_EXEC", "DEP_INSTALL",
    "TRANSFER", "MESSAGE_IN", "MESSAGE_OUT",
    "DATABASE_OP", "API_CALL", "MEMORY_ACCESS",
    "EVIDENCE_GAP",
}

RISK_TAGS = {
    "UNPINNED_DEP": "Unpinned dependency install",
    "UNDECLARED_DEP_INSTALL": "Undeclared dependency install",
    "REMOTE_SCRIPT": "Remote script execution pattern",
    "UNDECLARED_EXEC": "Undeclared process execution",
    "SENSITIVE_PATH": "Sensitive path access/mutation",
    "UNDECLARED_FILE_MUTATION": "Undeclared file mutation",
    "UNDECLARED_EGRESS": "Undeclared network egress",
    "EVIDENCE_GAP": "Missing or incomplete event data",
    "UNKNOWN_EVENT_TYPE": "Unknown event_type (not in RFC enum)",

    "SQL_RISK": "High-risk DB operation (drop/delete without where)",
    "API_CREDENTIAL_EXPOSURE": "Potential credential exposure in API call",
    "HIGH_MEMORY_ACCESS": "High memory access/alloc size",
}

DEFAULT_SENSITIVE_PREFIXES = [
    "/etc/", "/var/log/", "/root/", "/home/", "/Users/",
    "C:\\Windows\\System32\\", "C:\\Windows\\",
]

DEFAULT_POLICY_PROFILES = {
    # Important: keep existing conformance (risky_run = 7 violations)
    "advisory": {
        "block_unpinned_deps": True,
        "block_undeclared_actions": True,
        "block_sensitive_paths": True,
        "block_remote_script": True,
        "block_sql_risks": True,
        "block_api_exposure": True,
        "block_high_memory": True,
        "block_on_gaps": False,
        "block_on_unknown": False,
    },
    "strict_advisory": {
        "block_unpinned_deps": True,
        "block_undeclared_actions": True,
        "block_sensitive_paths": True,
        "block_remote_script": True,
        "block_sql_risks": True,
        "block_api_exposure": True,
        "block_high_memory": True,
        "block_on_gaps": True,
        "block_on_unknown": True,
    },
}

DEFAULT_MEMORY_THRESHOLD_BYTES = 1_000_000_000  # 1GB
REMOTE_SCRIPT_RE = re.compile(r"\b(curl|wget)\b.*\|\s*(bash|sh)\b", re.IGNORECASE)


# ----------------------------
# Helpers
# ----------------------------

def _iso_now_utc() -> str:
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _canon_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def _sha256_hex_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()

def _safe_open_text(path: str):
    return open(path, "r", encoding="utf-8", errors="replace")

def _is_hex64(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False


def load_policy_config(path: Optional[str]) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "profile": "advisory",
        "profiles": dict(DEFAULT_POLICY_PROFILES),
        "policy_rules": {},
        "sensitive_prefixes": list(DEFAULT_SENSITIVE_PREFIXES),
        "memory_threshold_bytes": DEFAULT_MEMORY_THRESHOLD_BYTES,
    }
    if not path or not os.path.exists(path):
        return cfg

    with _safe_open_text(path) as f:
        try:
            user = json.load(f)
        except Exception:
            return cfg

    if isinstance(user, dict):
        if isinstance(user.get("profile"), str):
            cfg["profile"] = user["profile"]

        if isinstance(user.get("profiles"), dict):
            merged = dict(cfg["profiles"])
            for name, rules in user["profiles"].items():
                if isinstance(rules, dict):
                    base = dict(merged.get(name, {}))
                    for k, v in rules.items():
                        base[k] = bool(v)
                    merged[name] = base
            cfg["profiles"] = merged

        if isinstance(user.get("policy_rules"), dict):
            cfg["policy_rules"] = {k: bool(v) for k, v in user["policy_rules"].items()}

        if isinstance(user.get("sensitive_prefixes"), list):
            cfg["sensitive_prefixes"] = [str(x) for x in user["sensitive_prefixes"]]

        if isinstance(user.get("memory_threshold_bytes"), (int, float)):
            cfg["memory_threshold_bytes"] = float(user["memory_threshold_bytes"])

    return cfg


def pick_rules(cfg: Dict[str, Any], profile_override: Optional[str]) -> Tuple[str, Dict[str, bool]]:
    profile = profile_override or cfg.get("profile") or "advisory"
    profiles = cfg.get("profiles") or {}
    base = dict(profiles.get(profile, profiles.get("advisory", {})))
    base.update(dict(cfg.get("policy_rules") or {}))
    rules = {k: bool(v) for k, v in base.items()}
    return profile, rules


def merge_details(event: Dict[str, Any]) -> Dict[str, Any]:
    details = event.get("details")
    if not isinstance(details, dict):
        details = {}
    # tolerate top-level fallbacks
    for k in [
        "host", "port", "direction",
        "path", "op", "mode",
        "cmd", "cmd_digest",
        "package", "version", "dep_name",
        "db_type", "query", "endpoint", "headers",
        "size",
    ]:
        if k in event and k not in details:
            details[k] = event[k]
    return details


def event_declared(event: Dict[str, Any], declared_intents: Optional[Iterable[str]]) -> bool:
    d = event.get("declared")
    if isinstance(d, bool):
        return d
    # optional fallback
    et = str(event.get("event_type", ""))
    if declared_intents:
        return et in set([str(x).strip() for x in declared_intents if str(x).strip()])
    return False


def must_fields_missing(event: Dict[str, Any]) -> List[str]:
    must = ["v", "ts", "trace_id", "seq", "actor", "event_type", "payload_digest", "domain_class"]
    return [k for k in must if k not in event or event.get(k) in (None, "")]


def required_details_missing(event_type: str, details: Dict[str, Any]) -> List[str]:
    req: Dict[str, List[str]] = {
        "NET_IO": ["host", "port", "direction"],
        "FILE_IO": ["path", "op"],
        "PROC_EXEC": ["cmd_digest"],
        "DEP_INSTALL": ["package", "version"],
        "DATABASE_OP": ["db_type", "query"],
        "API_CALL": ["endpoint"],
        "MEMORY_ACCESS": ["size"],
    }
    needed = req.get(event_type, [])
    return [k for k in needed if details.get(k) in (None, "")]


# ----------------------------
# Core logic
# ----------------------------

def analyze_events(
    events: List[Dict[str, Any]],
    declared_intents: Optional[Iterable[str]],
    policy_cfg: Dict[str, Any],
    policy_profile: Optional[str],
    do_policy_sim: bool,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:

    sensitive_prefixes: List[str] = policy_cfg.get("sensitive_prefixes") or list(DEFAULT_SENSITIVE_PREFIXES)
    memory_threshold = float(policy_cfg.get("memory_threshold_bytes") or DEFAULT_MEMORY_THRESHOLD_BYTES)
    profile_name, rules = pick_rules(policy_cfg, policy_profile)

    behavior_summary: Dict[str, List[str]] = {
        "network_out": [],
        "file_write": [],
        "proc_exec": [],
        "dep_install": [],
    }

    risk_highlights: List[Dict[str, Any]] = []
    evidence_gaps = 0

    receipts: List[Dict[str, Any]] = []
    prev_hash = "0" * 64

    for idx, ev in enumerate(events):
        et = str(ev.get("event_type", "UNKNOWN"))
        trace_id = str(ev.get("trace_id", "unknown-trace"))
        seq = ev.get("seq")
        if not isinstance(seq, int):
            seq = idx + 1

        details = merge_details(ev)
        declared = event_declared(ev, declared_intents)

        missing_must = must_fields_missing(ev)
        missing_det = required_details_missing(et, details)
        data_complete = ev.get("data_complete", True)
        has_gap = bool(missing_must or missing_det or (data_complete is False))

        if has_gap:
            evidence_gaps += 1
            risk_highlights.append({
                "tag": "EVIDENCE_GAP",
                "seq": seq,
                "evidence": ev.get("payload_digest", ""),
                "missing_must": missing_must,
                "missing_details": missing_det,
            })

        if et not in KNOWN_EVENT_TYPES:
            risk_highlights.append({
                "tag": "UNKNOWN_EVENT_TYPE",
                "seq": seq,
                "evidence": ev.get("payload_digest", ""),
                "event_type": et,
            })

        # --- Type-specific summaries & risks ---
        if et == "NET_IO":
            direction = str(details.get("direction", "")).upper()
            host = str(details.get("host", ""))
            port = str(details.get("port", ""))
            if direction == "OUT":
                behavior_summary["network_out"].append(f"HOST:{host}:{port}")
                if not declared:
                    risk_highlights.append({"tag": "UNDECLARED_EGRESS", "seq": seq, "evidence": ev.get("payload_digest", "")})

        elif et == "FILE_IO":
            op = str(details.get("op", "")).lower()
            path = str(details.get("path", ""))
            if op in ("write", "delete"):
                behavior_summary["file_write"].append(f"PATH:{path}")
                if any(path.startswith(p) for p in sensitive_prefixes):
                    risk_highlights.append({"tag": "SENSITIVE_PATH", "seq": seq, "evidence": ev.get("payload_digest", ""), "path": path})
                if not declared:
                    risk_highlights.append({"tag": "UNDECLARED_FILE_MUTATION", "seq": seq, "evidence": ev.get("payload_digest", ""), "path": path})

        elif et == "PROC_EXEC":
            cmd = str(details.get("cmd", ""))
            cmd_digest = str(details.get("cmd_digest", ""))
            if not cmd_digest and cmd:
                cmd_digest = _sha256_hex_str(cmd)
            behavior_summary["proc_exec"].append(f"CMD_DIGEST:sha256:{cmd_digest}")

            if cmd and REMOTE_SCRIPT_RE.search(cmd):
                risk_highlights.append({"tag": "REMOTE_SCRIPT", "seq": seq, "evidence": ev.get("payload_digest", ""), "cmd_digest": cmd_digest})
            if not declared:
                risk_highlights.append({"tag": "UNDECLARED_EXEC", "seq": seq, "evidence": ev.get("payload_digest", ""), "cmd_digest": cmd_digest})

        elif et == "DEP_INSTALL":
            package = str(details.get("package", details.get("dep_name", "")))
            version = str(details.get("version", ""))
            behavior_summary["dep_install"].append(f"{package}@{version}" if version else package)

            if version.lower() in ("latest", "*", "") or package.endswith("@latest"):
                risk_highlights.append({"tag": "UNPINNED_DEP", "seq": seq, "evidence": ev.get("payload_digest", ""), "dep": f"{package}@{version}"})
            if not declared:
                risk_highlights.append({"tag": "UNDECLARED_DEP_INSTALL", "seq": seq, "evidence": ev.get("payload_digest", ""), "dep": f"{package}@{version}"})

        elif et == "DATABASE_OP":
            behavior_summary.setdefault("database_op", [])
            db_type = str(details.get("db_type", ""))
            query = str(details.get("query", ""))
            behavior_summary["database_op"].append(f"DB:{db_type} QUERY_HASH:{_sha256_hex_str(query)}")

            q = query.lower()
            if "drop" in q or ("delete" in q and "where" not in q):
                risk_highlights.append({"tag": "SQL_RISK", "seq": seq, "evidence": ev.get("payload_digest", ""), "db_type": db_type})

        elif et == "API_CALL":
            behavior_summary.setdefault("api_call", [])
            endpoint = str(details.get("endpoint", ""))
            behavior_summary["api_call"].append(f"ENDPOINT:{endpoint}")

            headers = details.get("headers", {})
            if isinstance(headers, dict):
                for k, v in headers.items():
                    lk = str(k).lower()
                    if lk in ("api_key", "x-api-key", "authorization") and str(v).strip():
                        if "redacted" not in str(v).lower():
                            risk_highlights.append({"tag": "API_CREDENTIAL_EXPOSURE", "seq": seq, "evidence": ev.get("payload_digest", ""), "header": k})
                            break

        elif et == "MEMORY_ACCESS":
            behavior_summary.setdefault("memory_access", [])
            size = details.get("size", 0)
            try:
                size_f = float(size)
            except Exception:
                size_f = 0.0
            behavior_summary["memory_access"].append(f"SIZE:{int(size_f)}")
            if size_f > memory_threshold:
                risk_highlights.append({"tag": "HIGH_MEMORY_ACCESS", "seq": seq, "evidence": ev.get("payload_digest", ""), "size": int(size_f)})

        # --- Receipt chain ---
        event_hash = _sha256_hex_str(_canon_json(ev))
        receipt_core = {"trace_id": trace_id, "seq": seq, "event_type": et, "event_hash": event_hash, "prev_hash": prev_hash}
        receipt_hash = _sha256_hex_str(_canon_json(receipt_core))
        receipt = dict(receipt_core)
        receipt["receipt_hash"] = receipt_hash
        receipts.append(receipt)
        prev_hash = receipt_hash

    highlight_count = len([h for h in risk_highlights if h.get("tag")])

    if highlight_count == 0:
        status = "OBSERVED"
    elif evidence_gaps > 0:
        status = "ATTENTION_WITH_GAPS"
    else:
        status = "ATTENTION"

    badge: Dict[str, Any] = {
        "status": status,
        "behavior_summary": behavior_summary,
        "risk_highlights": risk_highlights,
        "stats": {"total_events": len(events), "highlight_count": highlight_count, "evidence_gaps": evidence_gaps},
    }

    if do_policy_sim:
        badge["policy_simulation"] = simulate_policy(risk_highlights, rules, profile_name)

    return badge, receipts


def simulate_policy(highlights: List[Dict[str, Any]], rules: Dict[str, bool], profile_name: str) -> Dict[str, Any]:
    violations: List[str] = []
    would_block = False

    for h in highlights:
        tag = h.get("tag")
        seq = h.get("seq")
        if not tag:
            continue

        blocked = False
        if tag in ("UNPINNED_DEP", "UNDECLARED_DEP_INSTALL"):
            blocked = rules.get("block_unpinned_deps", False)
        elif tag in ("UNDECLARED_EXEC", "UNDECLARED_FILE_MUTATION", "UNDECLARED_EGRESS"):
            blocked = rules.get("block_undeclared_actions", False)
        elif tag == "REMOTE_SCRIPT":
            blocked = rules.get("block_remote_script", False)
        elif tag == "SENSITIVE_PATH":
            blocked = rules.get("block_sensitive_paths", False)
        elif tag == "SQL_RISK":
            blocked = rules.get("block_sql_risks", False)
        elif tag == "API_CREDENTIAL_EXPOSURE":
            blocked = rules.get("block_api_exposure", False)
        elif tag == "HIGH_MEMORY_ACCESS":
            blocked = rules.get("block_high_memory", False)
        elif tag == "EVIDENCE_GAP":
            blocked = rules.get("block_on_gaps", False)
        elif tag == "UNKNOWN_EVENT_TYPE":
            blocked = rules.get("block_on_unknown", False)

        if blocked:
            would_block = True
            if tag == "UNPINNED_DEP":
                violations.append(f"Seq {seq}: Unpinned dependency {h.get('dep','')}".strip())
            elif tag == "UNDECLARED_DEP_INSTALL":
                violations.append(f"Seq {seq}: Undeclared dependency install {h.get('dep','')}".strip())
            elif tag == "REMOTE_SCRIPT":
                violations.append(f"Seq {seq}: Remote script pattern detected")
            elif tag == "UNDECLARED_EXEC":
                violations.append(f"Seq {seq}: Undeclared execution")
            elif tag == "SENSITIVE_PATH":
                violations.append(f"Seq {seq}: Sensitive file mutation {h.get('path','')}".strip())
            elif tag == "UNDECLARED_FILE_MUTATION":
                violations.append(f"Seq {seq}: Undeclared file mutation {h.get('path','')}".strip())
            elif tag == "UNDECLARED_EGRESS":
                violations.append(f"Seq {seq}: Undeclared egress")
            elif tag == "SQL_RISK":
                violations.append(f"Seq {seq}: High-risk database operation")
            elif tag == "API_CREDENTIAL_EXPOSURE":
                violations.append(f"Seq {seq}: Potential API credential exposure")
            elif tag == "HIGH_MEMORY_ACCESS":
                violations.append(f"Seq {seq}: High memory access")
            elif tag == "EVIDENCE_GAP":
                violations.append(f"Seq {seq}: Evidence gap (missing fields)")
            elif tag == "UNKNOWN_EVENT_TYPE":
                violations.append(f"Seq {seq}: Unknown event_type {h.get('event_type','unknown')}")
            else:
                violations.append(f"Seq {seq}: {tag}")

    return {"enabled": True, "profile": profile_name, "would_block": bool(would_block), "violation_count": len(violations), "violations": violations}


def write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def verify_receipts_file(path: str) -> Tuple[bool, str]:
    if not os.path.exists(path):
        return False, f"missing receipts file: {path}"
    rows: List[Dict[str, Any]] = []
    with _safe_open_text(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                return False, "invalid JSONL in receipts"
    if not rows:
        return False, "receipts empty"

    for i, r in enumerate(rows):
        for k in ("trace_id", "seq", "event_type", "event_hash", "prev_hash", "receipt_hash"):
            if k not in r:
                return False, f"missing key '{k}' at line {i+1}"
        if not _is_hex64(r["event_hash"]): return False, f"bad event_hash at seq={r.get('seq')}"
        if not _is_hex64(r["prev_hash"]): return False, f"bad prev_hash at seq={r.get('seq')}"
        if not _is_hex64(r["receipt_hash"]): return False, f"bad receipt_hash at seq={r.get('seq')}"

        core = {"trace_id": r["trace_id"], "seq": r["seq"], "event_type": r["event_type"], "event_hash": r["event_hash"], "prev_hash": r["prev_hash"]}
        expect = _sha256_hex_str(_canon_json(core))
        if r["receipt_hash"] != expect:
            return False, f"receipt_hash mismatch at seq={r.get('seq')}"

    for i in range(1, len(rows)):
        if rows[i]["prev_hash"] != rows[i-1]["receipt_hash"]:
            return False, f"chain broken at seq={rows[i].get('seq')}"

    return True, "OK"


def maybe_write_anchor(out_dir: str, receipts: List[Dict[str, Any]], anchor_path: Optional[str]) -> Optional[str]:
    if not anchor_path:
        return None
    final_hash = receipts[-1]["receipt_hash"] if receipts else ("0" * 64)
    trace_id = receipts[-1]["trace_id"] if receipts else "unknown-trace"

    anchor = {"trace_id": trace_id, "event_count": len(receipts), "final_receipt_hash": final_hash, "generated_at": _iso_now_utc()}
    key = os.environ.get("FLIGHT_ANCHOR_KEY", "")
    if key:
        sig = hmac.new(key.encode("utf-8", errors="replace"), _canon_json(anchor).encode("utf-8"), hashlib.sha256).hexdigest()
        anchor["hmac_sha256"] = sig

    path = anchor_path if os.path.isabs(anchor_path) else os.path.join(out_dir, anchor_path)
    write_json(path, anchor)
    return path


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OpenClaw Flight Recorder (offline analyzer)")
    p.add_argument("--input", help="JSONL flight log input")
    p.add_argument("--out", help="Output directory")
    p.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty output directory")
    p.add_argument("--policy-sim", action="store_true", help="Enable advisory policy simulation output")
    p.add_argument("--config", default=None, help="Optional policy.json config (see RFC/002)")
    p.add_argument("--profile", default=None, help="Policy profile name (advisory / strict_advisory)")
    p.add_argument("--declared-intents", default="", help="Comma-separated event_types considered declared (fallback only)")
    p.add_argument("--verify-receipts", default=None, help="Verify a receipts.jsonl file and exit")
    p.add_argument("--anchor-out", default=None, help="Write anchor JSON (relative to out/ if not absolute)")
    return p.parse_args(argv)


def ensure_out_dir(out_dir: str, overwrite: bool) -> None:
    if os.path.exists(out_dir):
        if os.listdir(out_dir) and not overwrite:
            raise SystemExit(f"Output dir not empty: {out_dir}. Use a new dir or pass --overwrite.")
    else:
        os.makedirs(out_dir, exist_ok=True)


def read_jsonl_events(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with _safe_open_text(path) as f:
        for lineno, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
                if not isinstance(obj, dict):
                    raise ValueError("non-object json")
                events.append(obj)
            except Exception:
                payload = f"parse_error_line_{lineno}"
                ev = {
                    "v": RFC_VERSION,
                    "ts": _iso_now_utc(),
                    "trace_id": "unknown-trace",
                    "seq": lineno,
                    "actor": "unknown",
                    "event_type": "EVIDENCE_GAP",
                    "payload_digest": "sha256:" + _sha256_hex_str(payload),
                    "domain_class": "META",
                    "declared": False,
                    "data_complete": False,
                    "details": {"reason": "json_parse_error", "lineno": lineno},
                }
                events.append(ev)
    return events


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    if args.verify_receipts:
        ok, msg = verify_receipts_file(args.verify_receipts)
        print(msg)
        return 0 if ok else 2

    if not args.input or not args.out:
        print("Error: --input and --out are required (unless --verify-receipts is used).", file=sys.stderr)
        return 2

    policy_cfg = load_policy_config(args.config)
    declared_intents = [x.strip() for x in args.declared_intents.split(",") if x.strip()] if args.declared_intents else None

    ensure_out_dir(args.out, args.overwrite)

    events = read_jsonl_events(args.input)
    badge, receipts = analyze_events(events, declared_intents, policy_cfg, args.profile, args.policy_sim)

    write_json(os.path.join(args.out, "badge.json"), badge)
    write_jsonl(os.path.join(args.out, "receipts.jsonl"), receipts)

    # optional anchor
    maybe_write_anchor(args.out, receipts, args.anchor_out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
