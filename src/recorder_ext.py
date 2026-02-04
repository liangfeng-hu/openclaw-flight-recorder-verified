#!/usr/bin/env python3
# OpenClaw Flight Recorder EXT (Experimental)
# - RFC-001 details-compatible
# - Deterministic receipt_hash
# - Optional policy simulation
# - NEW: advisory suggestions (facts -> template), no auto-fix

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import copy
import re
import hashlib

# Ensure local imports from src/
sys.path.insert(0, os.path.dirname(__file__))
from remediation_advisor import generate_suggestions, build_probe_plan_md  # noqa

DEFAULT_SENSITIVE_PATHS = ["/etc/", "/var/log/", "/home/user/.ssh/"]
DEFAULT_POLICY_RULES = {
    "block_unpinned_deps": True,
    "block_undeclared_actions": True,
    "block_sensitive_access": True,
    "block_sql_risks": True,
    "block_api_exposure": True,
    "block_high_memory": True,
    "block_evidence_gap": False,
}
DEFAULT_MEMORY_THRESHOLD = 1_000_000_000

REMOTE_SCRIPT_PAT = re.compile(r"(curl|wget).*\|.*(sh|bash|zsh)", re.IGNORECASE)
UNPINNED_VER_PAT = re.compile(r"(^latest$)|(\*)", re.IGNORECASE)


def canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def safe_str(x: Any) -> str:
    return "" if x is None else str(x)

def get_details(event: Dict[str, Any]) -> Dict[str, Any]:
    d = event.get("details")
    return d if isinstance(d, dict) else {}

def get_field(event: Dict[str, Any], key: str, default: Any = None) -> Any:
    d = get_details(event)
    if key in d:
        return d.get(key)
    return event.get(key, default)

def get_declared(event: Dict[str, Any], declared_intents: Optional[set]) -> bool:
    et = safe_str(event.get("event_type", ""))
    if declared_intents and et in declared_intents:
        return True
    if "declared" in event:
        return bool(event.get("declared"))
    d = get_details(event)
    if "declared" in d:
        return bool(d.get("declared"))
    return False

def normalize_event(event: Dict[str, Any], seq: int) -> Dict[str, Any]:
    e = copy.deepcopy(event)
    e["seq"] = int(e.get("seq", seq))
    if not isinstance(e.get("details"), dict):
        e["details"] = {}
    return e

def required_fields_for_event_type(event_type: str) -> List[str]:
    mapping = {
        "NET_IO": ["host", "port", "direction"],
        "FILE_IO": ["path", "op"],
        "DATABASE_OP": ["db_type", "query"],
        "API_CALL": ["endpoint"],
        "MEMORY_ACCESS": ["size"],
        # Draft-003 optional types
        "WS_CONNECT": ["host", "port", "direction", "protocol"],
        "GATEWAY_URL_SET": ["gateway_source", "url_digest", "validation_result"],
        "CRED_SEND": ["cred_type", "cred_digest", "target_host", "target_port", "transport"],
    }
    return mapping.get(event_type, [])

def is_evidence_gap(event: Dict[str, Any]) -> bool:
    et = safe_str(event.get("event_type", ""))
    if event.get("data_complete") is False:
        return True
    if get_field(event, "data_complete") is False:
        return True
    req = required_fields_for_event_type(et)
    for k in req:
        v = get_field(event, k, None)
        if v is None or (isinstance(v, str) and v.strip() == ""):
            return True
    return False


def detect_risks(event: Dict[str, Any], declared_intents: Optional[set], sensitive_paths: List[str], memory_threshold: int) -> List[Dict[str, Any]]:
    risks: List[Dict[str, Any]] = []
    et = safe_str(event.get("event_type", ""))
    seq = int(event.get("seq", -1))
    ev_hash = sha256_hex(canon_json(event))
    declared = get_declared(event, declared_intents)

    # DEP_INSTALL (RFC-001 details compatible)
    if et == "DEP_INSTALL":
        pkg = safe_str(get_field(event, "package", ""))
        ver = safe_str(get_field(event, "version", ""))
        dep_name = safe_str(get_field(event, "dep_name", ""))

        if ver and UNPINNED_VER_PAT.search(ver):
            risks.append({"tag": "UNPINNED_DEP", "seq": seq, "evidence": ev_hash})
        if dep_name and "@latest" in dep_name:
            risks.append({"tag": "UNPINNED_DEP", "seq": seq, "evidence": ev_hash})
        if not declared:
            risks.append({"tag": "UNDECLARED_DEP_INSTALL", "seq": seq, "evidence": ev_hash})

    # PROC_EXEC
    elif et == "PROC_EXEC":
        cmd = safe_str(get_field(event, "cmd", ""))
        if cmd and REMOTE_SCRIPT_PAT.search(cmd):
            risks.append({"tag": "REMOTE_SCRIPT", "seq": seq, "evidence": ev_hash})
        if not declared:
            risks.append({"tag": "UNDECLARED_EXEC", "seq": seq, "evidence": ev_hash})

    # FILE_IO
    elif et == "FILE_IO":
        path = safe_str(get_field(event, "path", ""))
        op = safe_str(get_field(event, "op", "")).lower()
        mode = safe_str(get_field(event, "mode", "")).lower()

        if path and any(path.startswith(pfx) for pfx in sensitive_paths):
            risks.append({"tag": "SENSITIVE_PATH", "seq": seq, "evidence": ev_hash})

        is_mutation = op in ("write", "delete") or mode in ("w", "a", "x")
        if is_mutation and not declared:
            risks.append({"tag": "UNDECLARED_FILE_MUTATION", "seq": seq, "evidence": ev_hash})

    # NET_IO
    elif et == "NET_IO":
        direction = safe_str(get_field(event, "direction", "")).upper()
        if direction == "OUT" and not declared:
            risks.append({"tag": "UNDECLARED_NET_IO", "seq": seq, "evidence": ev_hash})

    # DATABASE_OP
    elif et == "DATABASE_OP":
        query = safe_str(get_field(event, "query", "")).lower()
        if "drop" in query or ("delete" in query and "where" not in query):
            risks.append({"tag": "SQL_INJECTION_RISK", "seq": seq, "evidence": ev_hash})

    # API_CALL
    elif et == "API_CALL":
        headers = get_field(event, "headers", {}) or {}
        if not isinstance(headers, dict):
            headers = {}
        def nonempty(v: Any) -> bool:
            s = str(v).strip() if v is not None else ""
            return bool(s) and s.upper() not in ("REDACTED", "MASKED", "<REDACTED>", "***")
        found = False
        if "api_key" in headers and nonempty(headers.get("api_key")):
            found = True
        for k, v in headers.items():
            kl = str(k).lower()
            if kl.startswith("authorization") or kl in ("x-api-key", "x_api_key", "api-key"):
                if nonempty(v):
                    found = True
                    break
        if found:
            risks.append({"tag": "API_KEY_EXPOSURE", "seq": seq, "evidence": ev_hash})

    # MEMORY_ACCESS
    elif et == "MEMORY_ACCESS":
        size = get_field(event, "size", 0)
        try:
            size_int = int(size)
        except Exception:
            size_int = 0
        if size_int > int(memory_threshold):
            risks.append({"tag": "MEMORY_OVERFLOW_RISK", "seq": seq, "evidence": ev_hash})

    # Draft-003: GATEWAY_URL_SET / WS_CONNECT / CRED_SEND
    elif et == "GATEWAY_URL_SET":
        src = safe_str(get_field(event, "gateway_source", "unknown"))
        vr = safe_str(get_field(event, "validation_result", "UNKNOWN")).upper()
        allow_hit = bool(get_field(event, "allowlist_hit", False))
        if src == "query_param" and vr != "PASS":
            risks.append({"tag": "UNTRUSTED_GATEWAY_SOURCE", "seq": seq, "evidence": ev_hash})
        if vr == "SKIP":
            risks.append({"tag": "GATEWAY_VALIDATION_SKIPPED", "seq": seq, "evidence": ev_hash})
        if allow_hit is False:
            risks.append({"tag": "ALLOWLIST_MISS", "seq": seq, "evidence": ev_hash})

    elif et == "WS_CONNECT":
        direction = safe_str(get_field(event, "direction", "")).upper()
        auto_connect = bool(get_field(event, "auto_connect", False))
        host = safe_str(get_field(event, "host", ""))
        if direction == "OUT" and auto_connect:
            risks.append({"tag": "AUTO_WS_CONNECT", "seq": seq, "evidence": ev_hash})
        if host in ("localhost", "127.0.0.1", "::1") and direction == "OUT":
            risks.append({"tag": "WS_TO_LOCALHOST", "seq": seq, "evidence": ev_hash})

    elif et == "CRED_SEND":
        risks.append({"tag": "CRED_CROSS_BOUNDARY", "seq": seq, "evidence": ev_hash})
        if not declared:
            risks.append({"tag": "UNDECLARED_CRED_SEND", "seq": seq, "evidence": ev_hash})

    # Evidence gap
    if is_evidence_gap(event):
        risks.append({"tag": "EVIDENCE_GAP", "seq": seq, "evidence": ev_hash})

    return risks


def simulate_policy(risks: List[Dict[str, Any]], policy_rules: Dict[str, bool]) -> Dict[str, Any]:
    violations: List[str] = []
    would_block = False
    count = 0

    def block(tag: str) -> bool:
        if tag in ("UNPINNED_DEP", "UNDECLARED_DEP_INSTALL"):
            return policy_rules.get("block_unpinned_deps", True)
        if tag in ("REMOTE_SCRIPT", "UNDECLARED_EXEC", "UNDECLARED_FILE_MUTATION", "UNDECLARED_NET_IO", "UNDECLARED_CRED_SEND"):
            return policy_rules.get("block_undeclared_actions", True)
        if tag in ("SENSITIVE_PATH", "WS_TO_LOCALHOST"):
            return policy_rules.get("block_sensitive_access", True)
        if tag == "SQL_INJECTION_RISK":
            return policy_rules.get("block_sql_risks", True)
        if tag == "API_KEY_EXPOSURE":
            return policy_rules.get("block_api_exposure", True)
        if tag == "MEMORY_OVERFLOW_RISK":
            return policy_rules.get("block_high_memory", True)
        if tag in ("UNTRUSTED_GATEWAY_SOURCE", "AUTO_WS_CONNECT", "CRED_CROSS_BOUNDARY"):
            return True  # conservative in sim mode
        if tag == "EVIDENCE_GAP":
            return policy_rules.get("block_evidence_gap", False)
        return False

    for r in risks:
        tag = str(r.get("tag", ""))
        seq = r.get("seq", -1)
        if block(tag):
            violations.append(f"Seq {seq}: {tag} (evidence={str(r.get('evidence',''))[:16]}...)")
            count += 1
            would_block = True

    return {"enabled": True, "would_block": would_block, "violation_count": count, "violations": violations}


def load_config(path: Optional[str]) -> Tuple[List[str], Dict[str, bool], int]:
    if not path or not os.path.exists(path):
        return DEFAULT_SENSITIVE_PATHS, DEFAULT_POLICY_RULES, DEFAULT_MEMORY_THRESHOLD
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return DEFAULT_SENSITIVE_PATHS, DEFAULT_POLICY_RULES, DEFAULT_MEMORY_THRESHOLD

    sensitive_paths = cfg.get("sensitive_paths", DEFAULT_SENSITIVE_PATHS)
    if not isinstance(sensitive_paths, list):
        sensitive_paths = DEFAULT_SENSITIVE_PATHS

    policy_rules = cfg.get("policy_rules", DEFAULT_POLICY_RULES)
    if not isinstance(policy_rules, dict):
        policy_rules = DEFAULT_POLICY_RULES

    memory_threshold = cfg.get("memory_threshold", DEFAULT_MEMORY_THRESHOLD)
    try:
        memory_threshold = int(memory_threshold)
    except Exception:
        memory_threshold = DEFAULT_MEMORY_THRESHOLD

    merged = dict(DEFAULT_POLICY_RULES)
    merged.update({k: bool(v) for k, v in policy_rules.items()})
    return sensitive_paths, merged, memory_threshold


def build_receipts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    receipts: List[Dict[str, Any]] = []
    prev = "0" * 64
    for e in events:
        trace_id = safe_str(e.get("trace_id", "UNKNOWN"))
        seq = int(e.get("seq", -1))
        et = safe_str(e.get("event_type", "UNKNOWN"))
        ev_hash = sha256_hex(canon_json(e))
        base = {"trace_id": trace_id, "seq": seq, "event_type": et, "event_hash": ev_hash, "prev_hash": prev}
        rh = sha256_hex(canon_json(base))
        receipt = dict(base)
        receipt["event_ts"] = e.get("ts", None)  # deterministic metadata
        receipt["receipt_hash"] = rh
        receipts.append(receipt)
        prev = rh
    return receipts


def write_json(path: str, obj: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def ensure_out(out_dir: str, overwrite: bool) -> None:
    if os.path.exists(out_dir) and os.path.isdir(out_dir) and os.listdir(out_dir) and not overwrite:
        print(f"[!] Output dir not empty: {out_dir}. Use --overwrite or a new --out.", file=sys.stderr)
        sys.exit(2)
    os.makedirs(out_dir, exist_ok=True)

def read_jsonl(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            s = line.strip()
            if not s:
                continue
            try:
                events.append(json.loads(s))
            except json.JSONDecodeError:
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
                    "details": {"raw_line_no": line_no},
                    "data_complete": False,
                })
    return events


def main() -> None:
    ap = argparse.ArgumentParser(description="OpenClaw Flight Recorder EXT (advisory suggestions)")
    ap.add_argument("--input", required=True, help="JSONL flight log")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--overwrite", action="store_true", help="Overwrite output directory")
    ap.add_argument("--policy-sim", action="store_true", help="Enable advisory policy simulation")
    ap.add_argument("--suggest", action="store_true", help="Generate suggestions.json + probe_plan.md (advisory)")
    ap.add_argument("--config", default=None, help="policy.json for thresholds/paths/rules")
    ap.add_argument("--declared-intents", default="", help="Comma-separated event types treated as declared")
    args = ap.parse_args()

    sensitive_paths, policy_rules, memory_threshold = load_config(args.config)
    declared_intents = set([x.strip() for x in args.declared_intents.split(",") if x.strip()]) or None

    ensure_out(args.out, args.overwrite)

    raw = read_jsonl(args.input)
    events = [normalize_event(ev, i) for i, ev in enumerate(raw, start=1)]

    behavior = {
        "network_out": set(),
        "file_write": set(),
        "proc_exec": set(),
        "dep_install": set(),
        "database_op": set(),
        "api_call": set(),
        "memory_access": set(),
    }

    risks_all: List[Dict[str, Any]] = []
    gaps = 0

    for ev in events:
        et = safe_str(ev.get("event_type", ""))

        # behavior summary
        if et == "NET_IO" and safe_str(get_field(ev, "direction", "")).upper() == "OUT":
            behavior["network_out"].add(f"HOST:{safe_str(get_field(ev,'host','unknown'))}:{safe_str(get_field(ev,'port',''))}")
        elif et == "FILE_IO" and safe_str(get_field(ev, "op", "")).lower() in ("write", "delete"):
            behavior["file_write"].add(f"PATH:{safe_str(get_field(ev,'path','unknown'))}")
        elif et == "PROC_EXEC":
            cd = safe_str(get_field(ev, "cmd_digest", ""))
            if not cd:
                cmd = safe_str(get_field(ev, "cmd", ""))
                cd = sha256_hex(cmd) if cmd else "unknown"
            behavior["proc_exec"].add(f"CMD_DIGEST:{cd[:16]}...")
        elif et == "DEP_INSTALL":
            pkg = safe_str(get_field(ev, "package", ""))
            ver = safe_str(get_field(ev, "version", ""))
            depn = safe_str(get_field(ev, "dep_name", ""))
            behavior["dep_install"].add(f"{pkg}@{ver}" if (pkg and ver) else (depn or "unknown_dep"))
        elif et == "DATABASE_OP":
            behavior["database_op"].add("DATABASE_OP")
        elif et == "API_CALL":
            behavior["api_call"].add(f"ENDPOINT:{safe_str(get_field(ev,'endpoint','unknown'))}")
        elif et == "MEMORY_ACCESS":
            behavior["memory_access"].add(f"SIZE:{safe_str(get_field(ev,'size',0))}")
        elif et in ("WS_CONNECT", "GATEWAY_URL_SET", "CRED_SEND"):
            behavior["network_out"].add(f"NET_EXT:{et}")

        # risks
        r = detect_risks(ev, declared_intents, sensitive_paths, memory_threshold)
        risks_all.extend(r)
        if any(x.get("tag") == "EVIDENCE_GAP" for x in r):
            gaps += 1

    status = "OBSERVED"
    if len(risks_all) > 0:
        status = "ATTENTION"
    if gaps > 0:
        status = f"{status}_WITH_GAPS"

    badge: Dict[str, Any] = {
        "status": status,
        "behavior_summary": {k: sorted(list(v)) for k, v in behavior.items()},
        "risk_highlights": risks_all,
        "stats": {"total_events": len(events), "highlight_count": len(risks_all), "evidence_gaps": gaps}
    }

    if args.policy_sim:
        badge["policy_simulation"] = simulate_policy(risks_all, policy_rules)

    receipts = build_receipts(events)

    write_json(os.path.join(args.out, "badge.json"), badge)
    write_jsonl(os.path.join(args.out, "receipts.jsonl"), receipts)

    if args.suggest:
        pack = generate_suggestions(badge, input_hint=args.input)
        write_json(os.path.join(args.out, "suggestions.json"), pack)
        with open(os.path.join(args.out, "probe_plan.md"), "w", encoding="utf-8") as f:
            f.write(build_probe_plan_md(pack))

        # Optional: output a template policy file for convenience
        tpl = {
            "sensitive_paths": sensitive_paths,
            "policy_rules": policy_rules,
            "memory_threshold": memory_threshold
        }
        write_json(os.path.join(args.out, "policy_template.json"), tpl)

    print(json.dumps(badge, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
