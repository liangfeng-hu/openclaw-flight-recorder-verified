#!/usr/bin/env python3
# Advisory-only remediation suggestions (facts -> template).
# - No auto-fix
# - No execution
# Output conforms to Draft-004 remediation-advice/1

import json
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _uniq(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


def _tag_index(risk_highlights: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    idx: Dict[str, List[Dict[str, Any]]] = {}
    for r in risk_highlights:
        tag = str(r.get("tag", "UNKNOWN"))
        idx.setdefault(tag, []).append(r)
    return idx


def _evidence_list(items: List[Dict[str, Any]]) -> List[str]:
    ev = []
    for r in items:
        e = r.get("evidence")
        if e:
            ev.append(str(e))
    return _uniq(ev)


def _suggest_for_tag(tag: str) -> Optional[Dict[str, Any]]:
    catalog: Dict[str, Dict[str, Any]] = {
        "UNPINNED_DEP": {
            "priority": "HIGH",
            "title": "Pin dependencies and lock supply chain inputs",
            "do": [
                "Pin dependency versions (avoid latest/*).",
                "Use lockfiles/SBOM where possible; record provenance digests.",
                "Treat third-party skills as local executable code: review before enabling."
            ],
            "verify": [
                "Re-run recorder: UNPINNED_DEP should disappear.",
                "Receipt chain should remain continuous; no new evidence gaps."
            ],
        },
        "UNDECLARED_DEP_INSTALL": {
            "priority": "HIGH",
            "title": "Require explicit declaration for installs/updates",
            "do": [
                "Make installs/updates explicit in your runbook (declare intent).",
                "Run installs only in an isolated environment (VM/container) when possible."
            ],
            "verify": ["Re-run recorder: UNDECLARED_DEP_INSTALL should disappear or become declared."],
        },
        "REMOTE_SCRIPT": {
            "priority": "CRITICAL",
            "title": "Stop remote script execution patterns (curl|bash / wget|sh)",
            "do": [
                "Do NOT run one-liners that fetch remote scripts.",
                "Prefer documented packages with checksums and pinned versions.",
                "Isolate and inspect the skill source before execution."
            ],
            "verify": ["Re-run recorder: REMOTE_SCRIPT should disappear."],
        },
        "UNDECLARED_EXEC": {
            "priority": "CRITICAL",
            "title": "Make process execution explicit (or disable it in risky contexts)",
            "do": [
                "Declare and document any exec behavior; keep it off by default in community contexts.",
                "Separate high-risk exec from untrusted sources where possible."
            ],
            "verify": ["Re-run recorder: UNDECLARED_EXEC should disappear."],
        },
        "UNDECLARED_NET_IO": {
            "priority": "HIGH",
            "title": "Control outbound network calls (egress) via allowlists",
            "do": [
                "Declare outbound network usage.",
                "Use allowlists/proxy policies in production environments."
            ],
            "verify": ["Re-run recorder: UNDECLARED_NET_IO should disappear or become declared."],
        },
        "UNDECLARED_FILE_MUTATION": {
            "priority": "HIGH",
            "title": "Restrict file writes to a safe workspace",
            "do": [
                "Restrict writes to a dedicated workspace directory.",
                "Avoid touching system paths; treat them as high-risk."
            ],
            "verify": ["Re-run recorder: UNDECLARED_FILE_MUTATION should disappear."],
        },
        "SENSITIVE_PATH": {
            "priority": "CRITICAL",
            "title": "Prevent sensitive/system path modifications",
            "do": [
                "Block writes to system paths (e.g., /etc, system folders).",
                "Use sandboxing/isolation for untrusted skills."
            ],
            "verify": ["Re-run recorder: SENSITIVE_PATH should disappear."],
        },
        "EVIDENCE_GAP": {
            "priority": "MEDIUM",
            "title": "Fix evidence gaps (missing exporter fields / parsing issues)",
            "do": [
                "Ensure exporter provides required details fields (host/path/op/etc).",
                "Set data_complete=true only when fields are present.",
                "Avoid mixing incompatible schemas in one log."
            ],
            "verify": ["Re-run recorder: EVIDENCE_GAP should be 0."],
        },

        # Draft-003 tags
        "UNTRUSTED_GATEWAY_SOURCE": {
            "priority": "CRITICAL",
            "title": "Treat query-param gateway URLs as untrusted; enforce validation/allowlist",
            "do": [
                "Upgrade to a patched OpenClaw version (do not run known-vulnerable builds).",
                "Ensure gateway URLs are validated and allowlisted; never auto-connect on untrusted input.",
                "After patching, ensure validation_result is PASS/FAIL (not SKIP)."
            ],
            "verify": ["Re-run: UNTRUSTED_GATEWAY_SOURCE should disappear after fix."],
        },
        "AUTO_WS_CONNECT": {
            "priority": "HIGH",
            "title": "Disable automatic WebSocket connections in risky contexts",
            "do": [
                "Require explicit confirmation before WS connect when source is untrusted.",
                "Prefer wss and strict origin checks; keep URL as digest-only in logs."
            ],
            "verify": ["Re-run: AUTO_WS_CONNECT should disappear."],
        },
        "CRED_CROSS_BOUNDARY": {
            "priority": "CRITICAL",
            "title": "Credential boundary crossing detected — rotate/revoke tokens and tighten lifetimes",
            "do": [
                "Assume credentials may be exposed; rotate/revoke credentials used in that session.",
                "Prefer short-lived granular tokens; avoid long-lived classic tokens."
            ],
            "verify": ["Re-run: credential sends should only occur when explicitly intended."],
        },
        "UNDECLARED_CRED_SEND": {
            "priority": "CRITICAL",
            "title": "Undeclared credential send — treat as incident and require explicit declaration",
            "do": [
                "Treat as incident: revoke/rotate relevant credentials.",
                "Require explicit declaration and user confirmation for credential forwarding."
            ],
            "verify": ["Re-run: UNDECLARED_CRED_SEND should disappear."],
        },
    }

    if tag in catalog:
        out = dict(catalog[tag])
        out["tag"] = tag
        return out
    return None


def generate_advice(
    badge: Dict[str, Any],
    input_hint: str = "",
    source_tool_name: str = "openclaw-flight-recorder",
    policy_profile_id: str = "default",
    policy_profile_digest: str = "",
    receipt_chain_tip: str = "",
) -> Dict[str, Any]:
    risk_highlights = badge.get("risk_highlights", []) or []
    idx = _tag_index(risk_highlights)

    suggestions: List[Dict[str, Any]] = []
    for tag, items in idx.items():
        s = _suggest_for_tag(tag)
        if not s:
            continue
        s["count"] = len(items)
        s["evidence"] = _evidence_list(items)
        suggestions.append(s)

    tags_present = sorted(list(idx.keys()))
    st = badge.get("stats") or {}

    doc = {
        "v": "remediation-advice/1",
        "generated_at": _now_iso(),
        "source": {
            "tool_name": source_tool_name,
            "policy_profile_id": policy_profile_id,
        },
        "input": {
            "flight_log_path": input_hint,
            "receipt_chain_tip": receipt_chain_tip
        },
        "summary": {
            "status": badge.get("status"),
            "total_events": st.get("total_events"),
            "highlight_count": st.get("highlight_count"),
            "evidence_gaps": st.get("evidence_gaps"),
            "tags": tags_present,
        },
        "safety": {
            "auto_fix": False,
            "enforcement": False,
            "secrets_logged": False
        },
        "suggestions": suggestions
    }

    if policy_profile_digest:
        doc["source"]["policy_profile_digest"] = policy_profile_digest

    # Optional: summarize policy-sim if present
    ps = badge.get("policy_simulation")
    if isinstance(ps, dict):
        doc["policy_simulation_summary"] = {
            "enabled": bool(ps.get("enabled", True)),
            "would_block": bool(ps.get("would_block", False)),
            "violation_count": int(ps.get("violation_count", 0))
        }

    return doc


def build_probe_plan_md(advice: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Probe Plan (Advisory)")
    lines.append("")
    lines.append(f"- generated_at: {advice.get('generated_at')}")
    lines.append(f"- status: {advice.get('summary', {}).get('status')}")
    lines.append("")
    lines.append("## Goal")
    lines.append("Reduce high-attention tags and eliminate evidence gaps using manual fixes.")
    lines.append("")
    lines.append("## Steps")
    lines.append("1) Apply fixes manually (do NOT run untrusted one-liners).")
    lines.append("2) Re-run recorder on the same workflow/environment.")
    lines.append("3) Compare `badge.json` before/after (highlight_count should drop; evidence_gaps should be 0).")
    lines.append("4) Keep receipts for traceability (share only digests publicly).")
    lines.append("")
    lines.append("## Suggestions")
    lines.append("")
    for s in advice.get("suggestions", []):
        lines.append(f"### [{s.get('priority')}] {s.get('title')} (tag={s.get('tag')}, count={s.get('count')})")
        for d in s.get("do", []):
            lines.append(f"- DO: {d}")
        for v in s.get("verify", []):
            lines.append(f"- VERIFY: {v}")
        ev = s.get("evidence") or []
        if ev:
            lines.append("- Evidence digests: " + ", ".join([x[:16] + "..." for x in ev]))
        lines.append("")
    return "\n".join(lines)
