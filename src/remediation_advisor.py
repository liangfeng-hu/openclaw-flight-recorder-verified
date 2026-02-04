#!/usr/bin/env python3
# Advisory-only remediation suggestions (facts -> template).
# - No auto-fix
# - No command execution
# - Produces: suggestions.json + probe_plan.md (+ optional templates)

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


# ----------------------------
# Suggestion catalog (advisory)
# ----------------------------

def _suggest_for_tag(tag: str) -> Optional[Dict[str, Any]]:
    """
    Returns a suggestion template for a single tag.
    Pure advisory; avoids exploit steps.
    """
    # IMPORTANT: keep advice short, concrete, and verifiable.
    catalog: Dict[str, Dict[str, Any]] = {
        # Supply chain / skills
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
                "Make installs/updates explicit in your skill/runbook (declare intent).",
                "Run installs only in an isolated environment (VM/container) when possible."
            ],
            "verify": [
                "Re-run recorder: UNDECLARED_DEP_INSTALL should disappear or become declared.",
            ],
        },
        "REMOTE_SCRIPT": {
            "priority": "CRITICAL",
            "title": "Stop remote script execution patterns (curl|bash / wget|sh)",
            "do": [
                "Do NOT copy-paste one-liners that fetch remote scripts.",
                "If a skill requires setup, prefer documented packages with checksums and pinned versions.",
                "Isolate and inspect the skill source before execution."
            ],
            "verify": [
                "Re-run recorder: REMOTE_SCRIPT should disappear.",
                "Ensure no PROC_EXEC occurs unless explicitly declared and reviewed."
            ],
        },

        # Side effects
        "UNDECLARED_EXEC": {
            "priority": "CRITICAL",
            "title": "Make process execution explicit (or disable it in risky contexts)",
            "do": [
                "Declare and document any exec behavior; keep it off by default in community contexts.",
                "Consider separating 'gateway exec host' from device-local nodes if applicable."
            ],
            "verify": [
                "Re-run recorder: UNDECLARED_EXEC should disappear (declared=true or no exec)."
            ],
        },
        "UNDECLARED_NET_IO": {
            "priority": "HIGH",
            "title": "Control outbound network calls (egress) via allowlists",
            "do": [
                "Declare outbound network usage for the skill/agent.",
                "Use an allowlist/proxy policy in production environments."
            ],
            "verify": [
                "Re-run recorder: UNDECLARED_NET_IO should disappear or be declared."
            ],
        },
        "UNDECLARED_FILE_MUTATION": {
            "priority": "HIGH",
            "title": "Restrict file writes to a safe workspace",
            "do": [
                "Restrict writes to a dedicated workspace directory.",
                "Avoid touching system paths; treat them as high-risk.",
            ],
            "verify": [
                "Re-run recorder: UNDECLARED_FILE_MUTATION should disappear."
            ],
        },
        "SENSITIVE_PATH": {
            "priority": "CRITICAL",
            "title": "Prevent sensitive/system path modifications",
            "do": [
                "Block writes to system paths (e.g., /etc, system folders).",
                "Use sandboxing/isolation for untrusted skills."
            ],
            "verify": [
                "Re-run recorder: SENSITIVE_PATH should disappear."
            ],
        },

        # Data quality
        "EVIDENCE_GAP": {
            "priority": "MEDIUM",
            "title": "Fix evidence gaps (exporter missing fields / parsing issues)",
            "do": [
                "Ensure exporter provides required details fields (host/path/op/etc).",
                "Set data_complete=true only when fields are present.",
                "Avoid mixing incompatible schemas in a single log file."
            ],
            "verify": [
                "Re-run recorder: EVIDENCE_GAP should be 0."
            ],
        },

        # Draft-003 (WS / Gateway / Token boundary) tags (if you add them)
        "UNTRUSTED_GATEWAY_SOURCE": {
            "priority": "CRITICAL",
            "title": "Treat query-param gateway URLs as untrusted; enforce validation/allowlist",
            "do": [
                "Upgrade OpenClaw to a patched version (CVE-2026-25253 is < 2026.1.29).",
                "Ensure gateway URLs are validated and allowlisted; never auto-connect on untrusted input.",
                "After patching, ensure validation_result is PASS/FAIL (not SKIP)."
            ],
            "verify": [
                "Re-run ws_token_demo: UNTRUSTED_GATEWAY_SOURCE should not appear after fix.",
                "No auto-connect should occur without explicit confirmation/validation."
            ],
        },
        "AUTO_WS_CONNECT": {
            "priority": "HIGH",
            "title": "Disable automatic WebSocket connections in risky contexts",
            "do": [
                "Require explicit confirmation before WS connect when source is untrusted.",
                "Prefer wss and strict origin checks; keep URL as digest-only in logs."
            ],
            "verify": [
                "Re-run: AUTO_WS_CONNECT should disappear (auto_connect=false or no connect)."
            ],
        },
        "CRED_CROSS_BOUNDARY": {
            "priority": "CRITICAL",
            "title": "Credential boundary crossing detected — rotate/revoke tokens and tighten lifetimes",
            "do": [
                "Assume tokens may be exposed; rotate/revoke credentials used in that session.",
                "Use short-lived granular tokens where possible; avoid long-lived classic tokens."
            ],
            "verify": [
                "Re-run after rotation: CRED_CROSS_BOUNDARY should only appear when explicitly intended.",
                "Confirm no undeclared credential sends occur."
            ],
        },
        "UNDECLARED_CRED_SEND": {
            "priority": "CRITICAL",
            "title": "Undeclared credential send — treat as incident and require explicit declaration",
            "do": [
                "Treat this as an incident: revoke/rotate relevant credentials.",
                "Require explicit declaration and user confirmation for credential forwarding."
            ],
            "verify": [
                "Re-run: UNDECLARED_CRED_SEND should disappear."
            ],
        },
    }

    if tag in catalog:
        out = dict(catalog[tag])
        out["tag"] = tag
        return out
    return None


def generate_suggestions(
    badge: Dict[str, Any],
    input_hint: str = "",
) -> Dict[str, Any]:
    risk_highlights = badge.get("risk_highlights", []) or []
    idx = _tag_index(risk_highlights)

    suggestions: List[Dict[str, Any]] = []
    for tag, items in idx.items():
        s = _suggest_for_tag(tag)
        if not s:
            continue
        s["evidence"] = _evidence_list(items)
        s["count"] = len(items)
        suggestions.append(s)

    # Add a compact “meta suggestion” when supply-chain risk is present
    tags_present = set(idx.keys())
    if any(t in tags_present for t in ["UNPINNED_DEP", "UNDECLARED_DEP_INSTALL", "REMOTE_SCRIPT"]):
        suggestions.append({
            "tag": "SUPPLY_CHAIN_META",
            "priority": "HIGH",
            "title": "Supply-chain hygiene checklist (advisory)",
            "count": 1,
            "evidence": [],
            "do": [
                "Avoid installing skills from untrusted registries without review.",
                "Prefer verified sources and pinned versions; keep installation isolated.",
                "Run the Flight Recorder before enabling skills, and share only digests."
            ],
            "verify": [
                "After cleanup, re-run recorder; high-risk tags should reduce."
            ],
        })

    return {
        "generated_at": _now_iso(),
        "input_hint": input_hint,
        "summary": {
            "status": badge.get("status"),
            "total_events": (badge.get("stats") or {}).get("total_events"),
            "highlight_count": (badge.get("stats") or {}).get("highlight_count"),
            "evidence_gaps": (badge.get("stats") or {}).get("evidence_gaps"),
            "tags": sorted(list(tags_present)),
        },
        "suggestions": suggestions
    }


def build_probe_plan_md(suggestions_pack: Dict[str, Any]) -> str:
    """
    Produces a simple, human-friendly plan: fix direction + how to verify.
    """
    lines: List[str] = []
    lines.append("# Probe Plan (Advisory)")
    lines.append("")
    lines.append(f"- generated_at: {suggestions_pack.get('generated_at')}")
    lines.append(f"- input_hint: {suggestions_pack.get('input_hint')}")
    lines.append("")
    lines.append("## Goal")
    lines.append("Turn risky behavior into verifiable evidence: reduce high-attention tags and eliminate evidence gaps.")
    lines.append("")
    lines.append("## Steps")
    lines.append("1) Apply fixes manually (do NOT run untrusted one-liners).")
    lines.append("2) Re-run the recorder on the same workflow / same skill / same environment.")
    lines.append("3) Compare `badge.json` before/after (highlight_count should drop; gaps should be 0).")
    lines.append("4) Keep receipts for traceability (share only digests publicly).")
    lines.append("")
    lines.append("## Suggested Fix Directions")
    lines.append("")
    for s in suggestions_pack.get("suggestions", []):
        lines.append(f"### [{s.get('priority')}] {s.get('title')}  (tag={s.get('tag')}, count={s.get('count')})")
        for d in s.get("do", []):
            lines.append(f"- DO: {d}")
        for v in s.get("verify", []):
            lines.append(f"- VERIFY: {v}")
        if s.get("evidence"):
            lines.append(f"- Evidence digests: {', '.join([e[:16]+'...' for e in s['evidence']])}")
        lines.append("")
    return "\n".join(lines)
