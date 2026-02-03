# src/recorder.py
# ... 你原来的所有 import、常量、函数保持不变 ...

# 新增：兼容 RFC-001 嵌套 details + per-event declared
def get_detail(event: Dict[str, Any], key: str, default=None):
    """优先取顶层，再取 details 里"""
    return event.get(key) or event.get("details", {}).get(key, default)

def detect_risks(...):  # 你的原函数
    risks = []
    event_type = event["event_type"]
    is_declared = event.get("declared", True) if not declared_intents else (event_type in declared_intents)

    # 统一取值
    dep_name = get_detail(event, "dep_name") or f"{get_detail(event, 'package', '')}@{get_detail(event, 'version', '')}"
    cmd = get_detail(event, "cmd")
    path = get_detail(event, "path")
    host = get_detail(event, "host")
    query = get_detail(event, "query", "").lower()
    endpoint = get_detail(event, "endpoint")
    headers = get_detail(event, "headers", {})
    size = get_detail(event, "size", 0)
    op = get_detail(event, "op", get_detail(event, "mode", ""))

    # DEP_INSTALL
    if event_type == "DEP_INSTALL":
        if "@latest" in dep_name or get_detail(event, "version") == "latest":
            risks.append({"tag": "UNPINNED_DEP", "seq": event["seq"], "evidence": dep_name})
        if not is_declared:
            risks.append({"tag": "UNDECLARED_DEP_INSTALL", "seq": event["seq"], "evidence": dep_name})

    # PROC_EXEC
    elif event_type == "PROC_EXEC":
        if cmd and (cmd.startswith("curl") or cmd.startswith("wget")):
            risks.append({"tag": "REMOTE_SCRIPT", "seq": event["seq"], "evidence": cmd})
        if not is_declared:
            risks.append({"tag": "UNDECLARED_EXEC", "seq": event["seq"], "evidence": cmd})

    # FILE_IO
    elif event_type == "FILE_IO":
        if any(path.startswith(s) for s in sensitive_paths):
            risks.append({"tag": "SENSITIVE_PATH", "seq": event["seq"], "evidence": path})
        if (op == "w" or op == "write") and not is_declared:
            risks.append({"tag": "UNDECLARED_FILE_MUTATION", "seq": event["seq"], "evidence": path})

    # NET_IO
    elif event_type == "NET_IO":
        if not is_declared:
            risks.append({"tag": "UNDECLARED_NET_IO", "seq": event["seq"], "evidence": host})

    # 其他新类型保持你原来的逻辑（它们本来就从 details 取）
    # DATABASE_OP、API_CALL、MEMORY_ACCESS ... 直接用 get_detail 就行

    # ... 其余你的代码不变 ...

# 在 behavior_summary 收集部分也统一用 get_detail
# 例如：
elif et == "NET_IO":
    behavior_summary[key].append(f"HOST:{get_detail(event, 'host')}:{get_detail(event, 'port')}")
# 类似地改其他几个

# main() 中 declared_intents 保持你原来的代码（支持 --declared-intents 参数）
