# VERIFY.md — 可复现验收与一致性检查（SSOT）

本文件定义本项目的可复现验收口径：JSONL → badge.json（事实摘要）+ receipts.jsonl（可验证收据链）。
（注：--policy-sim 为 advisory 建议性信号，不是阻断防火墙。）

---

## 0. 环境要求
- Python 3.10+
- 零依赖（标准库即可）

---

## 1. 本地快速验收

### 1.1 Clean（必须干净）
python src/recorder.py --input examples/clean_run.jsonl --out out_clean

必须满足：
- status == OBSERVED
- highlight_count == 0
- evidence_gaps == 0
- risk_highlights 为空

### 1.2 Risky（必须出现核心风险信号）
python src/recorder.py --input examples/risky_run.jsonl --out out_risky --policy-sim

必须满足：
- status 为 ATTENTION（本示例要求 evidence_gaps == 0）
- would_block == true
- highlight_count >= 7
- violation_count >= 7
- 必须包含以下标签：
  UNPINNED_DEP, UNDECLARED_DEP_INSTALL, REMOTE_SCRIPT, UNDECLARED_EXEC,
  SENSITIVE_PATH, UNDECLARED_FILE_MUTATION, UNDECLARED_EGRESS

### 1.3 Extensions（扩展类型必须可工作）
python src/recorder.py --input examples/ext_run.jsonl --out out_ext --policy-sim

必须满足：
- would_block == true
- violation_count >= 3
- 必须包含以下标签：
  SQL_RISK, API_CREDENTIAL_EXPOSURE, HIGH_MEMORY_ACCESS

---

## 2. 一致性测试（CI 同口径）
python -m unittest discover -s tests -p "test_*.py" -v

---

## 3. receipts.jsonl 收据链要求
必须满足：
- 第一条 prev_hash 是 64 个 0
- 从第二条开始：每条 prev_hash 等于上一条 receipt_hash
- event_hash / prev_hash / receipt_hash 都是 64 位十六进制字符串

### 3.2 一键验链（若 recorder.py 支持）
python src/recorder.py --verify-receipts out_risky/receipts.jsonl

---

## 4. 常见失败原因
- .jsonl 文件每一行必须是“合法的单行 JSON”，不能出现换行断裂
- .jsonl 文件里不要出现任何额外文字（例如：```jsonl、文件名称：、注释）
