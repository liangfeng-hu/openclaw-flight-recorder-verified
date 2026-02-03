import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HEX64 = re.compile(r"^[0-9a-f]{64}$")

def run_recorder(input_path: str, out_dir: str, policy_sim: bool = False):
    cmd = [sys.executable, "src/recorder.py", "--input", input_path, "--out", out_dir]
    if policy_sim:
        cmd.append("--policy-sim")
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"recorder failed:\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")

def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_jsonl(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows

def assert_receipt_chain_ok(tc: unittest.TestCase, receipts):
    tc.assertGreater(len(receipts), 0, "receipts.jsonl should not be empty")

    for r in receipts:
        for k in ["trace_id", "seq", "event_type", "event_hash", "prev_hash", "receipt_hash"]:
            tc.assertIn(k, r, f"missing key {k}")
        tc.assertRegex(r["event_hash"], HEX64, "event_hash must be 64-hex")
        tc.assertRegex(r["prev_hash"], HEX64, "prev_hash must be 64-hex")
        tc.assertRegex(r["receipt_hash"], HEX64, "receipt_hash must be 64-hex")

    seqs = [r["seq"] for r in receipts]
    tc.assertEqual(seqs, sorted(seqs), "seq should be sorted ascending")

    for i in range(1, len(receipts)):
        tc.assertEqual(
            receipts[i]["prev_hash"],
            receipts[i - 1]["receipt_hash"],
            f"chain broken at seq={receipts[i]['seq']}"
        )

class TestExamples(unittest.TestCase):
    def test_clean_run(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = os.path.join(td, "out_clean")
            run_recorder("examples/clean_run.jsonl", out_dir, policy_sim=False)

            badge = load_json(os.path.join(out_dir, "badge.json"))
            receipts = load_jsonl(os.path.join(out_dir, "receipts.jsonl"))

            self.assertEqual(badge.get("status"), "OBSERVED")
            self.assertEqual(badge.get("stats", {}).get("highlight_count"), 0)
            self.assertEqual(badge.get("stats", {}).get("evidence_gaps"), 0)
            self.assertEqual(badge.get("risk_highlights"), [])

            assert_receipt_chain_ok(self, receipts)

    def test_risky_run_policy_sim(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = os.path.join(td, "out_sim")
            run_recorder("examples/risky_run.jsonl", out_dir, policy_sim=True)

            badge = load_json(os.path.join(out_dir, "badge.json"))
            receipts = load_jsonl(os.path.join(out_dir, "receipts.jsonl"))

            self.assertEqual(badge.get("status"), "ATTENTION")
            self.assertEqual(badge.get("stats", {}).get("highlight_count"), 7)
            self.assertEqual(badge.get("stats", {}).get("evidence_gaps"), 0)

            ps = badge.get("policy_simulation")
            self.assertIsNotNone(ps, "policy_simulation should exist when --policy-sim is used")
            self.assertTrue(ps.get("enabled"))
            self.assertTrue(ps.get("would_block"))
            self.assertEqual(ps.get("violation_count"), 7)

            assert_receipt_chain_ok(self, receipts)

if __name__ == "__main__":
    unittest.main()
