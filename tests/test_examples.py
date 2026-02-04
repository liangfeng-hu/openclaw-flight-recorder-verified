import json
import os
import subprocess
import tempfile
import unittest
import sys

PY = sys.executable

def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

class TestExamples(unittest.TestCase):
    def run_cmd(self, cmd):
        subprocess.check_call(cmd)

    def test_clean_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "out_clean")
            self.run_cmd([PY, "src/recorder.py", "--input", "examples/clean_run.jsonl", "--out", out_dir])

            badge = read_json(os.path.join(out_dir, "badge.json"))
            self.assertEqual(badge["status"], "OBSERVED")
            self.assertEqual(badge["stats"]["highlight_count"], 0)
            self.assertEqual(badge["stats"]["evidence_gaps"], 0)

            receipts = read_jsonl(os.path.join(out_dir, "receipts.jsonl"))
            self.assertEqual(len(receipts), 4)
            for i in range(1, len(receipts)):
                self.assertEqual(receipts[i]["prev_hash"], receipts[i-1]["receipt_hash"])

    def test_risky_run_policy_sim(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "out_risky")
            self.run_cmd([PY, "src/recorder.py", "--input", "examples/risky_run.jsonl", "--out", out_dir, "--policy-sim"])

            badge = read_json(os.path.join(out_dir, "badge.json"))
            self.assertTrue(badge["status"].startswith("ATTENTION"))
            self.assertGreaterEqual(badge["stats"]["highlight_count"], 7)
            self.assertIn("policy_simulation", badge)
            self.assertTrue(badge["policy_simulation"]["would_block"])

            tags = [r["tag"] for r in badge["risk_highlights"]]
            must = [
                "UNPINNED_DEP", "UNDECLARED_DEP_INSTALL", "REMOTE_SCRIPT", "UNDECLARED_EXEC",
                "SENSITIVE_PATH", "UNDECLARED_FILE_MUTATION", "UNDECLARED_EGRESS"
            ]
            for m in must:
                self.assertIn(m, tags)

if __name__ == "__main__":
    unittest.main()
