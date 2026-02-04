import json
import os
import subprocess
import tempfile
import unittest
import sys

PY = sys.executable

def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

class TestRecorderExtDeterminism(unittest.TestCase):
    def run_ext(self, input_path, out_dir, policy_sim=False):
        cmd = [PY, "src/recorder_ext.py", "--input", input_path, "--out", out_dir, "--overwrite"]
        if policy_sim:
            cmd.append("--policy-sim")
        subprocess.check_call(cmd)

    def test_clean_and_risky_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_clean = os.path.join(tmp, "out_clean")
            out_risky = os.path.join(tmp, "out_risky")

            self.run_ext("examples/clean_run.jsonl", out_clean, policy_sim=False)
            self.run_ext("examples/risky_run.jsonl", out_risky, policy_sim=True)

            badge_clean = read_json(os.path.join(out_clean, "badge.json"))
            badge_risky = read_json(os.path.join(out_risky, "badge.json"))

            self.assertTrue(badge_clean["status"].startswith("OBSERVED"))
            self.assertEqual(badge_clean["stats"]["highlight_count"], 0)

            self.assertTrue(badge_risky["status"].startswith("ATTENTION"))
            self.assertGreater(badge_risky["stats"]["highlight_count"], 0)
            self.assertIn("policy_simulation", badge_risky)
            self.assertTrue(badge_risky["policy_simulation"]["enabled"] in [True, 1])

    def test_receipts_are_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            out1 = os.path.join(tmp, "out1")
            out2 = os.path.join(tmp, "out2")

            self.run_ext("examples/risky_run.jsonl", out1, policy_sim=False)
            self.run_ext("examples/risky_run.jsonl", out2, policy_sim=False)

            r1 = read_jsonl(os.path.join(out1, "receipts.jsonl"))
            r2 = read_jsonl(os.path.join(out2, "receipts.jsonl"))

            # deterministic receipts: exactly equal
            self.assertEqual(r1, r2)

if __name__ == "__main__":
    unittest.main()
