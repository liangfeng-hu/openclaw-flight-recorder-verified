import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def run_recorder(args, cwd=None):
    cmd = [sys.executable, "src/recorder.py"] + args
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p


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


class TestConformance(unittest.TestCase):
    def test_clean_run(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = os.path.join(td, "out_clean")
            p = run_recorder(["--input", "examples/clean_run.jsonl", "--out", out_dir])
            self.assertEqual(p.returncode, 0, p.stderr)

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
            p = run_recorder(["--input", "examples/risky_run.jsonl", "--out", out_dir, "--policy-sim"])
            self.assertEqual(p.returncode, 0, p.stderr)

            badge = load_json(os.path.join(out_dir, "badge.json"))
            receipts = load_jsonl(os.path.join(out_dir, "receipts.jsonl"))

            self.assertIn(badge.get("status"), ["ATTENTION", "ATTENTION_WITH_GAPS"])
            self.assertEqual(badge.get("stats", {}).get("highlight_count"), 7)
            self.assertEqual(badge.get("stats", {}).get("evidence_gaps"), 0)

            ps = badge.get("policy_simulation")
            self.assertIsNotNone(ps)
            self.assertTrue(ps.get("enabled"))
            self.assertTrue(ps.get("would_block"))
            self.assertEqual(ps.get("violation_count"), 7)

            assert_receipt_chain_ok(self, receipts)

            # verify mode should pass
            vr = run_recorder(["--verify-receipts", os.path.join(out_dir, "receipts.jsonl")])
            self.assertEqual(vr.returncode, 0, vr.stdout + vr.stderr)

    def test_extensions_example(self):
        # ext_run.jsonl should trigger 3 extension risks
        with tempfile.TemporaryDirectory() as td:
            out_dir = os.path.join(td, "out_ext")
            p = run_recorder(["--input", "examples/ext_run.jsonl", "--out", out_dir, "--policy-sim"])
            self.assertEqual(p.returncode, 0, p.stderr)

            badge = load_json(os.path.join(out_dir, "badge.json"))
            tags = [x.get("tag") for x in badge.get("risk_highlights", [])]

            self.assertIn("SQL_RISK", tags)
            self.assertIn("API_CREDENTIAL_EXPOSURE", tags)
            self.assertIn("HIGH_MEMORY_ACCESS", tags)

            ps = badge.get("policy_simulation")
            self.assertTrue(ps.get("would_block"))
            self.assertEqual(ps.get("violation_count"), 3)


if __name__ == "__main__":
    unittest.main()
