import json
import os
import tempfile
import unittest
import sys
import subprocess

PY = sys.executable

def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

class TestSuggestionsExt(unittest.TestCase):
    def test_suggestions_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir = os.path.join(tmp, "out")
            cmd = [
                PY, "src/recorder_ext.py",
                "--input", "examples/risky_run.jsonl",
                "--out", outdir,
                "--overwrite",
                "--suggest",
                "--policy-sim"
            ]
            subprocess.check_call(cmd)

            self.assertTrue(os.path.exists(os.path.join(outdir, "suggestions.json")))
            self.assertTrue(os.path.exists(os.path.join(outdir, "probe_plan.md")))
            self.assertTrue(os.path.exists(os.path.join(outdir, "policy_template.json")))

            pack = read_json(os.path.join(outdir, "suggestions.json"))
            self.assertIn("suggestions", pack)
            self.assertTrue(isinstance(pack["suggestions"], list))
            self.assertIn("summary", pack)

if __name__ == "__main__":
    unittest.main()
