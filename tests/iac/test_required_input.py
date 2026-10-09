"""Run only the root variable declarations in a provider-free test directory.

Documentation addresses are synthetic test inputs, never deployment defaults.
No cloud provider is loaded, and no apply is executed.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]


class RequiredInputTests(unittest.TestCase):
    def test_missing_and_invalid_cidrs_fail_closed(self):
        binary = os.environ.get("TEST_TERRAFORM_BINARY", "terraform")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CHECKPOINT_DISABLE": "1",
               "TF_IN_AUTOMATION": "true", "AWS_EC2_METADATA_DISABLED": "true"}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "variables.tf").write_text((REPO / "terraform/variables.tf").read_text())
            cases = [("missing", None, False), ("empty", [], False), ("null", "null", False),
                     ("null element", [None], False), ("world", ["0.0.0.0/0"], False),
                     ("noncanonical world", ["192.0.2.1/0"], False),
                     ("ipv6", ["2001:db8::/32"], False), ("malformed", ["bad"], False),
                     ("invalid prefix", ["192.0.2.1/33"], False),
                     ("mixed", ["192.0.2.1/32", "0.0.0.0/0"], False),
                     ("mock operator", ["192.0.2.1/32"], True),
                     ("mock ranges", ["192.0.2.1/32", "198.51.100.0/24"], True)]
            for name, value, allowed in cases:
                with self.subTest(name=name):
                    args = [binary, "plan", "-input=false", "-no-color", "-lock=false"]
                    if value is not None:
                        args += ["-var=operator_public_access_cidrs=" + (value if value == "null" else json.dumps(value))]
                    result = subprocess.run(args, cwd=directory, env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, allowed, result.stdout + result.stderr)
                    if not allowed:
                        self.assertIn("operator_public_access_cidrs", result.stderr)
                        self.assertNotIn("Failed to query", result.stderr)


if __name__ == "__main__": unittest.main()
