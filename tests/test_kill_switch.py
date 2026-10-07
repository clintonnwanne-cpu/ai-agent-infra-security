"""Offline orchestration tests: fake AWS/kubectl, no credentials or cloud calls."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ROLE = "ai-agent-security-lab-ai-agent-role"
TRUST = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/example"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {"example:sub": "system:serviceaccount:ai-agent:ai-agent-sa",
                                  "example:aud": "sts.amazonaws.com"}}}]}
FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["FAKE_STATE"])
args = sys.argv[1:]
name = pathlib.Path(sys.argv[0]).name
with (state / "calls").open("a") as f:
    f.write(json.dumps([name, *args]) + "\n")
operation = " ".join(args[:2]) if name == "aws" else next(
    (x for x in ("rolebinding", "serviceaccount", "pods") if x in args), "")
if operation == os.environ.get("FAIL_OP"):
    print("AccessDenied: injected failure", file=sys.stderr)
    sys.exit(1)
if name != "aws":
    sys.exit(0)
if operation == "iam get-role":
    trust = json.loads((state / "trust").read_text())
    if os.environ.get("STALE_TRUST") and (state / "policy").exists():
        trust["Statement"] = [x for x in trust["Statement"] if x.get("Sid") != "AIAgentEmergencyDenyAssumption"]
    print(json.dumps({"Role": {"Arn": "arn:aws:iam::123456789012:role/" + os.environ["AGENT_ROLE_NAME"],
                              "AssumeRolePolicyDocument": trust}}))
elif operation == "sts get-caller-identity":
    arn = "arn:aws:iam::123456789012:user/operator"
    if os.environ.get("SELF_OPERATOR"):
        arn = "arn:aws:sts::123456789012:assumed-role/" + os.environ["AGENT_ROLE_NAME"] + "/session"
    print(json.dumps({"Account": os.environ.get("CALLER_ACCOUNT", "123456789012"), "Arn": arn}))
elif operation == "iam put-role-policy":
    (state / "policy").write_text(args[args.index("--policy-document") + 1])
elif operation == "iam update-assume-role-policy":
    (state / "trust").write_text(args[args.index("--policy-document") + 1])
elif operation == "iam get-role-policy":
    if not (state / "policy").exists():
        print("NoSuchEntity", file=sys.stderr); sys.exit(1)
    policy = json.loads((state / "policy").read_text())
    if os.environ.get("STALE_POLICY"):
        policy["Statement"][0]["Effect"] = "Allow"
    print(json.dumps({"PolicyDocument": policy}))
else:
    print("Unexpected operation", file=sys.stderr); sys.exit(99)
'''

class KillSwitchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        (self.state / "trust").write_text(json.dumps(TRUST))
        for name in ("aws", "kubectl"):
            p = self.state / name
            p.write_text(FAKE)
            p.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.state) + os.pathsep + os.environ["PATH"],
                    "FAKE_STATE": str(self.state), "AWS_ACCOUNT_ID": "123456789012",
                    "K8S_CONTEXT": "test-context", "AGENT_ROLE_NAME": ROLE}
        for key in ("FAIL_OP", "STALE_POLICY", "STALE_TRUST", "SELF_OPERATOR", "CALLER_ACCOUNT"):
            self.env.pop(key, None)

    def run_switch(self, *args, **env):
        return subprocess.run(["bash", str(ROOT / "scripts/kill_switch.sh"), *args],
                              env={**self.env, **env}, text=True, capture_output=True)

    def calls(self):
        p = self.state / "calls"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def test_quarantine_order_and_guardrail_preservation(self):
        result = self.run_switch()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        mutations = [c for c in calls if c[1:3] in [
            ["iam", "put-role-policy"], ["iam", "update-assume-role-policy"]]]
        self.assertEqual([c[2] for c in mutations], ["put-role-policy", "update-assume-role-policy"])
        self.assertLess(calls.index(mutations[-1]), next(i for i, c in enumerate(calls) if c[0] == "kubectl"))
        self.assertFalse(any("detach-role-policy" in c or "delete-role-policy" in c for c in calls))
        policy = json.loads((self.state / "policy").read_text())["Statement"][0]
        self.assertEqual((policy["Effect"], policy["Action"], policy["Resource"]), ("Deny", "*", "*"))
        self.assertNotIn("Condition", policy)  # includes old AND race-window sessions
        trust = json.loads((self.state / "trust").read_text())["Statement"]
        self.assertEqual(trust[0], TRUST["Statement"][0])
        self.assertEqual(trust[-1]["Principal"], "*")
        self.assertEqual(trust[-1]["Effect"], "Deny")
        self.assertEqual(set(trust[-1]["Action"]), {
            "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"})
        pods = next(c for c in calls if c[0] == "kubectl" and "pods" in c)
        self.assertIn("spec.serviceAccountName=ai-agent-sa", pods)
        self.assertIn("test-context", pods)
        self.assertIn("NOT verified", result.stdout)

    def test_rerun_does_not_duplicate_trust_deny(self):
        for _ in range(2):
            self.assertEqual(self.run_switch("--iam-only").returncode, 0)
        trust = json.loads((self.state / "trust").read_text())["Statement"]
        self.assertEqual(len(trust), 2)

    def test_single_statement_trust_supported(self):
        (self.state / "trust").write_text(json.dumps({**TRUST, "Statement": TRUST["Statement"][0]}))
        self.assertEqual(self.run_switch("--iam-only").returncode, 0)

    def test_dry_run_is_fully_offline(self):
        result = self.run_switch("--dry-run", AWS_ACCOUNT_ID="", K8S_CONTEXT="")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_invalid_flags_make_no_calls(self):
        for flags in [("--wat",), ("--iam-only", "--k8s-only")]:
            result = self.run_switch(*flags)
            self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_only_modes_and_reporting(self):
        result = self.run_switch("--k8s-only", AWS_ACCOUNT_ID="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(c[0] == "kubectl" for c in self.calls()))
        self.assertIn("AWS IAM: SKIPPED", result.stdout)
        (self.state / "calls").unlink()
        result = self.run_switch("--iam-only", K8S_CONTEXT="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(c[0] == "aws" for c in self.calls()))
        self.assertIn("Kubernetes: SKIPPED", result.stdout)

    def test_failures_are_nonzero_and_other_controls_continue(self):
        for operation in ("iam put-role-policy", "iam update-assume-role-policy",
                          "rolebinding", "serviceaccount", "pods"):
            with self.subTest(operation=operation):
                result = self.run_switch(FAIL_OP=operation)
                self.assertEqual(result.returncode, 1)
                self.assertIn("AccessDenied", result.stderr)
                self.assertIn("incomplete", result.stderr)
                self.assertTrue(any("pods" in c for c in self.calls()))
                self.assertNotIn("Requested controls completed", result.stdout)

    def test_readback_mismatch_is_failure(self):
        for env in ({"STALE_POLICY": "1"}, {"STALE_TRUST": "1"}):
            self.assertEqual(self.run_switch("--iam-only", **env).returncode, 1)

    def test_account_and_operator_validation_prevents_iam_mutation(self):
        for env in ({"AWS_ACCOUNT_ID": ""}, {"AWS_ACCOUNT_ID": "999999999999"},
                    {"CALLER_ACCOUNT": "999999999999"}, {"SELF_OPERATOR": "1"}):
            with self.subTest(env=env):
                result = self.run_switch(**env)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(any(c[1:3] == ["iam", "put-role-policy"] for c in self.calls()))
                self.assertTrue(any(c[0] == "kubectl" for c in self.calls()))
                p = self.state / "calls"
                if p.exists():
                    p.unlink()

    def test_missing_k8s_context_does_not_skip_iam(self):
        result = self.run_switch(K8S_CONTEXT="")
        self.assertEqual(result.returncode, 1)
        self.assertTrue((self.state / "policy").exists())
        self.assertTrue(all(c[0] == "aws" for c in self.calls()))

if __name__ == "__main__":
    unittest.main()
