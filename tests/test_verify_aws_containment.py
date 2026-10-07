"""Offline tests for evidence classification; no cloud calls."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess
import base64
from datetime import timedelta
import io
import json
import tempfile
from contextlib import redirect_stdout

spec = importlib.util.spec_from_file_location(
    "verify", Path(__file__).resolve().parents[1] / "scripts/verify_aws_containment.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerificationTests(unittest.TestCase):
    def test_only_authorization_denials_count(self):
        self.assertTrue(verify.evaluate("UnauthorizedOperation", "AccessDenied"))
        self.assertTrue(verify.evaluate("AccessDenied", "AccessDenied"))
        for error in ("success", "ExpiredToken", "InvalidIdentityToken",
                      "IDPRejectedClaim", "Throttling", "unclassified-error"):
            self.assertFalse(verify.evaluate(error, "AccessDenied"))
            self.assertFalse(verify.evaluate("UnauthorizedOperation", error))

    def test_freezes_credentials_without_profile_or_web_identity_fallback(self):
        with patch.dict(verify.os.environ, {"AWS_PROFILE": "admin",
                         "AWS_ROLE_ARN": "other", "AWS_WEB_IDENTITY_TOKEN_FILE": "/token",
                         "AWS_ENDPOINT_URL": "http://fake", "PATH": "/bin"}, clear=True):
            env = verify.credential_env({"AccessKeyId": "captured",
                                        "SecretAccessKey": "secret", "SessionToken": "session"})
        self.assertNotIn("AWS_PROFILE", env)
        self.assertNotIn("AWS_ROLE_ARN", env)
        self.assertNotIn("AWS_WEB_IDENTITY_TOKEN_FILE", env)
        self.assertNotIn("AWS_ENDPOINT_URL", env)
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "captured")
        self.assertEqual(env["AWS_EC2_METADATA_DISABLED"], "true")

    def test_cli_error_parsing_rejects_network_failures(self):
        for stderr, expected in [
            ("An error occurred (AccessDenied) when calling AssumeRoleWithWebIdentity", "AccessDenied"),
            ("Could not connect to endpoint", "unclassified-error")]:
            with patch.object(verify.subprocess, "run", return_value=
                              subprocess.CompletedProcess([], 1, "", stderr)):
                self.assertEqual(verify.call(["sts", "anything"], {})[0], expected)

    def test_fresh_probe_is_unsigned_and_old_probe_uses_ec2(self):
        with patch.object(verify, "call", return_value=("success", {})) as call:
            verify.probes("role", Path("/tmp/token"), "us-east-2", {"AWS_ACCESS_KEY_ID": "old"})
        self.assertEqual(call.call_args_list[0].args[0][:2], ["ec2", "describe-instances"])
        self.assertIn("--no-sign-request", call.call_args_list[1].args[0])
        self.assertIn("file:///tmp/token", call.call_args_list[1].args[0])


    def invoke_main(self, phase, directory, statuses=("success", "success"), evidence=True,
                    expiration=None, identity=None, token_exp=None):
        directory = Path(directory)
        exp = expiration or (verify.utc() + timedelta(hours=1)).isoformat()
        creds = {"Credentials": {"AccessKeyId": "key", "SecretAccessKey": "secret",
                                 "SessionToken": "session", "Expiration": exp}}
        token_exp = token_exp if token_exp is not None else (verify.utc() + timedelta(hours=1)).timestamp()
        encoded = base64.urlsafe_b64encode(json.dumps({"exp": token_exp}).encode()).decode().rstrip("=")
        token = "header." + encoded + ".signature"
        (directory / "creds").write_text(json.dumps(creds))
        (directory / "token").write_text(token)
        role = "arn:aws:iam::123456789012:role/agent"
        if phase == "contained" and evidence:
            (directory / "evidence").write_text(json.dumps({
                "role_arn": role, "region": "us-east-2",
                "access_key_sha256": verify.digest("key"), "token_sha256": verify.digest(token),
                "session_expiration": exp, "baseline_at": verify.utc().isoformat()}))
        args = ["verify", phase, "--credentials-file", str(directory / "creds"),
                "--token-file", str(directory / "token"), "--role-arn", role,
                "--region", "us-east-2", "--evidence-file", str(directory / "evidence")]
        with patch.object(verify.sys, "argv", args), \
             patch.object(verify, "call", return_value=("success", {"Arn": identity or
                 "arn:aws:sts::123456789012:assumed-role/agent/before"})), \
             patch.object(verify, "probes", return_value=statuses), \
             redirect_stdout(io.StringIO()) as output:
            result = verify.main()
        return result, output.getvalue()

    def test_baseline_stores_no_secrets_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.invoke_main("baseline", directory)
            self.assertEqual(result, 0)
            text = (Path(directory) / "evidence").read_text()
            self.assertNotIn("secret", text)
            self.assertNotIn("header.", text)
            self.assertEqual((Path(directory) / "evidence").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                self.invoke_main("baseline", directory)

    def test_unsuccessful_baseline_creates_no_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.invoke_main("baseline", directory, statuses=("UnauthorizedOperation", "success"))
            self.assertFalse((Path(directory) / "evidence").exists())

    def test_contained_requires_matching_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "evidence").write_text("{}")
            with self.assertRaises(ValueError):
                self.invoke_main("contained", directory, evidence=False)

    def test_contained_success_is_limited_probe_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.invoke_main("contained", directory,
                                             statuses=("UnauthorizedOperation", "AccessDenied"))
            self.assertEqual(result, 0)
            self.assertIn("not every AWS action", output)
            self.assertNotIn("secret", output)

    def test_expiry_and_wrong_identity_are_rejected(self):
        for extra in ({"expiration": verify.utc().isoformat()},
                      {"token_exp": verify.utc().timestamp()},
                      {"identity": "arn:aws:sts::123456789012:assumed-role/admin/wrong"}):
            with tempfile.TemporaryDirectory() as directory:
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    self.invoke_main("baseline", directory, **extra)

    def test_observation_past_deadline_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(verify.time, "monotonic", side_effect=[0, 181, 181]):
                result, _ = self.invoke_main("contained", directory,
                                             statuses=("UnauthorizedOperation", "AccessDenied"))
            self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
