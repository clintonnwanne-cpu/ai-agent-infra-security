#!/usr/bin/env python3
"""Read-only baseline/containment probes. Never logs credentials or JWTs."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ERROR_CODE = re.compile(r"An error occurred \(([^)]+)\)")
SESSION_DENIALS = {"UnauthorizedOperation", "AccessDenied", "AccessDeniedException"}
ASSUMPTION_DENIALS = {"AccessDenied", "AccessDeniedException"}


def utc():
    return datetime.now(timezone.utc)


def expiry(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Session expiration must include a timezone")
    return parsed


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def credential_env(credentials):
    # Freeze this session; disable SDK/CLI refresh and fallback identities.
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update(AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
               AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
               AWS_SESSION_TOKEN=credentials["SessionToken"],
               AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="",
               AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull)
    return env


def call(args, env):
    result = subprocess.run(["aws", *args, "--output", "json",
                             "--cli-connect-timeout", "5", "--cli-read-timeout", "5"],
                            env=env, text=True, capture_output=True, timeout=20)
    if result.returncode == 0:
        return "success", json.loads(result.stdout)
    match = ERROR_CODE.search(result.stderr)
    # Never echo raw errors: endpoints/proxies could include request material.
    return match.group(1) if match else "unclassified-error", None


def probes(role_arn, token_file, region, env):
    old, _ = call(["ec2", "describe-instances", "--region", region,
                   "--max-results", "5", "--no-paginate"], env)
    fresh, _ = call(["sts", "assume-role-with-web-identity", "--region", region,
                     "--role-arn", role_arn, "--role-session-name", "containment-probe",
                     "--duration-seconds", "900", "--web-identity-token",
                     "file://" + str(token_file.resolve()), "--no-sign-request"], env)
    return old, fresh


def evaluate(old, fresh):
    # ExpiredToken, InvalidIdentityToken, throttling, DNS, etc. are inconclusive.
    return old in SESSION_DENIALS and fresh in ASSUMPTION_DENIALS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["baseline", "contained"])
    parser.add_argument("--credentials-file", type=Path, required=True,
                        help="Pre-shutdown STS response containing Credentials")
    parser.add_argument("--token-file", type=Path, required=True,
                        help="Same valid web-identity JWT used by the baseline")
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--evidence-file", type=Path, required=True,
                        help="Baseline evidence (hashes only, no credentials)")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--interval", type=float, default=5)
    args = parser.parse_args()
    if args.timeout < 1 or args.interval < 1:
        parser.error("timeout and interval must be positive (interval >= 1)")
    role = re.fullmatch(r"arn:([^:]+):iam::([0-9]{12}):role/(.+)", args.role_arn)
    if not role:
        parser.error("role-arn must be an IAM role ARN")
    credentials = json.loads(args.credentials_file.read_text())["Credentials"]
    # Do not accept expired sessions or expiry inside the verification window.
    # Baseline STS validates the signature; this local exp check prevents an
    # expired token from being mistaken for trust-policy containment later.
    if expiry(credentials["Expiration"]) <= utc() + timedelta(seconds=args.timeout + 45):
        raise ValueError("Captured session expires too soon; obtain a new baseline before shutdown")
    token = args.token_file.read_text().strip()
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    if float(claims["exp"]) <= (utc() + timedelta(seconds=args.timeout + 45)).timestamp():
        raise ValueError("Web identity token expires too soon for the verification window")
    env = credential_env(credentials)
    identity_status, identity = call(["sts", "get-caller-identity", "--region", args.region], env)
    expected_prefix = f"arn:{role[1]}:sts::{role[2]}:assumed-role/{role[3].split('/')[-1]}/"
    if identity_status != "success" or not identity["Arn"].startswith(expected_prefix):
        raise ValueError("Captured credentials do not identify the specified agent role")
    binding = {
        "role_arn": args.role_arn, "region": args.region,
        "access_key_sha256": digest(credentials["AccessKeyId"]),
        "token_sha256": digest(token),
        "session_expiration": credentials["Expiration"],
    }
    if args.phase == "baseline":
        old, fresh = probes(args.role_arn, args.token_file, args.region, env)
        if (old, fresh) != ("success", "success"):
            raise ValueError(f"Baseline must succeed: existing_session={old}, new_assumption={fresh}")
        evidence = {**binding, "baseline_at": utc().isoformat()}
        # Exclusive creation: do not silently replace an earlier baseline.
        fd = os.open(args.evidence_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(evidence, f, indent=2)
        print("BASELINE: existing-session EC2 read and web-identity assumption succeeded.")
        return 0
    evidence = json.loads(args.evidence_file.read_text())
    if any(evidence.get(key) != value for key, value in binding.items()) or not evidence.get("baseline_at"):
        raise ValueError("Inputs differ from the successful baseline")
    started = time.monotonic()
    deadline = started + args.timeout
    while True:
        old, fresh = probes(args.role_arn, args.token_file, args.region, env)
        observed = utc().isoformat()
        print(f"{observed} existing_session={old} new_assumption={fresh}", flush=True)
        if evaluate(old, fresh) and time.monotonic() <= deadline:
            print(f"OBSERVED: both probes denied in this iteration, {time.monotonic() - started:.1f}s after verifier start.")
            print("Evidence covers this session, EC2 read, and web-identity path in this region; not every AWS action or a global timing bound.")
            return 0
        if time.monotonic() >= deadline:
            print("NOT VERIFIED: denial not observed for both probes within the window.", file=sys.stderr)
            return 1
        time.sleep(min(args.interval, max(0, deadline - time.monotonic())))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, IndexError, TypeError, OSError, subprocess.TimeoutExpired) as exc:
        # Do not expose raw exception text that could contain credential material.
        print(f"NOT VERIFIED: invalid inputs or probe execution failed ({type(exc).__name__}).", file=sys.stderr)
        sys.exit(1)
