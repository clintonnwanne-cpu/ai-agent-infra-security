"""Gate raw Checkov findings against two exact, conditional demo exceptions.

This verifies a required-input source contract, not approved operator addresses
or live enforcement. Raw Checkov JSON is never changed. Run with Checkov 3.3.24.
"""
import argparse
import json
import os
from pathlib import Path
import sys

from check_scan_coverage import verify as verify_coverage
from scanner_evidence import EKS_FILE, CLASSIFICATIONS, verify_evidence

EKS_PIN = "8a0efdbbc84180a26e0bacfd2b6fcfceac53b3b6"
SOURCE = "../vendor/terraform-aws-eks"
FILE = EKS_FILE
EXCEPTIONS = {
    ("CKV_AWS_39", "module.eks.aws_eks_cluster.this"):
        "Approved demo public API design: required approved IPv4 CIDRs, private endpoint retained; actual operator input still pending.",
    ("CKV_AWS_338", "module.eks.aws_cloudwatch_log_group.this[0]"):
        "Approved disposable-demo retention: 90 days; older forensic evidence expires. Review before persistent/compliance use.",
}
# Exact parsed validation expression: any relaxation requires explicit review.
VALIDATION = '${try(length(var.operator_public_access_cidrs) > 0 && alltrue([for cidr in var.operator_public_access_cidrs : can(cidrnetmask(cidr)) && try(tonumber(split("/",cidr)[1]) > 0,False)]),False)}'
EXISTING_SKIPS = {
    (check, "aws_s3_bucket." + bucket)
    for check in ("CKV_AWS_144", "CKV2_AWS_62")
    for bucket in ("agent_state", "agent_logs")
} | {("CKV_AWS_145", "aws_s3_bucket.agent_logs")}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def one(items, label):
    require(len(items) == 1, "Missing or ambiguous " + label)
    return items[0]


def verify_contract(root):
    # Use the HCL parser shipped with the pinned scanner, not text matching.
    import hcl2
    require(not any(k.startswith("TF_VAR_") for k in os.environ), "Unexpected TF_VAR input")
    require(not list(root.glob("*.tfvars*")) and not list(root.glob("*.tf.json"))
            and not list(root.glob("*override.tf")), "Unexpected variable/override source")
    definitions = [hcl2.loads(p.read_text()) for p in root.glob("*.tf")]
    module = one([m["eks"] for d in definitions for m in d.get("module", []) if "eks" in m], "EKS module")
    expected = {"source": [SOURCE], "cluster_endpoint_public_access": [True],
                "cluster_endpoint_private_access": [True],
                "cluster_endpoint_public_access_cidrs": ["${var.operator_public_access_cidrs}"],
                "cloudwatch_log_group_retention_in_days": [90]}
    for key, value in expected.items():
        require(json.dumps(module.get(key)) == json.dumps(value), "Changed EKS contract: " + key)
    variable = one([v["operator_public_access_cidrs"] for d in definitions for v in d.get("variable", [])
                    if "operator_public_access_cidrs" in v], "operator CIDR variable")
    require("default" not in variable and variable.get("nullable") == [False]
            and variable.get("type") == ["${list(string)}"], "CIDR input must be required and nonnullable")
    validation = one(variable.get("validation", []), "CIDR validation")
    require(validation.get("condition") == [VALIDATION], "Changed CIDR validation")
    # Read the same pinned source referenced by the report; reject missing,
    # ambiguous or changed resource wiring rather than guessing its settings.
    upstream = hcl2.loads((root / FILE.lstrip("/")).read_text())
    cluster = one([r["aws_eks_cluster"]["this"] for r in upstream.get("resource", [])
                   if "this" in r.get("aws_eks_cluster", {})], "upstream cluster")
    vpc = one(cluster.get("vpc_config", []), "cluster vpc_config")
    for field, argument in (("endpoint_public_access", "cluster_endpoint_public_access"),
                            ("endpoint_private_access", "cluster_endpoint_private_access"),
                            ("public_access_cidrs", "cluster_endpoint_public_access_cidrs")):
        require(vpc.get(field) == ["${var." + argument + "}"], "Changed cluster wiring: " + field)
    logs = one([r["aws_cloudwatch_log_group"]["this"] for r in upstream.get("resource", [])
                if "this" in r.get("aws_cloudwatch_log_group", {})], "upstream log group")
    require(logs.get("retention_in_days") == ["${var.cloudwatch_log_group_retention_in_days}"],
            "Changed log retention wiring")


def assess(report, scanner_exit):
    require(type(report) is dict and report.get("check_type") == "terraform", "Unexpected report shape")
    summary, results = report["summary"], report["results"]
    require(type(summary) is dict and type(results) is dict, "Invalid report objects")
    require(set(results) == {"passed_checks", "failed_checks", "skipped_checks", "parsing_errors"},
            "Unexpected result categories")
    require(summary.get("checkov_version") == "3.3.24", "Unexpected scanner version")
    require(type(results["parsing_errors"]) is list and not results["parsing_errors"]
            and type(summary["parsing_errors"]) is int and summary["parsing_errors"] == 0,
            "Parsing errors or invalid parsing result")
    seen, records = set(), {}
    for category, status in (("passed", "PASSED"), ("failed", "FAILED"), ("skipped", "SKIPPED")):
        checks = results[category + "_checks"]
        require(type(checks) is list and type(summary[category]) is int
                and summary[category] == len(checks), "Invalid " + category + " count/shape")
        for record in checks:
            require(type(record) is dict, "Invalid check record")
            key = (record.get("check_id"), record.get("resource"))
            require(all(type(v) is str and v for v in key), "Missing resource/check identity")
            require(key not in seen, "Duplicate/ambiguous check resource: " + str(key))
            seen.add(key)
            require(type(record.get("check_result")) is dict
                    and record["check_result"].get("result") == status, "Unexpected check status")
            require(type(record.get("file_path")) is str and record["file_path"], "Missing resource source")
            if category == "skipped":
                require(key in EXISTING_SKIPS and record["file_path"] == "/iam.tf", "Unapproved skip")
            records[key] = (category, record)
    require(scanner_exit in (0, 1) and scanner_exit == int(summary["failed"] > 0), "Unexpected scanner exit")
    require(type(summary.get("resource_count")) is int and summary["resource_count"] > 0, "Missing resources")
    accepted = []
    for key, reason in EXCEPTIONS.items():
        require(key in records, "Missing exception target: " + str(key))
        category, record = records[key]
        require(category == "failed" and record["file_path"] == FILE
                and record.get("caller_file_path") == "/main.tf", "Changed exception target/source/status")
        accepted.append({"check_id": key[0], "resource": key[1], "reason": reason})
    remaining = [{"check_id": r["check_id"], "resource": r["resource"]}
                 for r in results["failed_checks"] if (r["check_id"], r["resource"]) not in EXCEPTIONS]
    return {"accepted_demo_exceptions": accepted, "blocking_findings": remaining,
            "operator_cidrs_supplied_or_approved": False,
            "limits": "Required-input source contract only; mocked tests and source scanning do not verify deployable CIDRs or live enforcement."}


def classify_limitations(result, report):
    """Called only after same-commit source and mocked evidence verification."""
    accepted = []
    for pair, (path, reason) in CLASSIFICATIONS.items():
        matches = [r for r in report["results"]["failed_checks"]
                   if (r["check_id"], r["resource"]) == pair]
        record = one(matches, "scanner-limitation target " + str(pair))
        caller = None if pair[0].startswith("CKV2_") else "/main.tf"
        require(record["file_path"] == path and "caller_file_path" in record
                and record["caller_file_path"] == caller,
                "Changed classification source/caller")
        accepted.append({"check_id": pair[0], "resource": pair[1], "reason": reason})
    kms = one([r for r in report["results"]["passed_checks"]
               if r["check_id"] == "CKV_TF_1" and r["resource"] == "module.eks.kms"], "passing immutable KMS check")
    require(kms["file_path"] == FILE, "Changed KMS check source")
    # No approved operator input exists. Never silently close this item based
    # on a source scanner accepting an unresolved variable or mock fixture.
    one([r for r in report["results"]["failed_checks"] if r["check_id"] == "CKV_AWS_38"
         and r["resource"] == "module.eks.aws_eks_cluster.this"], "unresolved operator CIDR finding")
    result["classified_scanner_limitations"] = accepted
    result["blocking_findings"] = [r for r in result["blocking_findings"]
                                    if (r["check_id"], r["resource"]) not in CLASSIFICATIONS]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("scanner_exit", type=int)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("terraform"))
    parser.add_argument("--output", type=Path, default=Path("checkov-demo-exceptions.json"))
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    result = assess(report, args.scanner_exit)
    verify_coverage("terraform", report)
    verify_contract(args.root)
    verified = verify_evidence(args.root.resolve().parent, json.loads(args.evidence.read_text()))
    result = classify_limitations(result, report)
    result["evidence"] = verified
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Accepted exactly {len(result['accepted_demo_exceptions'])} demo exceptions; "
          f"{len(result['classified_scanner_limitations'])} guarded scanner limitations; "
          f"{len(result['blocking_findings'])} other findings remain blocking")
    return int(bool(result["blocking_findings"]))


if __name__ == "__main__":
    sys.exit(main())
