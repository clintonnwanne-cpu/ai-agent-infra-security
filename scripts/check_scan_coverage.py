"""Fail closed if Checkov omitted expected source coverage or could not parse it."""
import json
from pathlib import Path
import sys


def verify(framework, report):
    if report.get("check_type") != framework:
        raise ValueError(f"Expected {framework} report")
    summary = report["summary"]
    results = report["results"]
    if summary["parsing_errors"] or results["parsing_errors"]:
        raise ValueError("Checkov reported parsing errors")
    # Skipped checks alone cannot establish that the scanner evaluated a file.
    evaluated = results["passed_checks"] + results["failed_checks"]
    if not evaluated:
        raise ValueError("No evaluated checks")
    if framework == "terraform":
        expected = (
            "terraform-aws-vpc/7c1f791efd61f326ed6102d564d1a65d1eceedf0/main.tf",
            "terraform-aws-eks/8a0efdbbc84180a26e0bacfd2b6fcfceac53b3b6/main.tf",
            "terraform-aws-eks/8a0efdbbc84180a26e0bacfd2b6fcfceac53b3b6/modules/eks-managed-node-group/main.tf",
            "terraform-aws-kms/5508c9cdd6fdb0ed4dcf399f54ba02fb8c31bd4b/main.tf",
        )
        paths = {check["file_path"] for check in evaluated
                 if ".external_modules/" in check["file_path"]}
        for suffix in expected:
            if not any(path.endswith(suffix) for path in paths):
                raise ValueError(f"Missing external-module coverage: {suffix}")
        print(f"External-module coverage verified: {len(paths)} source files")
    elif framework == "kubernetes":
        if summary["resource_count"] != 5:
            raise ValueError("Expected the five resources in k8s/rbac.yaml; review coverage")
    else:
        raise ValueError(f"Unsupported framework: {framework}")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    verify(sys.argv[1], json.loads(Path(sys.argv[2]).read_text()))
