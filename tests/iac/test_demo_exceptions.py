"""Security gate regression tests; all reports/resources are synthetic."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import check_demo_exceptions as gate


def report():
    checks = [{"check_id": key[0], "resource": key[1], "check_result": {"result": "FAILED"},
               "file_path": gate.FILE, "caller_file_path": "/main.tf"} for key in gate.EXCEPTIONS]
    return {"check_type": "terraform", "summary": {"passed": 0, "failed": 2, "skipped": 0,
            "parsing_errors": 0, "resource_count": 2, "checkov_version": "3.3.24"},
            "results": {"passed_checks": [], "failed_checks": checks, "skipped_checks": [], "parsing_errors": []}}


class DemoGateTests(unittest.TestCase):
    def test_only_exact_pairs_accepted_and_raw_report_unchanged(self):
        raw = report()
        original = copy.deepcopy(raw)
        result = gate.assess(raw, 1)
        self.assertEqual(len(result["accepted_demo_exceptions"]), 2)
        self.assertEqual(result["blocking_findings"], [])
        self.assertEqual(raw, original)
        self.assertFalse(result["operator_cidrs_supplied_or_approved"])

    def test_other_failures_including_same_check_elsewhere_remain_blocking(self):
        for check, address in [("CKV_AWS_39", "module.other.aws_eks_cluster.this"),
                               ("CKV_AWS_338", "module.other.aws_cloudwatch_log_group.this[0]"),
                               ("CKV_AWS_58", "module.eks.aws_eks_cluster.this"),
                               ("CKV_TF_1", "module.eks.kms"),
                               ("CKV2_AWS_5", "module.eks.aws_security_group.node")]:
            with self.subTest(check=check, address=address):
                raw = report()
                r = copy.deepcopy(raw["results"]["failed_checks"][0])
                r.update(check_id=check, resource=address)
                raw["results"]["failed_checks"].append(r)
                raw["summary"]["failed"] += 1
                self.assertEqual(gate.assess(raw, 1)["blocking_findings"], [{"check_id": check, "resource": address}])

    def test_missing_ambiguous_changed_and_malformed_reports_rejected(self):
        cases = []
        for field, value in [("resource", None), ("resource", "module.eks.aws_eks_cluster.this[0]"),
                             ("file_path", "/other.tf"), ("caller_file_path", "/other.tf"),
                             ("check_result", {"result": "UNKNOWN"})]:
            raw = report(); raw["results"]["failed_checks"][0][field] = value; cases.append(raw)
        raw = report(); raw["results"]["failed_checks"].pop(); raw["summary"]["failed"] = 1; cases.append(raw)
        raw = report(); raw["results"]["failed_checks"].append(copy.deepcopy(raw["results"]["failed_checks"][0])); raw["summary"]["failed"] = 3; cases.append(raw)
        raw = report(); raw["results"]["parsing_errors"] = ["bad.tf"]; cases.append(raw)
        raw = report(); raw["summary"]["parsing_errors"] = 1; cases.append(raw)
        raw = report(); raw["summary"]["failed"] = 0; cases.append(raw)
        raw = report(); raw["summary"]["checkov_version"] = "future"; cases.append(raw)
        raw = report(); raw["results"]["unknown_checks"] = []; cases.append(raw)
        raw = report(); raw["results"]["passed_checks"] = {}; cases.append(raw)
        raw = report(); raw["results"]["failed_checks"][0]["check_result"]["result"] = "SKIPPED"; cases.append(raw)
        cases.extend([[], {}, {"check_type": "kubernetes"}])
        for i, raw in enumerate(cases):
            with self.subTest(case=i), self.assertRaises((ValueError, KeyError, TypeError)):
                gate.assess(raw, 1)
        for exit_code in (0, 2, 137):
            with self.subTest(exit=exit_code), self.assertRaises(ValueError):
                gate.assess(report(), exit_code)

    def test_unapproved_skip_rejected(self):
        raw = report()
        r = copy.deepcopy(raw["results"]["failed_checks"][0])
        r.update(check_id="CKV_AWS_58"); r["check_result"]["result"] = "SKIPPED"
        raw["results"]["skipped_checks"] = [r]; raw["summary"]["skipped"] = 1
        with self.assertRaises(ValueError): gate.assess(raw, 1)

    def test_source_contract_and_negative_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "terraform"
            root.mkdir()
            for source in (REPO / "terraform").glob("*.tf"):
                shutil.copyfile(source, root / source.name)
            upstream = root / gate.FILE.lstrip("/")
            upstream.parent.mkdir(parents=True)
            upstream.write_text('''resource "aws_eks_cluster" "this" {
  vpc_config {
    endpoint_public_access = var.cluster_endpoint_public_access
    endpoint_private_access = var.cluster_endpoint_private_access
    public_access_cidrs = var.cluster_endpoint_public_access_cidrs
  }
}
resource "aws_cloudwatch_log_group" "this" {
  retention_in_days = var.cloudwatch_log_group_retention_in_days
}
''')
            gate.verify_contract(root)
            cases = [("main.tf", "cluster_endpoint_public_access         = true", "cluster_endpoint_public_access         = false"),
                     ("main.tf", "cluster_endpoint_private_access        = true", "cluster_endpoint_private_access        = false"),
                     ("main.tf", "var.operator_public_access_cidrs", '["0.0.0.0/0"]'),
                     ("main.tf", "= 90", "= 365"),
                     ("variables.tf", "nullable    = false", "nullable    = true"),
                     ("variables.tf", "type        = list(string)", 'type = list(string)\n default = ["0.0.0.0/0"]'),
                     ("variables.tf", "> 0", ">= 0"),
                     (str(upstream.relative_to(root)), "endpoint_private_access = var.cluster_endpoint_private_access", "endpoint_private_access = false"),
                     (str(upstream.relative_to(root)), "public_access_cidrs = var.cluster_endpoint_public_access_cidrs", 'public_access_cidrs = ["0.0.0.0/0"]'),
                     (str(upstream.relative_to(root)), "retention_in_days = var.cloudwatch_log_group_retention_in_days", "retention_in_days = 7")]
            for filename, before, after in cases:
                with self.subTest(file=filename, before=before):
                    path = root / filename; original = path.read_text()
                    self.assertIn(before, original)
                    path.write_text(original.replace(before, after))
                    try:
                        with self.assertRaises(ValueError): gate.verify_contract(root)
                    finally: path.write_text(original)
            duplicate = root / "duplicate.tf"
            duplicate.write_text('module "eks" { source = "other" }')
            with self.assertRaises(ValueError): gate.verify_contract(root)
            duplicate.unlink()
            override = root / "operator.auto.tfvars"
            override.write_text('operator_public_access_cidrs = ["0.0.0.0/0"]')
            with self.assertRaises(ValueError): gate.verify_contract(root)
            override.unlink()
            upstream.unlink()
            with self.assertRaises(FileNotFoundError): gate.verify_contract(root)


if __name__ == "__main__": unittest.main()
