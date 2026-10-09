"""Regression tests for evidence-scoped classification; no live providers/calls."""
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
import scanner_evidence as proof
import vendor_integrity as vendor


def mock_evidence():
    return json.loads((REPO / "tests/iac/fixtures/mocked-evidence.json").read_text())


def mocked_report():
    failed = []
    for pair in gate.EXCEPTIONS:
        failed.append({"check_id": pair[0], "resource": pair[1], "file_path": gate.FILE,
                       "caller_file_path": "/main.tf", "check_result": {"result": "FAILED"}})
    for pair, (path, _) in proof.CLASSIFICATIONS.items():
        failed.append({"check_id": pair[0], "resource": pair[1], "file_path": path,
                       "caller_file_path": None if pair[0].startswith("CKV2_") else "/main.tf",
                       "check_result": {"result": "FAILED"}})
    failed.append({"check_id": "CKV_AWS_38", "resource": "module.eks.aws_eks_cluster.this", "file_path": gate.FILE,
                   "caller_file_path": "/main.tf", "check_result": {"result": "FAILED"}})
    passed = [{"check_id": "CKV_TF_1", "resource": "module.eks.kms", "file_path": gate.FILE,
               "check_result": {"result": "PASSED"}}]
    return {"check_type": "terraform", "summary": {"passed": 1, "failed": len(failed), "skipped": 0,
            "parsing_errors": 0, "resource_count": 12, "checkov_version": "3.3.24"},
            "results": {"passed_checks": passed, "failed_checks": failed, "skipped_checks": [], "parsing_errors": []}}


class ScannerEvidenceTests(unittest.TestCase):
    def test_vendor_integrity_and_negative_changes(self):
        vendor.verify_vendor(REPO / "vendor/terraform-aws-eks")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "eks"
            shutil.copytree(REPO / "vendor/terraform-aws-eks", target)
            for name in ["main.tf", "node_groups.tf", "templates/linux_user_data.tpl", "manifest.json", "kms-source.patch"]:
                path = target / name
                before = path.read_bytes()
                path.write_bytes(before + b"\n# changed\n")
                with self.subTest(file=name), self.assertRaises(ValueError): vendor.verify_vendor(target)
                path.write_bytes(before)
            (target / "extra.tf").write_text('resource "bad" "extra" {}')
            with self.assertRaises(ValueError): vendor.verify_vendor(target)
            (target / "extra.tf").unlink()
            (target / "main.tf").unlink()
            with self.assertRaises(ValueError): vendor.verify_vendor(target)

    def test_all_reviewed_reference_groups_match_source(self):
        expected = json.loads((REPO / "tests/iac/fixtures/direct-references.json").read_text())
        actual = proof.extract_references(REPO, REPO / "terraform" / proof.VPC_PATH)
        proof.verify_references(actual, expected)
        self.assertEqual(len(actual), 46)
        for label in actual:
            with self.subTest(label=label):
                changed = copy.deepcopy(actual); changed[label] = None
                with self.assertRaises(ValueError): proof.verify_references(changed, expected)
                changed = copy.deepcopy(actual); del changed[label]
                with self.assertRaises(ValueError): proof.verify_references(changed, expected)

    def test_direct_reference_mutations_rejected_independently_of_hashes(self):
        expected = json.loads((REPO / "tests/iac/fixtures/direct-references.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "terraform").mkdir()
            for p in (REPO / "terraform").glob("*.tf"): shutil.copyfile(p, root / "terraform" / p.name)
            shutil.copytree(REPO / "vendor", root / "vendor")
            vpc = root / "vpc"; vpc.mkdir()
            for p in (REPO / "terraform" / proof.VPC_PATH).glob("*.tf"): shutil.copyfile(p, vpc / p.name)
            cases = [
                ("vendor/terraform-aws-eks/main.tf", "[local.cluster_security_group_id]", "[]"),
                ("vendor/terraform-aws-eks/main.tf", "aws_security_group.cluster[0].id", "var.cluster_security_group_id"),
                ("vendor/terraform-aws-eks/node_groups.tf", "[local.node_security_group_id]", "[]"),
                ("vendor/terraform-aws-eks/node_groups.tf", "aws_security_group.node[0].id", "var.node_security_group_id"),
                ("vendor/terraform-aws-eks/modules/eks-managed-node-group/main.tf", "var.vpc_security_group_ids", "[]"),
                ("vendor/terraform-aws-eks/modules/eks-managed-node-group/main.tf", "? [] : local.security_group_ids", "? [] : []"),
                ("vendor/terraform-aws-eks/modules/eks-managed-node-group/main.tf", "aws_launch_template.this[0].id", "var.launch_template_id"),
                ("vpc/main.tf", "local.nat_gateway_ips,", "[],"),
                ("vpc/main.tf", "aws_eip.nat[*].id", "var.external_nat_ip_ids"),
                ("vpc/main.tf", "for_each = var.default_security_group_ingress", "for_each = []"),
                ("vpc/main.tf", "for_each = var.default_security_group_egress", "for_each = []"),
                ("terraform/main.tf", "single_nat_gateway   = true", "single_nat_gateway   = false"),
            ]
            for name, old, new in cases:
                with self.subTest(file=name, reference=old):
                    path = root / name; original = path.read_text()
                    self.assertIn(old, original)
                    path.write_text(original.replace(old, new))
                    try:
                        actual = proof.extract_references(root, vpc)
                        with self.assertRaises(ValueError): proof.verify_references(actual, expected)
                    finally: path.write_text(original)

    def test_unknown_default_rules_remain_explicitly_unknown(self):
        evidence = mock_evidence(); original = copy.deepcopy(evidence)
        rules = proof.verify_mock_evidence(evidence, "synthetic-test-commit", "synthetic-test-fingerprint")
        self.assertIsNone(rules["configured_ingress"])
        self.assertIsNone(rules["configured_egress"])
        self.assertIs(rules["ingress_unknown"], True)
        self.assertIs(rules["egress_unknown"], True)
        self.assertEqual(evidence, original)

    def test_missing_stale_changed_and_ambiguous_mock_evidence_rejected(self):
        cases = []
        for key, value in [("commit", "other"), ("source_fingerprint", "other"), ("evidence_version", 1),
                           ("terraform_version", "other"), ("secrets_encryption_resources", None),
                           ("ipv6_cni_instances", None), ("planned_resources", []), ("dependency_paths", {}),
                           ("mocked_plan", {}), ("demo_contract", {}), ("negative_controls_rejected", [])]:
            e = mock_evidence(); e[key] = value; cases.append(e)
        e = mock_evidence(); e["mocked_plan"]["passed"] = True; cases.append(e)
        e = mock_evidence(); e["demo_contract"]["endpoint_private_access"] = 1; cases.append(e)
        for name in proof.PINS:
            e = mock_evidence(); e["installed_modules"][name]["sha"] = "other"; cases.append(e)
            e = mock_evidence(); e["installed_modules"][name]["clean"] = False; cases.append(e)
        e = mock_evidence(); e["planned_resources"].append(e["planned_resources"][0]); cases.append(e)
        e = mock_evidence(); e["planned_resources"].append("module.eks.aws_iam_policy.cni_ipv6_policy[0]"); cases.append(e)
        for name in proof.PATHS:
            e = mock_evidence(); e["dependency_paths"][name] = None; cases.append(e)
            e = mock_evidence(); e["dependency_paths"][name][0][-1] = "wrong target"; cases.append(e)
        for direction in ("ingress", "egress"):
            for value in (False, None, "true"):
                e = mock_evidence(); e["default_security_group"][direction + "_unknown"] = value; cases.append(e)
            for value in ([], [{"cidr_blocks": ["0.0.0.0/0"]}]):
                e = mock_evidence(); e["default_security_group"]["configured_" + direction] = value; cases.append(e)
        e = mock_evidence(); del e["source_fingerprint"]; cases.append(e)
        for i, evidence in enumerate(cases):
            with self.subTest(case=i), self.assertRaises((ValueError, KeyError, TypeError)):
                proof.verify_mock_evidence(evidence, "synthetic-test-commit", "synthetic-test-fingerprint")

    def test_exact_classifications_preserve_raw_and_cidr_blocker(self):
        raw = mocked_report(); original = copy.deepcopy(raw)
        result = gate.classify_limitations(gate.assess(raw, 1), raw)
        self.assertEqual(len(result["accepted_demo_exceptions"]), 2)
        self.assertEqual(len(result["classified_scanner_limitations"]), 7)
        self.assertEqual(result["blocking_findings"], [{"check_id": "CKV_AWS_38", "resource": "module.eks.aws_eks_cluster.this"}])
        self.assertEqual(raw, original)
        self.assertFalse(result["operator_cidrs_supplied_or_approved"])

    def test_classification_cannot_expand_or_hide_missing_cidr_or_kms(self):
        for pair in proof.CLASSIFICATIONS:
            raw = mocked_report()
            target = next(r for r in raw["results"]["failed_checks"] if (r["check_id"], r["resource"]) == pair)
            for field, value in [("resource", "module.other.resource"), ("file_path", "/other.tf"), ("caller_file_path", "other")]:
                changed = copy.deepcopy(raw)
                next(r for r in changed["results"]["failed_checks"] if (r["check_id"], r["resource"]) == pair)[field] = value
                with self.subTest(pair=pair, field=field), self.assertRaises(ValueError):
                    gate.classify_limitations(gate.assess(changed, 1), changed)
            changed = copy.deepcopy(raw)
            del next(r for r in changed["results"]["failed_checks"] if (r["check_id"], r["resource"]) == pair)["caller_file_path"]
            with self.assertRaises(ValueError): gate.classify_limitations(gate.assess(changed, 1), changed)
            duplicate = copy.deepcopy(target); duplicate["resource"] = "module.other.resource"
            raw["results"]["failed_checks"].append(duplicate); raw["summary"]["failed"] += 1
            result = gate.classify_limitations(gate.assess(raw, 1), raw)
            self.assertEqual(len(result["blocking_findings"]), 2)
        raw = mocked_report()
        raw["results"]["passed_checks"] = []; raw["summary"]["passed"] = 0
        with self.assertRaises(ValueError): gate.classify_limitations(gate.assess(raw, 1), raw)
        raw = mocked_report()
        raw["results"]["failed_checks"] = [r for r in raw["results"]["failed_checks"] if r["check_id"] != "CKV_AWS_38"]
        raw["summary"]["failed"] -= 1
        with self.assertRaises(ValueError): gate.classify_limitations(gate.assess(raw, 1), raw)


if __name__ == "__main__": unittest.main()
