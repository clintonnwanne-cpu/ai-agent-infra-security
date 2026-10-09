"""Source-CI policy never promotes synthetic fixtures to deployment approval."""
import copy
from contextlib import ExitStack
from pathlib import Path
import unittest
from unittest.mock import patch

from test_scanner_evidence import gate, mocked_report


def evaluate(report, failing_guard=None):
    # Underlying guards have real-source/evidence mutation tests in the other
    # suites. Here test that the policy cannot bypass any guard or alter findings.
    with ExitStack() as stack:
        for name in ("verify_coverage", "verify_contract", "verify_evidence"):
            stack.enter_context(patch.object(gate, name,
                side_effect=ValueError("Rejected " + name) if name == failing_guard else None,
                return_value={"live_enforcement_verified": False}))
        return gate.evaluate_source_ci(Path("terraform"), report, 1, {})


class SourceCiTests(unittest.TestCase):
    def test_exact_failure_remains_visible_without_approval_or_live_claims(self):
        raw = mocked_report(); original = copy.deepcopy(raw)
        result = evaluate(raw)
        self.assertEqual(raw, original)
        self.assertEqual(result["blocking_findings"], [])
        self.assertEqual(len(result["accepted_demo_exceptions"]), 2)
        self.assertEqual(len(result["classified_scanner_limitations"]), 7)
        finding, = result["deployment_input_required"]
        self.assertEqual((finding["check_id"], finding["resource"]), gate.DEPLOYMENT_INPUT)
        self.assertEqual(finding["raw_status"], "FAILED")
        self.assertEqual(finding["scope"], "source_ci_only")
        self.assertIs(result["source_ci_contract_verified"], True)
        self.assertIs(result["actual_operator_input_evaluated"], False)
        self.assertIs(result["operator_cidrs_supplied_or_approved"], False)
        self.assertIs(result["live_enforcement_verified"], False)
        self.assertEqual(result["deployment_readiness"], "not_verified")

    def test_each_guard_must_pass_before_any_classification(self):
        for guard in ("verify_coverage", "verify_contract", "verify_evidence"):
            with self.subTest(guard=guard), patch.object(gate, "classify_limitations") as classify:
                with self.assertRaises(ValueError): evaluate(mocked_report(), guard)
                classify.assert_not_called()

    def test_missing_duplicate_other_resource_caller_and_status_rejected(self):
        cases = []
        for field, value in (("resource", "module.other.aws_eks_cluster.this"),
                             ("file_path", "/other.tf"), ("caller_file_path", "/other.tf"),
                             ("check_result", {"result": "UNKNOWN"})):
            raw = mocked_report(); raw["results"]["failed_checks"][-1][field] = value; cases.append(raw)
        raw = mocked_report(); raw["results"]["failed_checks"].pop(); raw["summary"]["failed"] -= 1; cases.append(raw)
        raw = mocked_report(); raw["results"]["failed_checks"].append(copy.deepcopy(raw["results"]["failed_checks"][-1])); raw["summary"]["failed"] += 1; cases.append(raw)
        for category, status in (("passed", "PASSED"), ("skipped", "SKIPPED")):
            raw = mocked_report()
            record = raw["results"]["failed_checks"].pop(); raw["summary"]["failed"] -= 1
            record["check_result"]["result"] = status
            raw["results"][category + "_checks"].append(record); raw["summary"][category] += 1
            cases.append(raw)
        for i, raw in enumerate(cases):
            with self.subTest(case=i), self.assertRaises(ValueError): evaluate(raw)

    def test_same_check_elsewhere_and_unrelated_failures_remain_blocking(self):
        for check in ("CKV_AWS_38", "CKV_AWS_NEW"):
            raw = mocked_report()
            other = copy.deepcopy(raw["results"]["failed_checks"][-1])
            other.update(check_id=check, resource="module.other.aws_eks_cluster.this")
            raw["results"]["failed_checks"].append(other); raw["summary"]["failed"] += 1
            result = evaluate(raw)
            self.assertEqual(result["blocking_findings"], [{"check_id": check, "resource": other["resource"]}])
            self.assertFalse(result["actual_operator_input_evaluated"])


if __name__ == "__main__":
    unittest.main()
