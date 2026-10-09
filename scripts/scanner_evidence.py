"""Guard seven scanner classifications with exact references and mocked evidence.

Dependency paths are supplementary. Classification is based on reviewed source
references/defaults plus instantiated mocked resources, never unknown == empty.
"""
import copy
import json
from pathlib import Path
import subprocess

from vendor_integrity import verify_vendor, source_fingerprint, require, digest, KMS_PIN
from verify_iac_evidence import PINS, REQUIRED, PATHS

REFERENCES_SHA256 = "d135f9b7102eb662e12f0e3f15569f5b7be143546b00943c1e8c65e5e7c9cbd6"
VPC_PIN = PINS["vpc"]
VPC_PATH = ".external_modules/github.com/terraform-aws-modules/terraform-aws-vpc/" + VPC_PIN
KMS_PATH = ".external_modules/github.com/terraform-aws-modules/terraform-aws-kms/" + KMS_PIN
EKS_FILE = "/../vendor/terraform-aws-eks/main.tf"
VPC_FILE = "/" + VPC_PATH + "/main.tf"
CLASSIFICATIONS = {
    ("CKV_AWS_58", "module.eks.aws_eks_cluster.this"): (EKS_FILE, "Dynamic secrets encryption expands in the mocked plan; key selection remains module-created."),
    ("CKV_AWS_111", "module.eks.aws_iam_policy_document.cni_ipv6_policy"): ("/../vendor/terraform-aws-eks/node_groups.tf", "Disabled IPv6 document: zero policy/document instances in the mocked plan."),
    ("CKV_AWS_356", "module.eks.aws_iam_policy_document.cni_ipv6_policy"): ("/../vendor/terraform-aws-eks/node_groups.tf", "Disabled IPv6 document: zero policy/document instances in the mocked plan."),
    ("CKV2_AWS_5", "module.eks.aws_security_group.cluster[0]"): (EKS_FILE, "Direct cluster security-group value references verified; no live attachment claim."),
    ("CKV2_AWS_5", "module.eks.aws_security_group.node"): ("/../vendor/terraform-aws-eks/node_groups.tf", "Direct node-group/launch-template group references verified; no live attachment claim."),
    ("CKV2_AWS_19", "module.vpc.aws_eip.nat[0]"): (VPC_FILE, "Direct NAT allocation reference reaches the created EIP; no live attachment claim."),
    ("CKV2_AWS_12", "module.vpc.aws_vpc.this"): (VPC_FILE, "Managed default-group source loops are empty; computed mocked rule values may remain unknown, not verified empty."),
}


def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items() if not k.startswith("__")}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


def document(directory):
    import hcl2
    require(not list(directory.glob("*.tf.json")) and not list(directory.glob("*override.tf")), "Unexpected source override")
    result = {}
    for path in sorted(directory.glob("*.tf")):
        for key, blocks in hcl2.loads(path.read_text()).items():
            require(type(blocks) is list, "Unexpected HCL block shape")
            result.setdefault(key, []).extend(blocks)
    return result


def block(doc, kind, *labels):
    matches = []
    for entry in doc.get(kind, []):
        for label in labels:
            if not isinstance(entry, dict) or label not in entry:
                break
            entry = entry[label]
        else:
            matches.append(entry)
    require(len(matches) == 1, "Missing/ambiguous HCL reference: " + "/".join((kind,) + labels))
    return clean(matches[0])


def local(doc, name):
    matches = [entry[name] for entry in doc.get("locals", []) if name in entry]
    require(len(matches) == 1, "Missing/ambiguous local: " + name)
    return clean(matches[0])


def extract_references(repo, vpc):
    root = document(repo / "terraform")
    eks = document(repo / "vendor/terraform-aws-eks")
    node = document(repo / "vendor/terraform-aws-eks/modules/eks-managed-node-group")
    vpc = document(vpc)
    output = {"root.terraform": block(root, "terraform"),
              "root.eks": block(root, "module", "eks"), "root.vpc": block(root, "module", "vpc")}
    selections = [
        ("eks.cluster", eks, "resource", ("aws_eks_cluster", "this"), ["vpc_config", "dynamic"]),
        ("eks.ipv6_document", eks, "data", ("aws_iam_policy_document", "cni_ipv6_policy"), ["count"]),
        ("eks.ipv6_policy", eks, "resource", ("aws_iam_policy", "cni_ipv6_policy"), ["count", "policy"]),
        ("eks.managed_node_input", eks, "module", ("eks_managed_node_group",),
         ["source", "vpc_security_group_ids", "network_interfaces", "enable_efa_support", "create_launch_template", "use_custom_launch_template", "launch_template_id"]),
        ("node.launch_template", node, "resource", ("aws_launch_template", "this"), ["count", "vpc_security_group_ids"]),
        ("node.group", node, "resource", ("aws_eks_node_group", "this"), ["dynamic"]),
        ("vpc.nat", vpc, "resource", ("aws_nat_gateway", "this"), ["count", "allocation_id"]),
        ("vpc.eip", vpc, "resource", ("aws_eip", "nat"), ["count"]),
        ("vpc.default_group", vpc, "resource", ("aws_default_security_group", "this"), ["count", "vpc_id", "dynamic"]),
        ("eks.kms", eks, "module", ("kms",), ["source", "create"]),
    ]
    for label, doc, kind, labels, keys in selections:
        item = block(doc, kind, *labels)
        output[label] = {key: item[key] for key in keys}
    for label, doc, names in [
        ("eks", eks, ["create", "create_cluster_sg", "cluster_security_group_id", "create_node_sg", "node_security_group_id", "enable_cluster_encryption_config"]),
        ("node", node, ["security_group_ids", "network_interfaces", "enable_efa_support", "launch_template_id"]),
        ("vpc", vpc, ["create_vpc", "nat_gateway_ips", "nat_gateway_count"]),
    ]:
        for name in names:
            output[label + ".local." + name] = local(doc, name)
    for label, doc, names in [
        ("eks", eks, ["create", "putin_khuylo", "create_kms_key", "create_cluster_security_group", "create_node_security_group", "create_cni_ipv6_iam_policy", "cluster_ip_family", "cluster_additional_security_group_ids", "eks_managed_node_group_defaults"]),
        ("node", node, ["create", "create_launch_template", "use_custom_launch_template", "enable_efa_support", "network_interfaces"]),
        ("vpc", vpc, ["create_vpc", "putin_khuylo", "reuse_nat_ips", "manage_default_security_group", "default_security_group_ingress", "default_security_group_egress"]),
    ]:
        for name in names:
            output[label + ".default." + name] = block(doc, "variable", name)["default"]
    return output


def verify_references(actual, expected):
    require(type(actual) is dict and set(actual) == set(expected), "Missing/extra reference evidence")
    for label, value in expected.items():
        require(json.dumps(actual[label], sort_keys=True) == json.dumps(value, sort_keys=True),
                "Changed direct value reference/default: " + label)


def verify_mock_evidence(evidence, commit, fingerprint):
    require(type(evidence) is dict and evidence["evidence_version"] == 2, "Unexpected evidence schema")
    require(evidence["commit"] == commit and evidence["source_fingerprint"] == fingerprint, "Stale or unrelated mocked evidence")
    require(evidence["terraform_version"] == "1.9.8", "Changed Terraform evidence version")
    modules = evidence["installed_modules"]
    require(set(modules) == set(PINS), "Missing/extra module evidence")
    for name, revision in PINS.items():
        require(modules[name]["sha"] == revision and modules[name]["clean"] is True, "Changed/dirty module evidence: " + name)
    require(json.dumps(evidence["mocked_plan"], sort_keys=True) ==
            json.dumps({"status": "pass", "passed": 1, "failed": 0, "errored": 0, "skipped": 0}, sort_keys=True),
            "Mocked plan did not pass or has ambiguous counts")
    controls = ["missing encryption", "enabled IPv6 policy", "missing launch template", "missing EIP"]
    controls += ["broken " + name for name in PATHS]
    controls += ["configured default-group ingress"]
    require(evidence["negative_controls_rejected"] == controls, "Missing negative-control evidence")
    resources = evidence["planned_resources"]
    require(type(resources) is list and all(type(r) is str for r in resources)
            and len(resources) == len(set(resources)) and REQUIRED <= set(resources), "Missing/ambiguous planned resources")
    require(not any("cni_ipv6_policy" in r for r in resources) and type(evidence["ipv6_cni_instances"]) is int
            and evidence["ipv6_cni_instances"] == 0, "IPv6 policy is instantiated or unknown")
    require(evidence["secrets_encryption_resources"] == ["secrets"], "Missing/unknown encryption")
    require(json.dumps(evidence["demo_contract"], sort_keys=True) == json.dumps({"endpoint_public_access": True, "endpoint_private_access": True,
            "cidrs_match_mock_fixture": True, "retention_days": 90, "operator_cidrs_verified": False}, sort_keys=True), "Changed demo evidence")
    paths = evidence["dependency_paths"]
    require(type(paths) is dict and set(paths) == set(PATHS), "Missing/extra dependency evidence")
    for label, anchors in PATHS.items():
        segments = paths[label]
        require(type(segments) is list and len(segments) == len(anchors) - 1, "Ambiguous dependency shape")
        for segment, start, end in zip(segments, anchors, anchors[1:]):
            require(type(segment) is list and len(segment) >= 2 and all(type(v) is str for v in segment)
                    and len(segment) == len(set(segment)) and segment[0] == start + " (expand)"
                    and segment[-1] == end + " (expand)", "Invalid dependency path")
    default = evidence["default_security_group"]
    require(type(default) is dict and set(default) == {"configured_ingress", "configured_egress", "ingress_unknown", "egress_unknown"}, "Ambiguous default-group evidence")
    for direction in ("ingress", "egress"):
        unknown, value = default[direction + "_unknown"], default["configured_" + direction]
        require(type(unknown) is bool, "Ambiguous rule unknown marker")
        require(value is None if unknown else value == [], "Configured rules or inconsistent unknown evidence")
    return copy.deepcopy(default)


def verify_evidence(repo, evidence):
    verify_vendor(repo / "vendor/terraform-aws-eks")
    for relative, revision in ((VPC_PATH, VPC_PIN), (KMS_PATH, KMS_PIN)):
        path = (repo / "terraform" / relative).resolve()
        git = ["git", "-C", str(path)]
        require(Path(subprocess.check_output(git + ["rev-parse", "--show-toplevel"], text=True).strip()).resolve() == path,
                "Missing independent scanner module checkout")
        require(subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip() == revision,
                "Changed scanner module revision")
        require(not subprocess.check_output(git + ["status", "--porcelain", "--untracked-files=all", "--ignored"], text=True).strip(),
                "Modified scanner module source")
    reviewed = (repo / "tests/iac/fixtures/direct-references.json").read_bytes()
    require(digest(reviewed) == REFERENCES_SHA256, "Unreviewed direct-reference contract")
    expected = json.loads(reviewed)
    actual = extract_references(repo, repo / "terraform" / VPC_PATH)
    verify_references(actual, expected)
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    default = verify_mock_evidence(evidence, commit, source_fingerprint(repo))
    return {"commit": commit, "direct_reference_groups_verified": len(actual),
            "default_security_group": default, "live_enforcement_verified": False}
