"""Credential-free, plan-only evidence for the pinned Terraform configuration.

Run after init. No Checkov finding is suppressed or required to stay failing.
Computed IDs/rules may be unknown: dependency paths are source evidence only.
"""
import argparse
from collections import deque
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from vendor_integrity import verify_vendor, source_fingerprint

PINS = {
    "eks": "8a0efdbbc84180a26e0bacfd2b6fcfceac53b3b6",
    "vpc": "7c1f791efd61f326ed6102d564d1a65d1eceedf0",
    "eks.kms": "5508c9cdd6fdb0ed4dcf399f54ba02fb8c31bd4b",
}
PROVIDERS = {"aws", "tls", "time", "cloudinit", "null"}
CLUSTER = "module.eks.aws_eks_cluster.this[0]"
NODE_TEMPLATE = 'module.eks.module.eks_managed_node_group["agent_nodes"].aws_launch_template.this[0]'
DEFAULT_SG = "module.vpc.aws_default_security_group.this[0]"
# Graphs include uninstantiated branches. Require the corresponding instances
# in the evaluated plan as well, and trust these paths only in pristine modules.
PATHS = {
    "cluster security group dependency": (
        "module.eks.aws_eks_cluster.this", "module.eks.aws_security_group.cluster"),
    "node launch-template security group dependency": (
        "module.eks.module.eks_managed_node_group.aws_launch_template.this",
        "module.eks.module.eks_managed_node_group.local.security_group_ids",
        "module.eks.module.eks_managed_node_group.var.vpc_security_group_ids",
        "module.eks.local.node_security_group_id", "module.eks.aws_security_group.node"),
    "NAT allocation dependency": (
        "module.vpc.aws_nat_gateway.this", "module.vpc.local.nat_gateway_ips",
        "module.vpc.aws_eip.nat"),
    "default security group VPC dependency": (
        "module.vpc.aws_default_security_group.this", "module.vpc.aws_vpc.this"),
}
REQUIRED = {
    CLUSTER, NODE_TEMPLATE, DEFAULT_SG,
    "module.eks.aws_security_group.cluster[0]",
    "module.eks.aws_security_group.node[0]",
    "module.vpc.aws_nat_gateway.this[0]", "module.vpc.aws_eip.nat[0]",
    "module.vpc.aws_vpc.this[0]",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(args, cwd, env):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def installed_modules(root, env):
    manifest = json.loads((root / ".terraform/modules/modules.json").read_text())
    modules = {m["Key"]: m for m in manifest["Modules"]}
    evidence = {}
    for name, expected in PINS.items():
        if name == "eks":
            directory = (root / modules[name]["Dir"]).resolve()
            require(directory == (root.parent / "vendor/terraform-aws-eks").resolve()
                    and modules[name]["Source"] == "../vendor/terraform-aws-eks", "Unexpected vendored EKS location")
            evidence[name] = verify_vendor(directory)
            continue
        directory = (root / modules[name]["Dir"]).resolve()
        git = ["git", "-C", str(directory)]
        # Do not accidentally verify the containing project when .git is absent.
        top = Path(command(git + ["rev-parse", "--show-toplevel"], root, env)).resolve()
        require(top == directory, f"{name}: missing independent Git checkout")
        sha = command(git + ["rev-parse", "HEAD"], root, env)
        require(sha == expected, f"{name}: unexpected installed revision {sha}")
        dirty = command(git + ["status", "--porcelain", "--untracked-files=all", "--ignored"], root, env)
        require(not dirty, f"{name}: installed source has modified, untracked or ignored files")
        evidence[name] = {"sha": sha, "source": modules[name]["Source"], "clean": True}
    return evidence


def graph_edges(dot):
    return re.findall(r'"\[root\] ([^"]+)" -> "\[root\] ([^"]+)"', dot)


def find_path(edges, start, end):
    graph = {}
    for source, target in edges:
        graph.setdefault(source, []).append(target)
    start, end = start + " (expand)", end + " (expand)"
    queue, seen = deque([[start]]), {start}
    while queue:
        path = queue.popleft()
        if path[-1] == end:
            return path
        for node in graph.get(path[-1], []):
            if node not in seen:
                seen.add(node)
                queue.append(path + [node])
    raise ValueError(f"Missing dependency path: {start} -> {end}")


def verify_relationships(changes, edges):
    resources = {r["address"]: r for r in changes}
    require(REQUIRED <= resources.keys(), f"Missing planned resources: {sorted(REQUIRED - resources.keys())}")
    for address in REQUIRED:
        require(resources[address]["change"]["actions"] == ["create"], f"Unexpected action for {address}")
    after = resources[CLUSTER]["change"]["after"]
    require(after["encryption_config"][0]["resources"] == ["secrets"], "Secrets encryption not expanded")
    require(not any("cni_ipv6_policy" in address for address in resources), "IPv6 CNI policy/document is instantiated")
    paths = {}
    for label, anchors in PATHS.items():
        paths[label] = [find_path(edges, a, b) for a, b in zip(anchors, anchors[1:])]
    default = resources[DEFAULT_SG]["change"]
    require(not default["after"].get("ingress") and not default["after"].get("egress"),
            "Default security group contains explicitly configured rules")
    return {
        "planned_resources": sorted(resources),
        "secrets_encryption_resources": after["encryption_config"][0]["resources"],
        "ipv6_cni_instances": 0,
        "dependency_paths": paths,
        "default_security_group": {
            "configured_ingress": default["after"].get("ingress"),
            "configured_egress": default["after"].get("egress"),
            "ingress_unknown": default["after_unknown"].get("ingress", False),
            "egress_unknown": default["after_unknown"].get("egress", False),
        },
        "limits": "Mocked plan and dependency evidence; unknown IDs/rules and live enforcement are not verified.",
    }


def negative_controls(changes, edges):
    """Tamper with observed evidence, not infrastructure; reject each defect."""
    cases = []
    missing_encryption = copy.deepcopy(changes)
    next(r for r in missing_encryption if r["address"] == CLUSTER)["change"]["after"]["encryption_config"][0]["resources"] = []
    cases.append(("missing encryption", missing_encryption, edges))
    cases.append(("enabled IPv6 policy", changes + [{"address": "module.eks.aws_iam_policy.cni_ipv6_policy[0]"}], edges))
    for label, address in [("missing launch template", NODE_TEMPLATE), ("missing EIP", "module.vpc.aws_eip.nat[0]")]:
        cases.append((label, [r for r in changes if r["address"] != address], edges))
    for label, anchors in PATHS.items():
        target = anchors[-1] + " (expand)"
        cases.append(("broken " + label, changes, [(a, b) for a, b in edges if b != target]))
    open_group = copy.deepcopy(changes)
    next(r for r in open_group if r["address"] == DEFAULT_SG)["change"]["after"]["ingress"] = [{"cidr_blocks": ["0.0.0.0/0"]}]
    cases.append(("configured default-group ingress", open_group, edges))
    for label, mutated, graph in cases:
        try:
            verify_relationships(mutated, graph)
        except (ValueError, KeyError, IndexError):
            continue
        raise ValueError(f"Negative control was incorrectly accepted: {label}")
    return [label for label, _, _ in cases]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform", default="terraform")
    parser.add_argument("--output", type=Path, default=Path("iac-evidence.json"))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    root = repo / "terraform"
    binary = shutil.which(args.terraform)
    require(binary is not None, "Terraform executable not found")
    binary = str(Path(binary).resolve())
    # Drop AWS_*, TF_VAR_*, CLI configuration, profiles and arbitrary inherited
    # settings. Only PATH and the platform temp directory are needed locally.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "AWS_EC2_METADATA_DISABLED": "true", "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
           "AWS_CONFIG_FILE": os.devnull, "CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "true"}
    if "TMPDIR" in os.environ:
        env["TMPDIR"] = os.environ["TMPDIR"]
    version = json.loads(command([binary, "version", "-json"], root, env))["terraform_version"]
    require(version == "1.9.8", "Review evidence format before changing Terraform 1.9.8")
    modules = installed_modules(root, env)
    lock = (root / ".terraform.lock.hcl").read_text()
    require(set(re.findall(r'provider "([^"]+)"', lock)) ==
            {"registry.terraform.io/hashicorp/" + name for name in PROVIDERS},
            "Review mock coverage after changing providers")
    fixture = repo / "tests/iac/relationships.tftest.hcl"
    fixture_text = fixture.read_text()
    require(set(re.findall(r'^mock_provider "([^"]+)"', fixture_text, re.M)) == PROVIDERS
            and re.findall(r"^\s*command\s*=\s*(\w+)", fixture_text, re.M) == ["plan"]
            and not re.search(r'^\s*provider\s+"', fixture_text, re.M),
            "Fixture must contain only the five mock providers and one plan command")
    with tempfile.TemporaryDirectory(prefix="iac-evidence-") as temporary:
        isolated = Path(temporary) / "terraform"
        isolated.mkdir()
        (Path(temporary) / "vendor").symlink_to(repo / "vendor", target_is_directory=True)
        # Never execute a user's existing tests/state/backend. This repository
        # has no backend; do not add one to this disposable test copy.
        for source in root.glob("*.tf"):
            shutil.copyfile(source, isolated / source.name)
        shutil.copyfile(root / ".terraform.lock.hcl", isolated / ".terraform.lock.hcl")
        (isolated / ".terraform").symlink_to(root / ".terraform", target_is_directory=True)
        (isolated / "tests").mkdir()
        shutil.copyfile(fixture, isolated / "tests/relationships.tftest.hcl")
        raw = isolated / "test.jsonl"
        with raw.open("w") as output:
            process = subprocess.run([binary, "test", "-json", "-verbose"], cwd=isolated, env=env,
                                     stdout=output, check=False)
        plans, summary = [], None
        with raw.open() as output:
            for line in output:
                event = json.loads(line)
                if event["type"] == "test_plan":
                    plans.append(event["test_plan"]["resource_changes"])
                elif event["type"] == "test_summary":
                    summary = event["test_summary"]
                elif event["type"] == "diagnostic" and event["diagnostic"]["severity"] == "error":
                    raise ValueError(event["diagnostic"]["summary"] + ": " + event["diagnostic"].get("detail", ""))
        require(process.returncode == 0 and summary and summary["status"] == "pass"
                and summary["passed"] == 1 and len(plans) == 1,
                "Expected exactly one successful mocked plan")
        expected_cidrs = json.loads(re.search(r"operator_public_access_cidrs\s*=\s*(\[[^\]]*\])", fixture_text)[1])
        cluster = next(r for r in plans[0] if r["address"] == CLUSTER)["change"]["after"]["vpc_config"][0]
        require(cluster["endpoint_public_access"] is True and cluster["endpoint_private_access"] is True
                and cluster["public_access_cidrs"] == expected_cidrs, "Changed mocked endpoint contract")
        logs = [r for r in plans[0] if r["address"] == "module.eks.aws_cloudwatch_log_group.this[0]"]
        require(len(logs) == 1 and logs[0]["change"]["after"]["retention_in_days"] == 90,
                "Changed mocked retention contract")
        dot = command([binary, "graph", "-type=plan"], isolated, env)
        edges, changes = graph_edges(dot), plans[0]
        result = verify_relationships(changes, edges)
        result.update({"evidence_version": 2, "source_fingerprint": source_fingerprint(repo),
                       "terraform_version": version, "installed_modules": modules,
                       "mocked_plan": summary,
                       "demo_contract": {"endpoint_public_access": True, "endpoint_private_access": True,
                                         "cidrs_match_mock_fixture": True, "retention_days": 90,
                                         "operator_cidrs_verified": False},
                       "negative_controls_rejected": negative_controls(changes, edges),
                       "commit": command(["git", "rev-parse", "HEAD"], repo, env)})
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Mocked plan and relationship evidence passed; {len(result['negative_controls_rejected'])} negative controls rejected")
    print("Terraform-installed KMS revision verified: " + modules["eks.kms"]["sha"])
    print(result["limits"])


if __name__ == "__main__":
    main()
