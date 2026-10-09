"""Verify the reviewed runtime subset and sole upstream KMS source patch."""
import argparse
import hashlib
import difflib
import json
from pathlib import Path
import subprocess

EKS_PIN = "8a0efdbbc84180a26e0bacfd2b6fcfceac53b3b6"
KMS_PIN = "5508c9cdd6fdb0ed4dcf399f54ba02fb8c31bd4b"
MANIFEST_SHA256 = "a738fa79390c42966edf96fda8bc0e7d4b120fdb65aa7bb6db6d34f85d0f0fbf"
OLD = '  source  = "terraform-aws-modules/kms/aws"\n  version = "2.1.0" # Note - be mindful of Terraform/provider version compatibility between modules'
NEW = ('  # Local modification: pin the same KMS 2.1.0 release to its immutable commit.\n'
       '  # See PROVENANCE.md; no key-selection or resource behavior changes.\n'
       '  source = "git::https://github.com/terraform-aws-modules/terraform-aws-kms.git?ref=' + KMS_PIN + '"')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_vendor(directory, upstream=None):
    raw = (directory / "manifest.json").read_bytes()
    require(digest(raw) == MANIFEST_SHA256, "Unreviewed vendor manifest")
    manifest = json.loads(raw)
    require(manifest["upstream_commit"] == EKS_PIN and manifest["kms_commit"] == KMS_PIN,
            "Changed vendor revisions")
    inventory = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
    require(not any(p.is_symlink() for p in directory.rglob("*")), "Vendor symlink is not permitted")
    require(inventory == set(manifest["files"]) | {"manifest.json", "PROVENANCE.md", "kms-source.patch"},
            "Missing or unexpected vendor file")
    if upstream:
        require(subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip() == EKS_PIN,
                "Wrong upstream revision")
        require(not subprocess.check_output(["git", "-C", str(upstream), "status", "--porcelain", "--untracked-files=all", "--ignored"], text=True).strip(),
                "Upstream checkout is not pristine")
    for name, hashes in manifest["files"].items():
        data = (directory / name).read_bytes()
        require(digest(data) == hashes["sha256"], "Modified vendor file: " + name)
        original = data
        if name == "main.tf":
            require(data.decode().count(NEW) == 1, "Missing or ambiguous KMS source patch")
            original = data.decode().replace(NEW, OLD).encode()
            patch = "".join(difflib.unified_diff(original.decode().splitlines(True), data.decode().splitlines(True),
                                                fromfile="a/main.tf", tofile="b/main.tf"))
            require((directory / "kms-source.patch").read_text() == patch, "Incorrect recorded vendor patch")
        require(digest(original) == hashes["upstream_sha256"], "Unexpected upstream difference: " + name)
        if upstream:
            require(original == (upstream / name).read_bytes(), "Upstream content mismatch: " + name)
    return {"sha": EKS_PIN, "source": "../vendor/terraform-aws-eks", "clean": True,
            "manifest_sha256": MANIFEST_SHA256, "kms_source_commit": KMS_PIN}


def source_fingerprint(repo):
    """Bind evidence to actual root inputs, provider lock and reviewed vendor."""
    paths = sorted((repo / "terraform").glob("*.tf")) + [repo / "terraform/.terraform.lock.hcl"]
    values = {p.relative_to(repo).as_posix(): digest(p.read_bytes()) for p in paths}
    values["vendor_manifest"] = verify_vendor(repo / "vendor/terraform-aws-eks")["manifest_sha256"]
    return digest(json.dumps(values, sort_keys=True).encode())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_vendor(Path(__file__).resolve().parents[1] / "vendor/terraform-aws-eks", args.upstream), indent=2))
