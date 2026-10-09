# Reviewed EKS runtime vendor copy

Upstream: https://github.com/terraform-aws-modules/terraform-aws-eks
Release: v20.37.2
Commit: `8a0efdbbc84180a26e0bacfd2b6fcfceac53b3b6`
License: Apache-2.0; the unmodified upstream LICENSE and README are included.
The upstream tracked tree contains no separate NOTICE file. Existing notices
and attribution in copied files are retained.

This is the runtime subset: root Terraform files; the `_user_data`,
`eks-managed-node-group`, `self-managed-node-group` and `fargate-profile`
submodules (Terraform files and README); and all four user-data templates.
Unreferenced optional modules, examples, upstream tests and CI are omitted.
No external fork or new repository is involved.

The sole upstream code change is in `main.tf`, prominently marked there and
recorded in `kms-source.patch`: replace the KMS registry source/version with
`git::https://github.com/terraform-aws-modules/terraform-aws-kms.git?ref=5508c9cdd6fdb0ed4dcf399f54ba02fb8c31bd4b`.
This is the previously verified KMS v2.1.0 release commit. Key ownership,
selection, permissions, resource defaults and architecture are unchanged.
KMS remains externally downloaded, with its own upstream license intact.

`manifest.json` records upstream and copied SHA-256 hashes for each file.
`scripts/vendor_integrity.py` pins the manifest digest, checks the complete
file inventory and every content hash, and verifies that reversing the one
KMS-source substitution reproduces the upstream main.tf hash. Its optional
`--upstream` argument compares all originals with a pristine checkout of the
commit above. CI checks vendor integrity plus pristine, exact-commit VPC/KMS
checkouts; it does not regenerate or silently update this manifest.

For an update: obtain and review a pristine upstream commit, re-export this
same runtime subset, reproduce and review the single KMS-source patch,
compare every upstream hash, and explicitly review any manifest/integrity
pin changes. Rerun the direct-reference, negative, mocked-plan and full scan
checks. Scanner classifications must be re-reviewed for a new source revision.
