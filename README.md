# AI Agent Infrastructure Security

Zero-trust security pattern for AI agents running on EKS. Demonstrates
least-privilege IAM, Kubernetes RBAC, network isolation, and an emergency
containment switch. Terraform defines the AWS infrastructure; Kubernetes
manifests define the agent's namespace identity and network controls.

---

## The Problem

AI agents are increasingly being granted IAM roles and Kubernetes
service accounts to automate infrastructure work. Without explicit
least-privilege scoping and a clear revocation path, a compromised
or malfunctioning agent could:

- Escalate its own IAM privileges
- Access secrets across the cluster
- Modify workloads in other namespaces
- Exfiltrate data from unintended S3 buckets

This project shows the pattern for constraining them from day one.

---

## Repository Structure
```
ai-agent-infra-security/
├── terraform/
│   ├── main.tf          # VPC + EKS cluster with KMS encryption
│   ├── iam.tf           # Agent IAM role, allow + deny policies, S3
│   └── variables.tf     # All configurable values
├── k8s/
│   └── rbac.yaml        # Namespace, ServiceAccount, Role, RoleBinding, NetworkPolicy
├── scripts/
│   ├── kill_switch.sh   # Persistent IAM quarantine + Kubernetes cleanup
│   └── verify_aws_containment.py # Baseline and post-shutdown AWS probes
├── tests/               # Offline orchestration and verifier tests
└── .github/
    └── workflows/
        ├── checkov.yml  # Automated IaC security scan on every PR
        └── kill-switch-tests.yml # Offline tests; no cloud credentials
```
---

## Security Controls

### 1. AWS IAM — Least-Privilege with Explicit Denies

Two-policy pattern: an Allow policy granting minimum required
permissions, and a Deny policy that explicitly blocks
the listed escalation actions even if additional Allow policies are added.
This is not a comprehensive block on every IAM write operation.

**Agent ALLOW policy:**
- Read EKS cluster metadata
- Describe EC2 instances, subnets, VPCs
- Read/write one dedicated S3 bucket (encrypted, versioned)
- Write its own CloudWatch logs

**Agent DENY policy (always wins over Allow):**
- Create or modify IAM roles or policies
- Create or delete EKS clusters or node groups
- Access Secrets Manager, SSM Parameter Store, or KMS decrypt
- Access any S3 bucket other than its own

### 2. Kubernetes RBAC — Namespace-Scoped Role

The agent's ServiceAccount is bound to a Role scoped to the
`ai-agent` namespace only. Not a ClusterRole.

```yaml
# Agent CAN:
- get/list/watch pods
- get pod logs
- get/create/update configmaps
- get/list/watch services

# Agent CANNOT:
- access secrets
- see other namespaces
- modify deployments or daemonsets
- create or modify RBAC objects
```

### 3. IRSA — ServiceAccount to IAM Role Binding

Short-lived, auto-rotating credentials via the cluster OIDC
provider. No long-lived access keys anywhere.

### 4. NetworkPolicy — Egress Restriction

The manifest permits outbound TCP 443 and 6443 and UDP 53, without
destination restrictions. It does not restrict port 443 to AWS endpoints.
Ingress is denied if the cluster network implementation enforces NetworkPolicy.

### 5. KMS Encryption

All Kubernetes secrets encrypted at rest with a dedicated KMS key.
Automatic annual key rotation enabled.

---

## Proof of Concept

Example expected RBAC results for the supplied manifest (not a current
live-cluster verification):

```
$ kubectl auth can-i list secrets \
    --namespace ai-agent \
    --as system:serviceaccount:ai-agent:ai-agent-sa
no

$ kubectl auth can-i list pods \
    --namespace ai-agent \
    --as system:serviceaccount:ai-agent:ai-agent-sa
yes

$ kubectl auth can-i list pods \
    --namespace kube-system \
    --as system:serviceaccount:ai-agent:ai-agent-sa
no
```

---

## The Kill Switch

This script requests containment of the **dedicated agent role** and its
namespace identity. It does not promise that all access ends within ten
seconds. AWS IAM changes are eventually consistent; API success and policy
read-back are not proof that every service has enforced the change.
Kubernetes deletion is asynchronous. Neither step undoes completed actions.

The script runs these controls sequentially, with IAM first:

1. Validate the intended AWS account and reject use of the target role as
   the operator. Install the reserved inline policy `AIAgentEmergencyDenyAll`:
   an unconditional `Deny` on `Action: "*"`, `Resource: "*"`.
2. Preserve the existing trust statements and add the reserved statement
   `AIAgentEmergencyDenyAssumption`, denying `AssumeRole`,
   `AssumeRoleWithSAML`, and `AssumeRoleWithWebIdentity` for all principals.
   Read back both policies.
3. Delete the configured namespace RoleBinding and ServiceAccount, and
   request deletion of every pod in that namespace using that ServiceAccount,
   including pods without an `app=ai-agent` label.

**Active AWS sessions:** changing trust alone does not affect previously
issued credentials. The unconditional role policy denies their authorized
requests after propagation and also covers sessions issued during the
trust-policy propagation window. This is permission revocation, not
destruction of STS credentials; credentials retain their expiration.
Unlike a timestamp-only `AWSRevokeOlderSessions` policy, this quarantine has
no issue-time cutoff that could leave later sessions usable. It remains
until an operator explicitly removes it.

**Guardrails:** the managed Allow and Deny policies, permissions boundary
(if any), and unrelated inline policies remain untouched. Repeated runs
replace the same emergency inline policy and maintain one emergency trust
statement. These two names are reserved for this script. Do not share the
agent role with other workloads: quarantine affects all its sessions.

**Failure behavior:** failed controls and read-back mismatches produce a
nonzero exit, preserve visible CLI errors, and do not stop attempts at the
remaining controls. Partial containment is possible. A zero exit means
only that requests completed and IAM read-back matched; the script says
that data-plane containment and pod termination remain unverified.
Unknown options and conflicting `--iam-only --k8s-only` exit before any calls.
`--dry-run` makes no AWS or Kubernetes calls.

### Run

From the repository root, use an independent operator with
`iam:GetRole`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, and
`iam:GetRolePolicy` on the target role. No policy-detachment permission is
needed. The Kubernetes operator needs deletion rights on the target
RoleBinding, ServiceAccount, and pods (and list rights for the pod selector).
Verification additionally needs read/impersonation rights as noted below.

Choose the account and context explicitly; the script does not choose a
cluster from the default context. Set overrides when Terraform resource
names differ from the defaults.

```bash
export AWS_ACCOUNT_ID=630243422167  # replace with the intended account
export K8S_CONTEXT=YOUR_EKS_CONTEXT
export AGENT_ROLE_NAME=ai-agent-security-lab-ai-agent-role
export AGENT_NAMESPACE=ai-agent AGENT_SA=ai-agent-sa
export AGENT_ROLEBINDING=ai-agent-rolebinding

./scripts/kill_switch.sh --dry-run
./scripts/kill_switch.sh             # IAM and Kubernetes
# Alternatively:
./scripts/kill_switch.sh --iam-only  # Kubernetes skipped
./scripts/kill_switch.sh --k8s-only   # AWS IAM skipped
```

### Reproducible offline verification

Requires Bash, jq, and Python 3. No live credentials or cluster are used.
The fake CLIs check operation ordering, policy documents, guardrail
preservation, repeat runs, all control failures, read-back mismatches,
account/operator checks, dry-run, pod selection, and mode reporting.
Verifier tests check denial classification and prevention of credential
refresh/fallback. These tests demonstrate orchestration, not AWS enforcement.

```bash
bash -n scripts/kill_switch.sh
python3 -m unittest discover -s tests -v
```

GitHub Actions runs these independently of Checkov.

### Live AWS verification (disposable lab only)

Run a baseline **before** containment. Use the same saved session afterward;
do not let an SDK obtain replacement credentials. The read-only probe is
`ec2:DescribeInstances`, which the repo allows. S3 object reads are unsuitable
as the sole baseline: the current guardrail denies `kms:Decrypt` while the
state bucket uses KMS encryption.

Also run the Kubernetes baseline check below before executing the kill switch.

The following uses the operator to obtain a one-hour audience-bound
ServiceAccount JWT, then exchanges it for a 15-minute agent session.
Store credential files outside the repo, restrict permissions, and never
commit or print their contents. An STS exchange is non-destructive but
creates a real temporary session.

```bash
umask 077
PROBE_DIR=$(mktemp -d)
export AGENT_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${AGENT_ROLE_NAME}"
export AWS_REGION=us-east-2

kubectl --context "$K8S_CONTEXT" -n "$AGENT_NAMESPACE" create token "$AGENT_SA" \
  --audience sts.amazonaws.com --duration=1h > "$PROBE_DIR/web-identity.jwt"
aws sts assume-role-with-web-identity \
  --region "$AWS_REGION" --role-arn "$AGENT_ROLE_ARN" \
  --role-session-name before-kill-switch --duration-seconds 900 \
  --web-identity-token "file://$PROBE_DIR/web-identity.jwt" \
  --no-sign-request > "$PROBE_DIR/session.json"

python3 scripts/verify_aws_containment.py baseline \
  --credentials-file "$PROBE_DIR/session.json" \
  --token-file "$PROBE_DIR/web-identity.jwt" --role-arn "$AGENT_ROLE_ARN" \
  --region "$AWS_REGION" --evidence-file "$PROBE_DIR/baseline.json"
# STOP if the baseline exits nonzero; it must show both probes succeeding.

./scripts/kill_switch.sh

python3 scripts/verify_aws_containment.py contained \
  --credentials-file "$PROBE_DIR/session.json" \
  --token-file "$PROBE_DIR/web-identity.jwt" --role-arn "$AGENT_ROLE_ARN" \
  --region "$AWS_REGION" --evidence-file "$PROBE_DIR/baseline.json" \
  --timeout 180 --interval 5
```

The verifier checks that captured credentials identify the target role,
binds the successful baseline to hashes of the same credentials/token, and
disables profile, web-identity, metadata, and credential-file fallback for
the old-session probe. It only succeeds when, in one polling iteration,
the old session receives an authorization denial for the EC2 read and
the new web-identity assumption receives `AccessDenied`.
Expired credentials, invalid JWTs, throttling, and network errors do not
count as containment. Timeout is a failed observation, not permission to
declare the agent safe. Complete both phases promptly, well before expiry.

`sts:GetCallerIdentity` can succeed even with an explicit deny, so it is
used only to check identity, never as an access-revocation probe.
The verifier prints UTC observations and elapsed time from **verifier
start**, not a global revocation latency. It covers one session, one
read action, one assumption path, and one region. Test other required
service actions/regions separately using successful baselines.

### Kubernetes checks

Before containment, record a successful namespace pod-list authorization
check. After containment, require `no` for the same identity. Impersonation
requires suitable operator privileges; this tests RBAC, not token validity.

```bash
kubectl --context "$K8S_CONTEXT" auth can-i list pods \
  -n "$AGENT_NAMESPACE" \
  --as "system:serviceaccount:$AGENT_NAMESPACE:$AGENT_SA" \
  --as-group system:serviceaccounts \
  --as-group "system:serviceaccounts:$AGENT_NAMESPACE" \
  --as-group system:authenticated
# Before: yes. After: no (can-i exits nonzero for no).

kubectl --context "$K8S_CONTEXT" get rolebinding "$AGENT_ROLEBINDING" \
  -n "$AGENT_NAMESPACE" --ignore-not-found
kubectl --context "$K8S_CONTEXT" get serviceaccount "$AGENT_SA" \
  -n "$AGENT_NAMESPACE" --ignore-not-found
kubectl --context "$K8S_CONTEXT" get pods \
  --field-selector "spec.serviceAccountName=$AGENT_SA" -n "$AGENT_NAMESPACE"
# Require successful queries, no binding/account, and no matching pods.
# A terminating pod still exists; repeat until absent.
```

For these commands, set `AGENT_ROLEBINDING=ai-agent-rolebinding` unless you
use an override. Check for unexpected RoleBindings/ClusterRoleBindings and
controller/reconciler recreation. Deleting this binding does not remove
other grants to the same identity. Deleting a pod does not guarantee an
unreachable node has stopped its process, and removing RBAC does not close
every existing watch/stream. A real-token API probe and node/workload
inspection are needed if those are part of the containment claim.

### Scope and recovery

This mechanism does not revoke sessions already assumed into **other**
roles, credentials for other identities, presigned capabilities, completed
operations, or data already copied. Investigate those separately. A role
deny is deliberately used instead of merely removing its Allow policy;
implicit deny may be insufficient with resource-policy grants to a session.
`GetCallerIdentity` is an explicit exception to a blanket “all access” claim.

Pause Terraform, Kubernetes controllers, and GitOps reconciliation during
the incident. A Terraform apply may restore the original trust policy;
reapplying `k8s/rbac.yaml` recreates the deleted identities/binding. The
emergency inline deny is not managed by this repo's Terraform, but another
policy manager could remove it. Monitor both emergency controls.

Do **not** treat `terraform apply` as a complete recovery command. Leave
quarantine in place until investigation is complete. The safest lab restart
is a new dedicated role/identity while keeping the old role quarantined.
If recovering the same role, preserve revocation of old sessions: before
removing the unconditional deny, stage and retain an
`AWSRevokeOlderSessions` inline deny using `aws:TokenIssueTime` and a reviewed
UTC cutoff covering every session issued before/during containment.
AWS's console uses a cutoff approximately 30 seconds into the future;
that is not a propagation guarantee. Keep trust blocked while staging
revocation, retain the revocation policy through affected-session expiry,
and ensure no session can slip past the chosen cutoff during recovery.
Review the trust policy and original deny guardrails, then reopen only
under a deliberate recovery plan. Require an old-session denied probe and
a newly issued session's successful baseline action; re-quarantine on any
unexpected old-session success. Do not remove both emergency controls
blindly or automate reopening from a fixed sleep.

AWS references:
- [Revoke IAM role session permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
- [Disabling permissions for temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html)
- [IAM eventual consistency](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot.html#troubleshoot_general_eventual-consistency)
- [GetCallerIdentity exception](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)

---

## IaC Security Scanning

Terraform and Kubernetes run in **independent jobs** on PRs targeting `main`
and pushes to `main`. Each job checks out the event's exact head SHA. A
Terraform failure cannot skip Kubernetes. Findings outside the two exact approved demo exceptions remain hard failures;
there is no blanket skip list or soft-fail configuration. Full JSON reports
are uploaded even when a scan fails. The separate offline test workflow
runs on pushes and PRs without cloud credentials.

CI pins Checkov **3.3.24**, Terraform **1.9.8**, and action commit SHAs.
The root modules are pinned to the commits for VPC **5.21.0** and EKS
**20.37.2**, compatible with the locked AWS provider **5.100.0**. The EKS
module selects KMS **2.1.0** internally. Provider checksums are recorded for
Linux AMD64 and macOS ARM64. Checkov downloads external modules and the
coverage step requires evaluated VPC, EKS, managed-node-group, and KMS
source files at the expected revisions. Missing reports, missing module
coverage, and parsing errors fail that step. `--skip-download` disables
Checkov's platform policy download; `--download-external-modules true`
still enables Terraform module retrieval.

### Verification evidence and remaining findings

Local verification of the required-input/90-day design reproduced the results
below with the pinned tools. Commit-specific remote evidence is available in
[PR checks and downloadable artifacts](https://github.com/clintonnwanne-cpu/ai-agent-infra-security/pull/1/checks).
Earlier evidence at `dd557a5` covered the CI/S3 closeout; it did not test the
new required operator input or exact exception gate.

| Check | Observed result |
|---|---|
| Offline orchestration and verifier suite | 20 tests passed; Bash syntax passed |
| Whitespace and Terraform formatting | Passed |
| Backend-disabled, credential-free Terraform initialization and validation | Passed |
| Terraform Checkov, including external modules | 379 passed, **11 failed**, 5 explicitly skipped, 0 parsing errors; 155 resources |
| Exact demo exception gate | 2 accepted; **9 other findings remain blocking**; raw findings unchanged |
| New gate regression tests | 5 tests passed, including malformed/ambiguous reports, changed settings and unrelated findings |
| Required-input tests | 1 provider-free test passed across 12 cases, including omitted input, invalid ranges and synthetic valid inputs |
| Mocked Terraform evidence | Passed; endpoint/private access, fixture CIDR transfer and 90-day retention checked; existing 9 negative controls passed |
| External-module coverage gate | Passed; 8 evaluated external source files |
| Kubernetes Checkov | 13 passed, 0 failed, 0 skipped, 0 parsing errors; 5 resources |

These results supersede the earlier top-level-only run at `918eaaf`
(73 passed, 10 failed, Kubernetes skipped). Scan counts describe static
source checks, including conditional module resources; they are not an
inventory of deployed resources or proof of live enforcement. See the
[PR checks and downloadable scan reports](https://github.com/clintonnwanne-cpu/ai-agent-infra-security/pull/1/checks)
for commit-specific CI evidence.

All 11 raw Terraform findings remain visible. Exactly two have approved
conditional demo exceptions; the other nine remain blocking:

| Check(s) / occurrences | Assessment and next decision |
|---|---|
| `CKV_AWS_39` / 1 | Approved public-endpoint demo exception on the exact cluster resource, conditional on the required restricted-input contract and private access. See below. |
| `CKV_AWS_38` / 1 | Still blocking: no operator CIDRs have been supplied. The root now requires validated input with no default; Checkov still flags the unresolved module CIDRs. Mocked documentation addresses do not establish deployable settings. |
| `CKV_AWS_338` / 1 | Approved exact log-group exception: explicit 90-day retention for the disposable demo. The one-year rule remains visible in the raw report. |
| `CKV_AWS_58` / 1 | Requires further verification: the root requests secrets encryption, but the scanner flags the module's dynamic encryption block. The credential-free mocked plan expands `resources = ["secrets"]`. The module defaults to creating its own KMS key; do not assume the root-supplied key is selected. Inspect an approved plan and live configuration before claiming the intended key is used. |
| `CKV_TF_1` / 1 | The upstream EKS module references KMS by registry version `2.1.0`, not commit hash. Both the Checkov coverage gate and the Terraform-installed module check verify the retrieved KMS revision, but neither changes that upstream source declaration. |
| `CKV_AWS_111`, `CKV_AWS_356` / 2 | The upstream IPv6 CNI policy document contains wildcard write resources. Its creation is disabled by default (`create_cni_ipv6_iam_policy = false`); the mocked plan contains no policy/document instances, although source scanning still reports it. Review permissions before enabling IPv6. |
| `CKV2_AWS_5` / 2 | Source links cluster/node security groups through locals and node-group inputs. The scanner does not resolve those attachments here. Confirm attachment in an approved plan; these are not accepted security exceptions. |
| `CKV2_AWS_19` / 1 | The VPC EIP is wired to a NAT gateway through `local.nat_gateway_ips`. Checkov 3.3.24 explicitly accepts NAT attachments despite the rule's EC2-focused title; it leaves this allocation expression unresolved. CI checks the planned NAT/EIP instances and dependency path, not live attachment. |
| `CKV2_AWS_12` / 1 | The VPC module defaults to managing the default security group with empty ingress/egress rules. The graph check still flags the VPC. Confirm the effective rules in an approved plan. |

Actual operator CIDRs, upstream module changes, and plan/live verification
remain follow-up work. CI remains red for nine non-exempt findings. No graph,
conditional-policy, encryption or transitive-module-pin exception was added.
A passing coverage gate does not waive findings.

### Required operator input and approved demo design

`operator_public_access_cidrs` is a required, nonnullable IPv4 CIDR list with
**no default**. It rejects an empty list, null elements, malformed ranges,
IPv6 and `/0`. Omitted input fails a noninteractive Terraform plan; there is
no open-access fallback. Public and private EKS API access remain enabled.
The public ranges must be explicitly approved for the actual operator before
any deployment. Syntax validation does not verify ownership, approval or an
appropriate range size; broad or combined ranges still require human review.
No actual operator CIDRs have been supplied or verified in this PR.

Documentation addresses occur only in isolated test fixtures. They must not
be copied into deployment input. CI supplies no operator variable to Checkov
and does not substitute test addresses into the scanned Terraform root.
[AWS documents public CIDR restrictions alongside private endpoint access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html).

CloudWatch control-plane log retention is explicitly **90 days**, as approved
for this disposable demo. Evidence older than 90 days can expire; teardown
can remove the log group sooner. This does not satisfy a one-year retention
requirement. Review retention and durable evidence storage before persistent
or compliance use. S3 object/version retention is unchanged.

`scripts/check_demo_exceptions.py` accepts only these failed check/resource
pairs, with the pinned EKS source and root caller:

- `CKV_AWS_39` — `module.eks.aws_eks_cluster.this`: approved laptop-access
  design, required validated operator input, and private endpoint retained.
  IAM/RBAC is still required; this is not evidence of live restriction.
- `CKV_AWS_338` — `module.eks.aws_cloudwatch_log_group.this[0]`: explicit
  90-day retention with the disposable-demo tradeoff above.

The gate parses root and upstream HCL to verify the required input, exact
validation expression, endpoint settings/wiring and retention setting/wiring.
It rejects missing/ambiguous targets, changed settings, overrides, unexpected
scanner statuses/exits/report shapes, parsing errors and unapproved skips.
Any other failed check remains blocking, including the same check on another
resource. A module-level skip would propagate into descendants, so none was
added. The five existing S3 skips remain separately scoped in `iam.tf`.
The gate does not rewrite raw JSON: artifacts contain both the full findings
and `checkov-demo-exceptions.json` with accepted pairs and blocking findings.

### Credential-free relationship evidence

`python3 scripts/verify_iac_evidence.py` runs after initialization in the
Terraform validation job. It verifies that the installed EKS, VPC and KMS
modules are independent, pristine Git checkouts at the reviewed commits.
In particular, Terraform's own KMS checkout must be
`5508c9cdd6fdb0ed4dcf399f54ba02fb8c31bd4b`; this supplements the scanner's
separate download check. Missing Git metadata, a changed revision, or local
module changes fail closed. It does not make the upstream version-tag
reference immutable or waive `CKV_TF_1`.

The verifier copies the root `.tf` files into a temporary directory and uses
only `tests/iac/relationships.tftest.hcl` for the full root: all five providers are mocked,
`command = plan`, and credentials, profiles and `TF_VAR_*` settings are
removed from the subprocess environment. It executes no apply. The mocked
IAM policy-document values are placeholders; this is not an IAM policy or
AWS authorization test. The existing 20 kill-switch/verifier tests remain
unchanged. A separate provider-free test uses only variable declarations to
check omitted and invalid inputs.

Assertions require expanded secrets encryption, no instantiated IPv6 CNI
policy/document, and the expected cluster, node launch template, security
groups, NAT, EIP and default-group resources. Terraform dependency paths
supply additional source evidence for the network relationships. Explicitly
configured default-group rules fail the check. The report records unknown
computed rules/IDs as unknown: a dependency path can include ordering edges,
and neither a path nor a mocked plan proves live attachment or enforcement.
These checks rely on the reviewed, immutable EKS/VPC source and do not assert
that Checkov must keep producing a particular failure count.

Nine negative controls alter only the captured evidence (remove encryption,
inject an IPv6 policy, remove the launch template/EIP, sever each dependency
path, or inject a default-group rule). Each must be rejected. CI uploads the
compact `iac-relationship-evidence` JSON artifact with the checked commit,
module revisions, dependency paths, unknowns and negative-control outcomes.
The large mocked provider schemas are temporary and are not published.

### Resource-specific demo exceptions and S3 controls

Both `aws_s3_bucket.agent_state` and `aws_s3_bucket.agent_logs` carry
in-resource Checkov comments for `CKV_AWS_144` (no cross-region recovery
target in this disposable, single-region demo) and `CKV2_AWS_62` (no
object-event consumer). These are four explicit exceptions, not production
recommendations; reassess them before persistent use.

Only `aws_s3_bucket.agent_logs` skips `CKV_AWS_145`: AWS requires **SSE-S3**
for S3 server access-log destinations. Explicit `AES256` default encryption
is configured. The old circular-dependency explanation was unsupported and
has been removed. Versioning is enabled on both buckets. Each lifecycle
rule aborts incomplete multipart uploads after seven days, following the
AWS example; it does **not** expire completed objects or historical versions.
The existing `force_destroy = true` makes these buckets disposable and must
be reconsidered before storing durable data.

Log delivery grants only `s3:PutObject` to `logging.s3.amazonaws.com`, only
under `agent_logs/access-logs/*`, with the source bucket ARN and source
account required. Logging depends on the destination policy and encryption
configuration. Delivery is best effort and has not been tested against AWS.
No recursive logging is configured on the destination bucket.

References:
- [AWS log-delivery permissions, destination encryption, and destination logging guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html)
- [AWS incomplete-multipart lifecycle example](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpu-abort-incomplete-mpu-lifecycle-config.html)
- [Checkov resource-level suppression syntax](https://www.checkov.io/2.Basics/Suppressing%20and%20Skipping%20Policies.html)

Reproduce without AWS credentials (module/provider downloads require internet):

```bash
bash -n scripts/kill_switch.sh
python3 -m unittest discover -s tests -v
git diff --check
terraform fmt -check -recursive terraform
terraform -chdir=terraform init -backend=false -input=false -lockfile=readonly
terraform -chdir=terraform validate
terraform fmt -check -recursive tests/iac
python3 scripts/verify_iac_evidence.py
python3 -m pip install checkov==3.3.24
checkov -d terraform --framework terraform --download-external-modules true \
  --external-modules-download-path .external_modules --skip-download \
  --compact -o cli -o json --output-file-path console,checkov-terraform.json
# Run the next commands even when Terraform findings return a nonzero exit.
python3 scripts/check_scan_coverage.py terraform checkov-terraform.json
checkov -d k8s --framework kubernetes --skip-download \
  --compact -o cli -o json --output-file-path console,checkov-kubernetes.json
python3 scripts/check_scan_coverage.py kubernetes checkov-kubernetes.json
```

All evidence above is offline orchestration or static analysis. Live AWS/EKS
containment, network-policy enforcement, S3 log delivery, and agent KMS/S3
functionality remain unverified. The agent's explicit `kms:Decrypt` deny
still conflicts with reading its KMS-encrypted bucket; the live-verification
section intentionally uses an EC2 read baseline. No universal or
under-ten-second revocation claim is supported.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| jq | 1.6+ | https://jqlang.org |
| Python | 3.10+ (verification) | https://www.python.org |
| AWS CLI | v2+ | https://aws.amazon.com/cli |
| Terraform | 1.9.8 tested (>= 1.5.0 required) | https://developer.hashicorp.com/terraform/install |
| kubectl | any | https://kubernetes.io/docs/tasks/tools |
| Checkov | 3.3.24 | `pip3 install checkov==3.3.24` |

---

## Deploy

Before an approved deployment, supply the actual reviewed
`operator_public_access_cidrs` through your Terraform input mechanism.
No value is provided here. Without it, `terraform plan -input=false` fails.
Do not use the mocked documentation addresses. The blocking findings and
live-verification limits above remain unresolved.

```bash
# Configure AWS credentials
aws configure

# Initialize and deploy infrastructure
cd terraform
terraform init
terraform plan -input=false -out=tfplan
terraform apply tfplan

# Connect kubectl to the cluster
aws eks update-kubeconfig \
  --region us-east-2 \
  --name ai-agent-security-lab

# Apply Kubernetes RBAC
kubectl apply -f k8s/rbac.yaml

# Verify RBAC is correctly scoped
kubectl auth can-i list secrets \
  --namespace ai-agent \
  --as system:serviceaccount:ai-agent:ai-agent-sa
# Expected: no

kubectl auth can-i list pods \
  --namespace ai-agent \
  --as system:serviceaccount:ai-agent:ai-agent-sa
# Expected: yes
```

---

## Cleanup

```bash
cd terraform
terraform destroy
```

EKS costs ~$0.10/hour for the control plane plus EC2 node costs.
Destroy when not actively using the cluster.

---

## Author

Clinton Nwanne — Cloud Security Infrastructure Engineer, Atlanta GA
[LinkedIn](https://www.linkedin.com/in/clintonnwanne/) |
[GitHub](https://github.com/clintonnwanne-cpu)
