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
permissions, and a Deny policy that explicitly blocks privilege
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

Checkov runs automatically on every push and pull request via
GitHub Actions. Scans both Terraform and Kubernetes manifests.

Initial scan: 7 findings
After fixes: resolved KMS key policy (CKV2_AWS_64) and S3 access
logging (CKV_AWS_18). Remaining findings documented with rationale.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| jq | 1.6+ | https://jqlang.org |
| Python | 3.10+ (verification) | https://www.python.org |
| AWS CLI | v2+ | https://aws.amazon.com/cli |
| Terraform | >= 1.5.0 | https://developer.hashicorp.com/terraform/install |
| kubectl | any | https://kubernetes.io/docs/tasks/tools |
| Checkov | latest | `pip3 install checkov` |

---

## Deploy

```bash
# Configure AWS credentials
aws configure

# Initialize and deploy infrastructure
cd terraform
terraform init
terraform plan -out=tfplan
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
