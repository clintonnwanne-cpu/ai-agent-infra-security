# AI Agent Infrastructure Security

Zero-trust security pattern for AI agents running on EKS. Demonstrates
least-privilege IAM, Kubernetes RBAC, network isolation, and a hard
kill switch; all provisioned with Terraform.

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
│   └── kill_switch.sh   # Revoke all agent access in under 10 seconds
└── .github/
    └── workflows/
        └── checkov.yml  # Automated IaC security scan on every PR
```
---

## Security Controls

### 1. AWS IAM — Least-Privilege with Explicit Denies

Two-policy pattern: an Allow policy granting minimum required
permissions, and a Deny policy that explicitly blocks privilege
escalation paths regardless of any future Allow policies added.

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

Agent pods: outbound port 443 (AWS APIs) and port 53 (DNS) only.
All inbound connections blocked.

### 5. KMS Encryption

All Kubernetes secrets encrypted at rest with a dedicated KMS key.
Automatic annual key rotation enabled.

---

## Proof of Concept

RBAC verification against the live cluster:

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

Single script. Revokes both Kubernetes RBAC and AWS IAM
simultaneously. Agent loses all access in under 10 seconds.

$ ../scripts/kill_switch.sh
[2026-05-25T21:00:59] === AI AGENT KILL SWITCH INITIATED ===
[2026-05-25T21:00:59] Step 1/4: Deleting RoleBinding
rolebinding "ai-agent-rolebinding" deleted from ai-agent namespace
[2026-05-25T21:01:00] Step 2/4: Deleting ServiceAccount
serviceaccount "ai-agent-sa" deleted from ai-agent namespace
[2026-05-25T21:01:02] Step 3/4: Detaching allow policy from IAM role
[2026-05-25T21:01:03] Step 4/4: Detaching deny policy from IAM role
[2026-05-25T21:01:04] === KILL SWITCH COMPLETE ===
[2026-05-25T21:01:04]     Kubernetes RBAC : REVOKED
[2026-05-25T21:01:04]     AWS IAM         : REVOKED
[2026-05-25T21:01:04] To restore access: terraform apply

Options:
```bash
./scripts/kill_switch.sh --dry-run    # preview without changes
./scripts/kill_switch.sh --iam-only   # revoke AWS access only
./scripts/kill_switch.sh --k8s-only   # revoke cluster access only
```

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
