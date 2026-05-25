#!/usr/bin/env bash
set -euo pipefail

AGENT_NAMESPACE="${AGENT_NAMESPACE:-ai-agent}"
AGENT_SA="${AGENT_SA:-ai-agent-sa}"
AGENT_ROLE_NAME="${AGENT_ROLE_NAME:-ai-agent-security-lab-ai-agent-role}"
ALLOW_POLICY_NAME="${ALLOW_POLICY_NAME:-ai-agent-security-lab-ai-agent-allow}"
DENY_POLICY_NAME="${DENY_POLICY_NAME:-ai-agent-security-lab-ai-agent-deny}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"

DRY_RUN=false
IAM_ONLY=false
K8S_ONLY=false

for arg in "$@"; do
  case $arg in
    --dry-run)   DRY_RUN=true ;;
    --iam-only)  IAM_ONLY=true ;;
    --k8s-only)  K8S_ONLY=true ;;
  esac
done

log()  { echo "[$(date '+%Y-%m-%dT%H:%M:%S')] $*"; }
warn() { echo "[$(date '+%Y-%m-%dT%H:%M:%S')] WARNING: $*" >&2; }

run() {
  if $DRY_RUN; then
    echo "  [DRY RUN] $*"
  else
    "$@"
  fi
}

log "=== AI AGENT KILL SWITCH INITIATED ==="
$DRY_RUN && log "*** DRY RUN MODE — no changes will be made ***"

if ! $IAM_ONLY; then
  log "Step 1/4: Deleting RoleBinding"
  run kubectl delete rolebinding ai-agent-rolebinding \
    -n "$AGENT_NAMESPACE" --ignore-not-found

  log "Step 2/4: Deleting ServiceAccount"
  run kubectl delete serviceaccount "$AGENT_SA" \
    -n "$AGENT_NAMESPACE" --ignore-not-found

  run kubectl delete pods -l app=ai-agent -n "$AGENT_NAMESPACE" --ignore-not-found
fi

if ! $K8S_ONLY; then
  ALLOW_POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${ALLOW_POLICY_NAME}"
  DENY_POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${DENY_POLICY_NAME}"

  log "Step 3/4: Detaching allow policy from IAM role"
  run aws iam detach-role-policy \
    --role-name "$AGENT_ROLE_NAME" \
    --policy-arn "$ALLOW_POLICY_ARN" 2>/dev/null || warn "Allow policy not attached or already removed"

  log "Step 4/4: Detaching deny policy from IAM role"
  run aws iam detach-role-policy \
    --role-name "$AGENT_ROLE_NAME" \
    --policy-arn "$DENY_POLICY_ARN" 2>/dev/null || warn "Deny policy not attached or already removed"
fi

log "=== KILL SWITCH COMPLETE ==="
log "    Kubernetes RBAC : $( $K8S_ONLY && echo 'SKIPPED' || echo 'REVOKED' )"
log "    AWS IAM          : $( $IAM_ONLY && echo 'SKIPPED' || echo 'REVOKED' )"
log ""
log "To restore access: terraform apply"