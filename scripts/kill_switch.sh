#!/usr/bin/env bash
# Contain the dedicated agent role; never remove its existing deny guardrails.
set -euo pipefail
export AWS_PAGER=""

AGENT_NAMESPACE="${AGENT_NAMESPACE:-ai-agent}"
AGENT_SA="${AGENT_SA:-ai-agent-sa}"
AGENT_ROLEBINDING="${AGENT_ROLEBINDING:-ai-agent-rolebinding}"
AGENT_ROLE_NAME="${AGENT_ROLE_NAME:-ai-agent-security-lab-ai-agent-role}"
# Reserved for this script, independent of Terraform's managed allow/deny policies.
QUARANTINE_POLICY_NAME=AIAgentEmergencyDenyAll
TRUST_DENY_SID=AIAgentEmergencyDenyAssumption
DRY_RUN=false
IAM_ONLY=false
K8S_ONLY=false
FAILURES=0

log() { printf '%s\n' "$*"; }
error() { printf 'ERROR: %s\n' "$*" >&2; }
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --iam-only) IAM_ONLY=true ;;
    --k8s-only) K8S_ONLY=true ;;
    --help)
      log 'Usage: kill_switch.sh [--dry-run] [--iam-only | --k8s-only]'
      log 'Live IAM requires AWS_ACCOUNT_ID; live Kubernetes requires K8S_CONTEXT.'
      exit 0 ;;
    *) error "Unknown option: $arg"; exit 2 ;;
  esac
done
if $IAM_ONLY && $K8S_ONLY; then
  error '--iam-only and --k8s-only are mutually exclusive'; exit 2
fi

# A real failure stays visible, but does not prevent other containment steps.
attempt() {
  if "$@"; then return 0; fi
  error "Control failed: $*"
  FAILURES=$((FAILURES + 1))
  return 0
}

contain_iam() {
  command -v aws >/dev/null || { error 'aws is required'; return 1; }
  command -v jq >/dev/null || { error 'jq is required'; return 1; }
  [[ ${AWS_ACCOUNT_ID:-} =~ ^[0-9]{12}$ ]] || {
    error 'Set AWS_ACCOUNT_ID to the intended 12-digit account'; return 1;
  }
  local role caller arn account caller_arn partition trust quarantine blocked
  role=$(aws iam get-role --role-name "$AGENT_ROLE_NAME" --output json) || return 1
  caller=$(aws sts get-caller-identity --output json) || return 1
  arn=$(jq -er '.Role.Arn' <<< "$role") || return 1
  account=$(jq -er '.Account' <<< "$caller") || return 1
  caller_arn=$(jq -er '.Arn' <<< "$caller") || return 1
  partition=$(cut -d: -f2 <<< "$arn")
  if [[ $account != "$AWS_ACCOUNT_ID" || $arn != arn:"$partition":iam::"$AWS_ACCOUNT_ID":role/* ]]; then
    error 'Operator account or target role differs from AWS_ACCOUNT_ID'; return 1
  fi
  if [[ $caller_arn == arn:"$partition":sts::"$AWS_ACCOUNT_ID":assumed-role/"$AGENT_ROLE_NAME"/* ]]; then
    error 'Use an independent operator identity, not the target agent role'; return 1
  fi
  trust=$(jq -ce '.Role.AssumeRolePolicyDocument | select(.Version == "2012-10-17" and .Statement != null)' <<< "$role") || return 1
  quarantine='{"Version":"2012-10-17","Statement":[{"Sid":"DenyAllDuringQuarantine","Effect":"Deny","Action":"*","Resource":"*"}]}'
  blocked=$(jq -c --arg sid "$TRUST_DENY_SID" '
    .Statement = ((.Statement | if type == "array" then . else [.] end)
      | map(select(.Sid != $sid))) + [{Sid:$sid,Effect:"Deny",Principal:"*",
      Action:["sts:AssumeRole","sts:AssumeRoleWithSAML","sts:AssumeRoleWithWebIdentity"]}]' <<< "$trust") || return 1

  log "IAM target: $arn"
  # Deny existing sessions AND sessions issued during trust-policy propagation.
  # No timestamp cutoff can leave later sessions usable while quarantine remains.
  attempt aws iam put-role-policy --role-name "$AGENT_ROLE_NAME" \
    --policy-name "$QUARANTINE_POLICY_NAME" --policy-document "$quarantine"
  attempt aws iam update-assume-role-policy --role-name "$AGENT_ROLE_NAME" \
    --policy-document "$blocked"

  # Read-back is configuration evidence, NOT proof of data-plane propagation.
  local actual_policy actual_trust
  if actual_policy=$(aws iam get-role-policy --role-name "$AGENT_ROLE_NAME" \
      --policy-name "$QUARANTINE_POLICY_NAME" --output json) && \
     jq -e --argjson expected "$quarantine" '.PolicyDocument == $expected' <<< "$actual_policy" >/dev/null; then
    log 'IAM quarantine policy read-back matched.'
  else
    error 'IAM quarantine policy read-back failed'; FAILURES=$((FAILURES + 1))
  fi
  if actual_trust=$(aws iam get-role --role-name "$AGENT_ROLE_NAME" --output json) && \
     jq -e --argjson expected "$blocked" '.Role.AssumeRolePolicyDocument == $expected' <<< "$actual_trust" >/dev/null; then
    log 'IAM trust policy read-back matched.'
  else
    error 'IAM trust policy read-back failed'; FAILURES=$((FAILURES + 1))
  fi
}

contain_k8s() {
  command -v kubectl >/dev/null || { error 'kubectl is required'; return 1; }
  [[ -n ${K8S_CONTEXT:-} ]] || { error 'Set K8S_CONTEXT to the intended cluster context'; return 1; }
  local -a kube=(kubectl --context "$K8S_CONTEXT" --request-timeout=15s)
  log "Kubernetes target: $K8S_CONTEXT / $AGENT_NAMESPACE / $AGENT_SA"
  attempt "${kube[@]}" delete rolebinding "$AGENT_ROLEBINDING" -n "$AGENT_NAMESPACE" --ignore-not-found --wait=false
  attempt "${kube[@]}" delete serviceaccount "$AGENT_SA" -n "$AGENT_NAMESPACE" --ignore-not-found --wait=false
  # Match the identity, not a label an agent could lack or change.
  attempt "${kube[@]}" delete pods --field-selector "spec.serviceAccountName=$AGENT_SA" \
    -n "$AGENT_NAMESPACE" --ignore-not-found --wait=false
}

log '=== AI AGENT CONTAINMENT ==='
if $DRY_RUN; then
  log 'DRY RUN: no AWS or Kubernetes calls will be made.'
  if ! $K8S_ONLY; then
    log "IAM: validate AWS_ACCOUNT_ID and independent operator; target $AGENT_ROLE_NAME"
    log "IAM: put $QUARANTINE_POLICY_NAME (Deny * on *), then add $TRUST_DENY_SID to trust; read back both. Preserve all managed policies."
  else log 'AWS IAM: SKIPPED'; fi
  if ! $IAM_ONLY; then
    log "Kubernetes: context ${K8S_CONTEXT:-<required>}; delete $AGENT_ROLEBINDING, $AGENT_SA, and pods using $AGENT_SA in $AGENT_NAMESPACE"
  else log 'Kubernetes: SKIPPED'; fi
  exit 0
fi

# IAM first, so a slow/unreachable cluster does not delay AWS containment.
if ! $K8S_ONLY; then attempt contain_iam; else log 'AWS IAM: SKIPPED'; fi
if ! $IAM_ONLY; then attempt contain_k8s; else log 'Kubernetes: SKIPPED'; fi
if (( FAILURES > 0 )); then
  error "Containment incomplete: $FAILURES failed controls/checks. Review errors and retry."
  exit 1
fi
log 'Requested controls completed. Data-plane containment and pod termination are NOT verified.'
log 'Run the README live verification procedure; there is no fixed revocation-time guarantee.'
log 'Quarantine persists until explicit recovery. terraform apply alone is not a recovery procedure.'
