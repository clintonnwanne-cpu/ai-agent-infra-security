data "aws_iam_policy_document" "agent_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:sub"
      values   = ["system:serviceaccount:${var.agent_namespace}:${var.agent_service_account}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ai_agent" {
  name               = "${var.cluster_name}-ai-agent-role"
  assume_role_policy = data.aws_iam_policy_document.agent_trust.json
  description        = "Least-privilege role for AI agent workload"
  tags               = local.common_tags
}

data "aws_iam_policy_document" "agent_allow" {
  statement {
    sid    = "EKSReadOnly"
    effect = "Allow"
    actions = [
      "eks:DescribeCluster",
      "eks:ListClusters",
      "eks:ListNodegroups",
      "eks:DescribeNodegroup",
    ]
    resources = [module.eks.cluster_arn]
  }

  statement {
    sid    = "EC2ReadOnly"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "S3AgentBucketReadWrite"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.agent_state.arn,
      "${aws_s3_bucket.agent_state.arn}/*",
    ]
  }

  statement {
    sid    = "CloudWatchLogsWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:*:log-group:/ai-agent/*"]
  }
}

data "aws_iam_policy_document" "agent_deny" {
  statement {
    sid    = "DenyIAMWrite"
    effect = "Deny"
    actions = [
      "iam:CreateRole",
      "iam:AttachRolePolicy",
      "iam:PutRolePolicy",
      "iam:PassRole",
      "iam:CreateUser",
      "iam:CreateAccessKey",
      "iam:UpdateAssumeRolePolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyEKSWrite"
    effect = "Deny"
    actions = [
      "eks:CreateCluster",
      "eks:DeleteCluster",
      "eks:UpdateClusterConfig",
      "eks:UpdateClusterVersion",
      "eks:CreateNodegroup",
      "eks:DeleteNodegroup",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenySecretsAccess"
    effect = "Deny"
    actions = [
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "kms:Decrypt",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyS3OtherBuckets"
    effect = "Deny"
    actions = ["s3:*"]
    not_resources = [
      aws_s3_bucket.agent_state.arn,
      "${aws_s3_bucket.agent_state.arn}/*",
    ]
  }
}

resource "aws_iam_policy" "agent_allow" {
  name        = "${var.cluster_name}-ai-agent-allow"
  description = "Allowed actions for AI agent role"
  policy      = data.aws_iam_policy_document.agent_allow.json
  tags        = local.common_tags
}

resource "aws_iam_policy" "agent_deny" {
  name        = "${var.cluster_name}-ai-agent-deny"
  description = "Explicit deny guardrails for AI agent role"
  policy      = data.aws_iam_policy_document.agent_deny.json
  tags        = local.common_tags
}

resource "aws_iam_role_policy_attachment" "agent_allow" {
  role       = aws_iam_role.ai_agent.name
  policy_arn = aws_iam_policy.agent_allow.arn
}

resource "aws_iam_role_policy_attachment" "agent_deny" {
  role       = aws_iam_role.ai_agent.name
  policy_arn = aws_iam_policy.agent_deny.arn
}

resource "aws_s3_bucket" "agent_state" {
  bucket        = "${var.cluster_name}-agent-state-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = local.common_tags
}

resource "aws_s3_bucket_versioning" "agent_state" {
  bucket = aws_s3_bucket.agent_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "agent_state" {
  bucket = aws_s3_bucket.agent_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.eks.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "agent_state" {
  bucket                  = aws_s3_bucket.agent_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}
#checkov:skip=CKV_AWS_144:Cross-region replication not required for demo logging bucket
#checkov:skip=CKV_AWS_21:Versioning not required for access logs
#checkov:skip=CKV_AWS_145:Logging bucket uses AES256 - KMS would create circular dependency
#checkov:skip=CKV2_AWS_61:Lifecycle config not required for demo logging bucket
#checkov:skip=CKV2_AWS_62:Event notifications not required for logging bucket
resource "aws_s3_bucket" "agent_logs" {
  bucket        = "${var.cluster_name}-agent-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "agent_logs" {
  bucket                  = aws_s3_bucket.agent_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "agent_state" {
  bucket        = aws_s3_bucket.agent_state.id
  target_bucket = aws_s3_bucket.agent_logs.id
  target_prefix = "access-logs/"
}
