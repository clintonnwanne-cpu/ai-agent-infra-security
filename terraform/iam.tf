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
    sid     = "DenyS3OtherBuckets"
    effect  = "Deny"
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
  #checkov:skip=CKV_AWS_144:Disposable single-region demo; no cross-region recovery target. Reassess before persistent use.
  #checkov:skip=CKV2_AWS_62:Disposable demo has no object-event consumer; access logs are configured separately. Reassess before persistent use.
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
resource "aws_s3_bucket" "agent_logs" {
  #checkov:skip=CKV_AWS_144:Disposable single-region demo; no cross-region recovery target. Reassess before persistent use.
  #checkov:skip=CKV2_AWS_62:Disposable demo has no log-object event consumer. Reassess before persistent use.
  #checkov:skip=CKV_AWS_145:S3 server access-log destinations require SSE-S3, configured explicitly below; see AWS enable-server-access-logging documentation.
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
  depends_on = [
    aws_s3_bucket_policy.agent_logs,
    aws_s3_bucket_server_side_encryption_configuration.agent_logs,
  ]
}

resource "aws_s3_bucket_versioning" "agent_logs" {
  bucket = aws_s3_bucket.agent_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "agent_logs" {
  bucket = aws_s3_bucket.agent_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Abort unfinished uploads only; do not expire objects or historical versions.
# Seven days follows the AWS incomplete-multipart lifecycle example.
resource "aws_s3_bucket_lifecycle_configuration" "agent_state" {
  bucket = aws_s3_bucket.agent_state.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "agent_logs" {
  bucket = aws_s3_bucket.agent_logs.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "agent_log_delivery" {
  statement {
    sid       = "S3ServerAccessLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.agent_logs.arn}/access-logs/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.agent_state.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "agent_logs" {
  bucket = aws_s3_bucket.agent_logs.id
  policy = data.aws_iam_policy_document.agent_log_delivery.json
}
