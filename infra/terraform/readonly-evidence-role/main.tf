# OPTIONAL — not used by the default application and never applied by this project.
#
# A least-privilege, read-only IAM role a future RecoveryProof collector could assume
# to gather backup *metadata* (never backup contents). It grants no write, delete,
# restore or IAM permissions. Review with your security team before use; creating an
# IAM role is free, but API calls and any CloudTrail lookups may be billed.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 7.0"
    }
  }
}

variable "trusted_principal_arn" {
  description = "ARN of the principal (user/role) allowed to assume this role."
  type        = string
}

variable "external_id" {
  description = "External ID required in sts:AssumeRole to prevent confused-deputy use."
  type        = string
  sensitive   = true
}

variable "role_name" {
  type    = string
  default = "recoveryproof-readonly-evidence"
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.trusted_principal_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

data "aws_iam_policy_document" "readonly_metadata" {
  statement {
    sid = "BackupMetadata"
    actions = [
      "backup:ListBackupVaults",
      "backup:DescribeBackupVault",
      "backup:ListRecoveryPointsByBackupVault",
      "backup:DescribeRecoveryPoint",
      "backup:ListRestoreJobs",
      "backup:DescribeRestoreJob",
      "backup:GetBackupVaultAccessPolicy",
      "backup:ListBackupPlans",
      "backup:GetBackupPlan",
    ]
    resources = ["*"]
  }
  statement {
    sid = "S3ProtectionMetadata"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketObjectLockConfiguration",
      "s3:GetBucketVersioning",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketPolicy",
      "s3:GetLifecycleConfiguration",
    ]
    resources = ["*"]
  }
  statement {
    sid = "InventoryMetadata"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSnapshots",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSnapshots",
      "kms:DescribeKey",
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "readonly_evidence" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags = {
    Purpose = "RecoveryProof read-only evidence collection"
  }
}

resource "aws_iam_role_policy" "readonly_metadata" {
  name   = "readonly-backup-metadata"
  role   = aws_iam_role.readonly_evidence.id
  policy = data.aws_iam_policy_document.readonly_metadata.json
}

output "role_arn" {
  value = aws_iam_role.readonly_evidence.arn
}
