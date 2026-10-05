terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"

  # Plan-only mode: no AWS account needed. Dummy credentials come from
  # environment variables, never from this file.
  skip_credentials_validation = var.offline_plan
  skip_requesting_account_id  = var.offline_plan
  skip_metadata_api_check     = var.offline_plan
}

# Audit logs are kept for at least one year (LOG-RETENTION).
resource "aws_cloudwatch_log_group" "audit" {
  name              = var.log_group_name
  retention_in_days = 365
}

# Public access to the data bucket is fully blocked (ACCESS-EXPOSURE).
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = var.bucket_name
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
