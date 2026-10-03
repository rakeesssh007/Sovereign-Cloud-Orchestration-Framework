# FIXTURE: non_compliant/s3_aws_managed_key
# EXPECTED RESULT: VIOLATION (key-ownership control)
# INTENTIONAL VIOLATION: uses the AWS-managed key alias/aws/s3 instead of a customer-managed key.
# Regulatory basis: NOT YET VERIFIED (see docs/regulation-mapping).

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

  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_s3_bucket" "data" {
  bucket = "scof-fixture-aws-managed-key-bucket"
  tags = {
    Sector = "finance"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/aws/s3"
    }
  }
}