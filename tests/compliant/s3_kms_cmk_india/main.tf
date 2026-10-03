# FIXTURE: compliant/s3_kms_cmk_india
# EXPECTED RESULT: COMPLIANT
# Controls exercised: region = ap-south-1, S3 SSE uses KMS, customer-managed key.
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

resource "aws_kms_key" "data" {
  description         = "Customer-managed key for finance data"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "data" {
  bucket = "scof-fixture-compliant-bucket"
  tags = {
    Sector = "finance"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}