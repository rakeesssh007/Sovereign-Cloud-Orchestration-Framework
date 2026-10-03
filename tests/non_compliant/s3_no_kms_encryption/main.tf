# FIXTURE: non_compliant/s3_no_kms_encryption
# EXPECTED RESULT: VIOLATION (encryption control)
# INTENTIONAL VIOLATION: bucket uses SSE-S3 (AES256) instead of KMS.
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
  bucket = "scof-fixture-no-kms-bucket"
  tags = {
    Sector = "finance"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}