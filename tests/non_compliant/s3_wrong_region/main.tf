# FIXTURE: non_compliant/s3_wrong_region
# EXPECTED RESULT: VIOLATION (region / data-residency control)
# INTENTIONAL VIOLATION: deployed in us-east-1 for an India-jurisdiction finance workload.
# Regulatory basis for any residency rule: NOT YET VERIFIED (see docs/regulation-mapping).

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
  region = "us-east-1"

  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_kms_key" "data" {
  description         = "Customer-managed key for finance data"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "data" {
  bucket = "scof-fixture-wrong-region-bucket"
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