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
  region                      = "ap-south-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "shut" {
  bucket = "scof-eval-shut-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "shut" {
  bucket = aws_s3_bucket.shut.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.k.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "shut" {
  bucket                  = aws_s3_bucket.shut.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "wide" {
  bucket = "scof-eval-wide-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "wide" {
  bucket = aws_s3_bucket.wide.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.k.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "wide" {
  bucket                  = aws_s3_bucket.wide.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
