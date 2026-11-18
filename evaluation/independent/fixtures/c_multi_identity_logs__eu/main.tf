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
  region                      = "eu-west-1"
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

resource "aws_iam_policy" "ops" {
  name = "scof-eval-ops"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["cloudwatch:GetMetricData"], Resource = ["*"] }
    ]
  })
}

resource "aws_cloudwatch_log_group" "ops" {
  name = "/scof/eval/ops"
}
