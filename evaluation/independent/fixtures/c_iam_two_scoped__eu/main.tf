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

resource "aws_iam_policy" "scoped" {
  name = "scof-eval-scoped"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:ListBucket"], Resource = ["arn:aws:s3:::scof-eval-reports", "arn:aws:s3:::scof-eval-reports/*"] },
      { Effect = "Allow", Action = ["logs:PutLogEvents"], Resource = ["arn:aws:logs:*:*:log-group:/scof/eval/*"] }
    ]
  })
}
