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
resource "aws_kms_key" "rds" {
  description         = "CMK for RDS storage encryption (fixture)"
  enable_key_rotation = true
}

resource "aws_db_instance" "finance" {
  backup_retention_period     = 7
  publicly_accessible = true
  identifier                  = "scof-finance-db"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "dbadmin"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.rds.arn
  skip_final_snapshot         = true
}