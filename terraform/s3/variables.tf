variable "aws_region" {
  description = "AWS region for deployment (jurisdiction-relevant control)."
  type        = string
  default     = "ap-south-1"
}

variable "offline_plan" {
  description = "When true, the AWS provider skips all credential/account lookups so terraform plan runs with no AWS account. Set false only when using real credentials."
  type        = bool
  default     = true
}

variable "bucket_name" {
  description = "Name of the S3 bucket (not created unless applied)."
  type        = string
  default     = "scof-ref-finance-data-bucket"
}
