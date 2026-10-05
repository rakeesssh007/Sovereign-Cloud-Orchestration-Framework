variable "offline_plan" {
  description = "When true, the AWS provider skips all credential/account lookups so terraform plan runs with no AWS account. Set false only when using real credentials."
  type        = bool
  default     = true
}

variable "bucket_name" {
  description = "Name of the S3 bucket the public access block applies to (the bucket itself is not created here)."
  type        = string
  default     = "scof-ref-finance-audit-bucket"
}

variable "log_group_name" {
  description = "Name of the CloudWatch log group."
  type        = string
  default     = "/scof/ref/audit"
}
