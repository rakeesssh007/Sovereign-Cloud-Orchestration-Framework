# Label review sheet (generated from the build spec; the matrix is the reference)

How to use: for each scenario, read the Terraform, the matrix check line, and the label. Tick the three boxes. Do NOT run any evaluator or look at Rego or past result CSVs.

1. **Facts match:** the Terraform below really contains what 'Facts' says.
2. **Label matches the matrix:** under the matrix check line, the intended control is violated (or, for compliant/leakage, nothing is).
3. **Nothing else is violated:** in every context listed, no *other enabled* control is violated, and the provider region is allowed for that context (India region for india contexts, EU region for eu).

Controls enabled per context (from router/policy-routing/control_sets.json): ACCESS-EXPOSURE: india-finance, eu, india-healthcare, india; BACKUP-RESILIENCE: india-finance, eu, india-healthcare, india; DATA-ENCRYPTION: india-finance, eu, india-healthcare, india; IAM-NO-WILDCARD-ADMIN: india-finance, eu, india-healthcare, india; KEY-OWNERSHIP: india-finance, eu, india-healthcare, india; KEY-ROTATION: india-finance, eu, india-healthcare, india; LOG-RETENTION: india-finance, india-healthcare, india; REGION-RESTRICTION: india-finance, eu

## nc_region_s3_us_east_1  (NON-COMPLIANT)

- Intended control: **REGION-RESTRICTION**; expected: **FAIL**
- Regions: us-east-1; contexts: eu, india-finance
- Facts: Provider region us-east-1; S3 bucket with aws:kms CMK, rotation true, all four public-access-block flags true.
- Matrix check (REGION-RESTRICTION): the AWS provider region must be in the allowed list supplied by the routing context. One Rego rule; the router passes the list.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "data" {
  bucket = "scof-eval-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.k.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## nc_region_iam_london  (NON-COMPLIANT)

- Intended control: **REGION-RESTRICTION**; expected: **FAIL**
- Regions: eu-west-2; contexts: eu, india-finance
- Facts: Provider region eu-west-2 (United Kingdom, excluded from the EU list and not India); single scoped IAM policy.
- Matrix check (REGION-RESTRICTION): the AWS provider region must be in the allowed list supplied by the routing context. One Rego rule; the router passes the list.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_iam_policy" "reader" {
  name = "scof-eval-reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::scof-eval-reports/*"] }
    ]
  })
}
```

## nc_enc_s3_aes256  (NON-COMPLIANT)

- Intended control: **DATA-ENCRYPTION**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: S3 bucket encrypted with AES256 (SSE-S3), no KMS; all four public-access-block flags true; no key resources.
- Matrix check (DATA-ENCRYPTION): S3 sse_algorithm is aws:kms; RDS storage_encrypted is true; EC2 root_block_device encrypted is true.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "scof-eval-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## nc_enc_rds_unencrypted  (NON-COMPLIANT)

- Intended control: **DATA-ENCRYPTION**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: RDS instance storage_encrypted = false; backup_retention_period 7; publicly_accessible false; no key references.
- Matrix check (DATA-ENCRYPTION): S3 sse_algorithm is aws:kms; RDS storage_encrypted is true; EC2 root_block_device encrypted is true.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_db_instance" "orders" {
  identifier                  = "scof-eval-orders"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "evaladmin"
  manage_master_user_password = true
  storage_encrypted           = false
  backup_retention_period     = 7
  publicly_accessible         = false
  skip_final_snapshot         = true
}
```

## nc_kown_s3_aws_managed_alias  (NON-COMPLIANT)

- Intended control: **KEY-OWNERSHIP**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: S3 SSE uses aws:kms with the AWS-managed alias alias/aws/s3 (not a customer-managed key); public-access-block flags all true.
- Matrix check (KEY-OWNERSHIP): referenced KMS keys must be customer-managed (an aws_kms_key resource or a CMK ARN), not an AWS-managed alias (alias/aws/*).
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "scof-eval-data-bucket"
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

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## nc_kown_ec2_aws_managed_alias  (NON-COMPLIANT)

- Intended control: **KEY-OWNERSHIP**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: EC2 root_block_device encrypted true with kms_key_id set to the AWS-managed alias alias/aws/ebs (not a customer-managed key); no other resources.
- Matrix check (KEY-OWNERSHIP): referenced KMS keys must be customer-managed (an aws_kms_key resource or a CMK ARN), not an AWS-managed alias (alias/aws/*).
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_instance" "app" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  root_block_device {
    encrypted   = true
    kms_key_id  = "alias/aws/ebs"
  }
}
```

## nc_krot_standalone_key  (NON-COMPLIANT)

- Intended control: **KEY-ROTATION**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: A single aws_kms_key with enable_key_rotation = false (default symmetric key); no other resources.
- Matrix check (KEY-ROTATION): aws_kms_key.enable_key_rotation is true.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "archive" {
  description         = "evaluation key archive"
  enable_key_rotation = false
}
```

## nc_krot_key_used_by_s3  (NON-COMPLIANT)

- Intended control: **KEY-ROTATION**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: Customer-managed key with enable_key_rotation = false referenced by an S3 aws:kms configuration; public-access-block flags all true.
- Matrix check (KEY-ROTATION): aws_kms_key.enable_key_rotation is true.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "bucketkey" {
  description         = "evaluation key bucketkey"
  enable_key_rotation = false
}

resource "aws_s3_bucket" "data" {
  bucket = "scof-eval-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.bucketkey.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## nc_iam_single_statement_admin  (NON-COMPLIANT)

- Intended control: **IAM-NO-WILDCARD-ADMIN**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: One IAM policy with a single Allow statement: Action ["*"] on Resource ["*"].
- Matrix check (IAM-NO-WILDCARD-ADMIN): no IAM policy statement may Allow Action "*" on Resource "*".
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_iam_policy" "admin" {
  name = "scof-eval-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["*"], Resource = ["*"] }
    ]
  })
}
```

## nc_iam_second_statement_admin  (NON-COMPLIANT)

- Intended control: **IAM-NO-WILDCARD-ADMIN**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: One IAM policy with two Allow statements: a scoped s3:GetObject statement first, then Action ["*"] on Resource ["*"].
- Matrix check (IAM-NO-WILDCARD-ADMIN): no IAM policy statement may Allow Action "*" on Resource "*".
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_iam_policy" "mixed" {
  name = "scof-eval-mixed"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::scof-eval-reports/*"] },
      { Effect = "Allow", Action = ["*"], Resource = ["*"] }
    ]
  })
}
```

## nc_log_30_days  (NON-COMPLIANT)

- Intended control: **LOG-RETENTION**; expected: **FAIL**
- Regions: ap-south-1; contexts: india, india-finance, india-healthcare
- Facts: One CloudWatch log group with retention_in_days = 30.
- Matrix check (LOG-RETENTION): aws_cloudwatch_log_group.retention_in_days must be at least 365. An absent value or 0 (never expires) passes.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_cloudwatch_log_group" "audit" {
  name = "/scof/eval/audit"
  retention_in_days = 30
}
```

## nc_log_mixed_groups  (NON-COMPLIANT)

- Intended control: **LOG-RETENTION**; expected: **FAIL**
- Regions: ap-south-1; contexts: india, india-finance, india-healthcare
- Facts: Two CloudWatch log groups: one with retention_in_days = 180, one with 365.
- Matrix check (LOG-RETENTION): aws_cloudwatch_log_group.retention_in_days must be at least 365. An absent value or 0 (never expires) passes.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_cloudwatch_log_group" "short" {
  name = "/scof/eval/short"
  retention_in_days = 180
}

resource "aws_cloudwatch_log_group" "long" {
  name = "/scof/eval/long"
  retention_in_days = 365
}
```

## nc_acc_s3_block_policy_false  (NON-COMPLIANT)

- Intended control: **ACCESS-EXPOSURE**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: S3 public-access-block with block_public_policy = false and the other three flags true; aws:kms CMK with rotation true.
- Matrix check (ACCESS-EXPOSURE): no aws_s3_bucket_public_access_block has any of block_public_acls, block_public_policy, ignore_public_acls or restrict_public_buckets set to false, and no aws_db_instance has publicly_accessible set to true.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "scof-eval-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.k.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}
```

## nc_acc_rds_public  (NON-COMPLIANT)

- Intended control: **ACCESS-EXPOSURE**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: RDS instance with publicly_accessible = true; storage encrypted with CMK (rotation true); backup 7.
- Matrix check (ACCESS-EXPOSURE): no aws_s3_bucket_public_access_block has any of block_public_acls, block_public_policy, ignore_public_acls or restrict_public_buckets set to false, and no aws_db_instance has publicly_accessible set to true.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_db_instance" "customers" {
  identifier                  = "scof-eval-customers"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "evaladmin"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.k.arn
  backup_retention_period     = 7
  publicly_accessible         = true
  skip_final_snapshot         = true
}
```

## nc_bkp_zero_days  (NON-COMPLIANT)

- Intended control: **BACKUP-RESILIENCE**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: RDS backup_retention_period = 0 (automated backups disabled); encrypted with CMK (rotation true); not public.
- Matrix check (BACKUP-RESILIENCE): aws_db_instance.backup_retention_period must be set explicitly to at least 1. A value below 1 is denied. An omitted value is denied too: the plan reports it as unknown until apply, and the AWS provider documents a default of 0, which disables automated backups ([provider documentation, read 2026-10-05](https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/db_instance.html.markdown)).
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_db_instance" "payments" {
  identifier                  = "scof-eval-payments"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "evaladmin"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.k.arn
  backup_retention_period     = 0
  publicly_accessible         = false
  skip_final_snapshot         = true
}
```

## nc_bkp_omitted  (NON-COMPLIANT)

- Intended control: **BACKUP-RESILIENCE**; expected: **FAIL**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: RDS backup_retention_period omitted (unknown at plan time; provider default 0); encrypted with CMK (rotation true); not public.
- Matrix check (BACKUP-RESILIENCE): aws_db_instance.backup_retention_period must be set explicitly to at least 1. A value below 1 is denied. An omitted value is denied too: the plan reports it as unknown until apply, and the AWS provider documents a default of 0, which disables automated backups ([provider documentation, read 2026-10-05](https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/db_instance.html.markdown)).
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_db_instance" "claims" {
  identifier                  = "scof-eval-claims"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "evaladmin"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.k.arn
  publicly_accessible         = false
  skip_final_snapshot         = true
}
```

## c_s3_kms_cmk  (COMPLIANT)

- Intended control: **none (all enabled controls must pass)**; expected: **PASS**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: S3 bucket, aws:kms with a customer-managed key (rotation true), all four public-access-block flags true.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "docs" {
  bucket = "scof-eval-docs-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "docs" {
  bucket = aws_s3_bucket.docs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.k.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "docs" {
  bucket                  = aws_s3_bucket.docs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## c_rds_cmk_backup14  (COMPLIANT)

- Intended control: **none (all enabled controls must pass)**; expected: **PASS**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: RDS encrypted with a CMK (rotation true), backup_retention_period 14, publicly_accessible false.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_db_instance" "accounts" {
  identifier                  = "scof-eval-accounts"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "evaladmin"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.k.arn
  backup_retention_period     = 14
  publicly_accessible         = false
  skip_final_snapshot         = true
}
```

## c_ec2_cmk_root  (COMPLIANT)

- Intended control: **none (all enabled controls must pass)**; expected: **PASS**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: EC2 instance, root_block_device encrypted true with a customer-managed key (rotation true).
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "ebs" {
  description         = "evaluation key ebs"
  enable_key_rotation = true
}

resource "aws_instance" "app" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs.arn
  }
}
```

## c_iam_two_scoped  (COMPLIANT)

- Intended control: **none (all enabled controls must pass)**; expected: **PASS**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: One IAM policy with two scoped Allow statements; no wildcard action on wildcard resource.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
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
```

## c_log_400_days  (COMPLIANT)

- Intended control: **none (all enabled controls must pass)**; expected: **PASS**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: One CloudWatch log group with retention_in_days = 400.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_cloudwatch_log_group" "app" {
  name = "/scof/eval/app"
  retention_in_days = 400
}
```

## c_multi_data_tier  (COMPLIANT)

- Intended control: **none (all enabled controls must pass)**; expected: **PASS**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: KMS key (rotation true), S3 aws:kms bucket with all public-access-block flags true, encrypted RDS (backup 7, not public), log group at exactly 365 days.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "lake" {
  bucket = "scof-eval-lake-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lake" {
  bucket = aws_s3_bucket.lake.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.k.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "lake" {
  bucket                  = aws_s3_bucket.lake.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "core" {
  identifier                  = "scof-eval-core"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "evaladmin"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.k.arn
  backup_retention_period     = 7
  publicly_accessible         = false
  skip_final_snapshot         = true
}

resource "aws_cloudwatch_log_group" "core" {
  name = "/scof/eval/core"
  retention_in_days = 365
}
```

## c_multi_identity_logs  (COMPLIANT)

- Intended control: **none (all enabled controls must pass)**; expected: **PASS**
- Regions: ap-south-1, eu-west-1; contexts: eu, india, india-finance, india-healthcare
- Facts: KMS key (rotation true), IAM policy with a scoped action on all resources (not an admin wildcard), log group with retention omitted (never expires).
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
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
```

## Leakage rows (expected: no finding at all)

- [ ] `nc_log_30_days` under `eu` (region eu-west-1): LOG-RETENTION is not enabled in eu: a 30-day log group in an EU region must produce no finding
- [ ] `nc_region_s3_us_east_1` under `india-healthcare` (region us-east-1): REGION-RESTRICTION is not enabled in india-healthcare: a us-east-1 plan must produce no REGION-RESTRICTION finding and no other finding
- [ ] `nc_region_s3_us_east_1` under `india` (region us-east-1): REGION-RESTRICTION is not enabled in the sector-neutral india context: a us-east-1 plan must produce no REGION-RESTRICTION finding and no other finding
