# Exploratory label review sheet

These 11 scenarios are reported separately and are NOT part of the 89-row headline set. Review them the same way (facts match, label matches the matrix, nothing else violated). Reference: the matrix 'Check' and 'Limits' lines shown.

- X1_BOUNDARY: labels follow the matrix check line.
- X2_DECLARED_GAP: the matrix itself lists these as outside the control's scope, or a documented heuristic may miss a literal reading. A miss confirms a known limitation; it is not tuned away.

## x1_log_180_days_nearest_below  (X1_BOUNDARY)

- Context: india-finance, region ap-south-1; expected: **FAIL**; intended control: **LOG-RETENTION**
- Facts: One log group with retention_in_days = 180, the largest provider-valid value below 365 (the AWS provider only accepts fixed values such as 180, 365, 400, so 364 cannot occur in a real plan).
- Matrix check (LOG-RETENTION): aws_cloudwatch_log_group.retention_in_days must be at least 365. An absent value or 0 (never expires) passes.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_cloudwatch_log_group" "audit" {
  name = "/scof/eval/audit"
  retention_in_days = 180
}
```

## x1_log_365_days_exact  (X1_BOUNDARY)

- Context: india-finance, region ap-south-1; expected: **PASS**; intended control: **none (all enabled controls must pass)**
- Facts: One log group with retention_in_days = 365, exactly at the baseline (matrix: at least 365).
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_cloudwatch_log_group" "audit" {
  name = "/scof/eval/audit"
  retention_in_days = 365
}
```

## x1_backup_one_day  (X1_BOUNDARY)

- Context: india-finance, region ap-south-1; expected: **PASS**; intended control: **none (all enabled controls must pass)**
- Facts: RDS backup_retention_period = 1, exactly at the SCOF baseline (matrix: at least 1); encrypted with a rotating CMK; not public.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_kms_key" "k" {
  description         = "evaluation key k"
  enable_key_rotation = true
}

resource "aws_db_instance" "sales" {
  identifier                  = "scof-eval-sales"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "evaladmin"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.k.arn
  backup_retention_period     = 1
  publicly_accessible         = false
  skip_final_snapshot         = true
}
```

## x1_iam_deny_admin  (X1_BOUNDARY)

- Context: india-finance, region ap-south-1; expected: **PASS**; intended control: **none (all enabled controls must pass)**
- Facts: IAM policy: a scoped Allow plus a Deny statement on Action "*" and Resource "*". Matrix: no statement may Allow Action * on Resource *; a Deny is not an Allow.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_iam_policy" "guard" {
  name = "scof-eval-guard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::scof-eval-reports/*"] },
      { Effect = "Deny", Action = ["*"], Resource = ["*"] }
    ]
  })
}
```

## x1_iam_service_wildcard  (X1_BOUNDARY)

- Context: india-finance, region ap-south-1; expected: **PASS**; intended control: **none (all enabled controls must pass)**
- Facts: IAM policy: Allow Action ["s3:*"] on Resource ["*"]. Matrix check is Action "*" on Resource "*"; a service-level wildcard is not that.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_iam_policy" "svc" {
  name = "scof-eval-svc"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:*"], Resource = ["*"] }
    ]
  })
}
```

## x1_iam_scalar_admin  (X1_BOUNDARY)

- Context: india-finance, region ap-south-1; expected: **FAIL**; intended control: **IAM-NO-WILDCARD-ADMIN**
- Facts: IAM policy: one Allow statement with scalar string Action "*" and scalar string Resource "*" (not lists).
- Matrix check (IAM-NO-WILDCARD-ADMIN): no IAM policy statement may Allow Action "*" on Resource "*".
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_iam_policy" "scalar" {
  name = "scof-eval-scalar"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "*", Resource = "*" }
    ]
  })
}
```

## x1_s3_two_buckets_one_open  (X1_BOUNDARY)

- Context: india-finance, region ap-south-1; expected: **FAIL**; intended control: **ACCESS-EXPOSURE**
- Facts: Two S3 buckets: one with all four public-access-block flags true, one with block_public_acls = false; both aws:kms with a rotating CMK.
- Matrix check (ACCESS-EXPOSURE): no aws_s3_bucket_public_access_block has any of block_public_acls, block_public_policy, ignore_public_acls or restrict_public_buckets set to false, and no aws_db_instance has publicly_accessible set to true.
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
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
```

## x2_kown_alias_arn_aws_managed  (X2_DECLARED_GAP)

- Context: india-finance, region ap-south-1; expected: **FAIL**; intended control: **KEY-OWNERSHIP**
- Facts: S3 SSE aws:kms with kms_master_key_id set to the ARN form of the AWS-managed alias alias/aws/s3. Matrix: key must not be an AWS-managed alias (alias/aws/*).
- Matrix check (KEY-OWNERSHIP): referenced KMS keys must be customer-managed (an aws_kms_key resource or a CMK ARN), not an AWS-managed alias (alias/aws/*).
- Matrix limits (KEY-OWNERSHIP): (none)
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
      kms_master_key_id = "arn:aws:kms:ap-south-1:123456789012:alias/aws/s3"
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

## x2_access_bucket_without_pab  (X2_DECLARED_GAP)

- Context: india-finance, region ap-south-1; expected: **FAIL**; intended control: **ACCESS-EXPOSURE**
- Facts: S3 bucket with aws:kms encryption and no public-access-block resource. Matrix Limits: a bucket with no public-access-block resource is not modelled and false negatives are accepted (declared gap).
- Matrix check (ACCESS-EXPOSURE): no aws_s3_bucket_public_access_block has any of block_public_acls, block_public_policy, ignore_public_acls or restrict_public_buckets set to false, and no aws_db_instance has publicly_accessible set to true.
- Matrix limits (ACCESS-EXPOSURE): only explicit exposure is detected. A bucket with no public-access-block resource, public bucket policies or ACLs, security groups and account-level block settings are not modelled, so false negatives are accepted for the MVP.
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
```

## x2_enc_extra_ebs_block_unencrypted  (X2_DECLARED_GAP)

- Context: india-finance, region ap-south-1; expected: **FAIL**; intended control: **DATA-ENCRYPTION**
- Facts: EC2 instance with an encrypted root device and an additional ebs_block_device with encrypted = false. Matrix check names root_block_device only (declared gap).
- Matrix check (DATA-ENCRYPTION): S3 sse_algorithm is aws:kms; RDS storage_encrypted is true; EC2 root_block_device encrypted is true.
- Matrix limits (DATA-ENCRYPTION): (none)
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
    encrypted  = true
    kms_key_id = aws_kms_key.ebs.arn
  }
  ebs_block_device {
    device_name = "/dev/sdf"
    volume_size = 8
    encrypted   = false
  }
}
```

## x2_enc_standalone_ebs_unencrypted  (X2_DECLARED_GAP)

- Context: india-finance, region ap-south-1; expected: **FAIL**; intended control: **DATA-ENCRYPTION**
- Facts: Standalone aws_ebs_volume with encrypted = false. Matrix check names S3, RDS and EC2 root device only (declared gap; standalone EBS ownership was never verified).
- Matrix check (DATA-ENCRYPTION): S3 sse_algorithm is aws:kms; RDS storage_encrypted is true; EC2 root_block_device encrypted is true.
- Matrix limits (DATA-ENCRYPTION): (none)
- [ ] 1 facts match   [ ] 2 label matches matrix   [ ] 3 nothing else violated

```hcl
resource "aws_ebs_volume" "scratch" {
  availability_zone = "ap-south-1a"
  size              = 8
  encrypted         = false
}
```

