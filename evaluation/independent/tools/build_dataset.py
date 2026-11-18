#!/usr/bin/env python3
"""Build the independent evaluation fixtures and the expected-label manifest (Design B).

Labels are written from the regulation-to-control matrix text and the scenario facts below.
This script never runs OPA, Conftest or the SCOF CLI. It never overwrites an existing fixture.
"""
import csv
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "evaluation" / "independent"
FIX = OUT / "fixtures"
LOCK = ROOT / "tests" / "compliant" / "log_group_retention_365_india" / ".terraform.lock.hcl"
IN_REGION, EU_REGION = "ap-south-1", "eu-west-1"
CTX_INDIA = ["india-finance", "india-healthcare", "india"]

PROV = """terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region                      = "@REGION@"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
"""


def kms(name, rotation=True):
    return f'''
resource "aws_kms_key" "{name}" {{
  description         = "evaluation key {name}"
  enable_key_rotation = {str(rotation).lower()}
}}
'''


def s3(name, sse="kms", key=None, pab=(True, True, True, True)):
    enc = f'sse_algorithm     = "{"AES256" if sse == "aes" else "aws:kms"}"'
    if sse == "kms" and key:
        enc += f'\n      kms_master_key_id = {key}'
    a, b, c, d = (str(x).lower() for x in pab)
    return f'''
resource "aws_s3_bucket" "{name}" {{
  bucket = "scof-eval-{name}-bucket"
}}

resource "aws_s3_bucket_server_side_encryption_configuration" "{name}" {{
  bucket = aws_s3_bucket.{name}.id
  rule {{
    apply_server_side_encryption_by_default {{
      {enc}
    }}
  }}
}}

resource "aws_s3_bucket_public_access_block" "{name}" {{
  bucket                  = aws_s3_bucket.{name}.id
  block_public_acls       = {a}
  block_public_policy     = {b}
  ignore_public_acls      = {c}
  restrict_public_buckets = {d}
}}
'''


def rds(name, enc=True, key=None, backup="7", public=None):
    lines = [f'  identifier                  = "scof-eval-{name}"',
             '  engine                      = "postgres"',
             '  instance_class              = "db.t3.micro"',
             '  allocated_storage           = 20',
             '  username                    = "evaladmin"',
             '  manage_master_user_password = true',
             f'  storage_encrypted           = {str(enc).lower()}']
    if key:
        lines.append(f'  kms_key_id                  = {key}')
    if backup is not None:
        lines.append(f'  backup_retention_period     = {backup}')
    if public is not None:
        lines.append(f'  publicly_accessible         = {str(public).lower()}')
    lines.append('  skip_final_snapshot         = true')
    return f'\nresource "aws_db_instance" "{name}" {{\n' + "\n".join(lines) + "\n}\n"


def ec2(name, enc=True, key=None):
    k = f'\n    kms_key_id  = {key}' if key else ""
    return f'''
resource "aws_instance" "{name}" {{
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  root_block_device {{
    encrypted   = {str(enc).lower()}{k}
  }}
}}
'''


def iam(name, statements):
    sts = ",\n".join(
        '      { Effect = "Allow", Action = %s, Resource = %s }' % (a, r) for a, r in statements)
    return f'''
resource "aws_iam_policy" "{name}" {{
  name = "scof-eval-{name}"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
{sts}
    ]
  }})
}}
'''


def logs(name, days=None):
    d = f"\n  retention_in_days = {days}" if days is not None else ""
    return f'''
resource "aws_cloudwatch_log_group" "{name}" {{
  name = "/scof/eval/{name}"{d}
}}
'''


# scenario: id, kind (NC|C), control, contexts rows via variants, hcl, facts, source ids, basis
# variants: list of (region, [contexts]); the "eu twin" differs only in provider region.
def sc(sid, kind, control, body, facts, sources, basis, region_rows, family=None):
    return dict(id=sid, kind=kind, control=control, body=body, facts=facts,
                sources=sources, basis=basis, region_rows=region_rows, family=family or sid)


INDIA_ROWS = [(IN_REGION, CTX_INDIA)]
TWIN_ROWS = [(IN_REGION, CTX_INDIA), (EU_REGION, ["eu"])]
S = []

# ---- REGION-RESTRICTION: violates under india-finance and eu (single fixture, fixed foreign region)
S.append(sc("nc_region_s3_us_east_1", "NC", "REGION-RESTRICTION",
            kms("k") + s3("data", key="aws_kms_key.k.arn"),
            "Provider region us-east-1; S3 bucket with aws:kms CMK, rotation true, all four public-access-block flags true.",
            "S1, S6", "SCOF interpretation of RBI payment-data localisation (india-finance) and GDPR Art 44 (eu); outside both allow-lists",
            [("us-east-1", ["india-finance", "eu"])]))
S.append(sc("nc_region_iam_london", "NC", "REGION-RESTRICTION",
            iam("reader", [('["s3:GetObject"]', '["arn:aws:s3:::scof-eval-reports/*"]')]),
            "Provider region eu-west-2 (United Kingdom, excluded from the EU list and not India); single scoped IAM policy.",
            "S1, S6", "SCOF interpretation; eu-west-2 is excluded from the eu allow-list in the matrix",
            [("eu-west-2", ["india-finance", "eu"])]))
# ---- DATA-ENCRYPTION
S.append(sc("nc_enc_s3_aes256", "NC", "DATA-ENCRYPTION",
            s3("data", sse="aes"),
            "S3 bucket encrypted with AES256 (SSE-S3), no KMS; all four public-access-block flags true; no key resources.",
            "S2, S5", "SCOF interpretation: persistent storage must use KMS (SSE-S3 is still encryption in law)", TWIN_ROWS))
S.append(sc("nc_enc_rds_unencrypted", "NC", "DATA-ENCRYPTION",
            rds("orders", enc=False, backup="7", public=False),
            "RDS instance storage_encrypted = false; backup_retention_period 7; publicly_accessible false; no key references.",
            "S2, S5", "SCOF interpretation: RDS storage must be encrypted", TWIN_ROWS))
# ---- KEY-OWNERSHIP
S.append(sc("nc_kown_s3_aws_managed_alias", "NC", "KEY-OWNERSHIP",
            s3("data", key='"alias/aws/s3"'),
            "S3 SSE uses aws:kms with the AWS-managed alias alias/aws/s3 (not a customer-managed key); public-access-block flags all true.",
            "none verified", "SCOF interpretation (INTERPRETATION label)", TWIN_ROWS))
S.append(sc("nc_kown_ec2_aws_managed_alias", "NC", "KEY-OWNERSHIP",
            ec2("app", enc=True, key='"alias/aws/ebs"'),
            "EC2 root_block_device encrypted true with kms_key_id set to the AWS-managed alias alias/aws/ebs (not a customer-managed key); no other resources.",
            "none verified", "SCOF interpretation (INTERPRETATION label)", TWIN_ROWS))
# ---- KEY-ROTATION
S.append(sc("nc_krot_standalone_key", "NC", "KEY-ROTATION",
            kms("archive", rotation=False),
            "A single aws_kms_key with enable_key_rotation = false (default symmetric key); no other resources.",
            "none verified", "SCOF interpretation (best practice)", TWIN_ROWS))
S.append(sc("nc_krot_key_used_by_s3", "NC", "KEY-ROTATION",
            kms("bucketkey", rotation=False) + s3("data", key="aws_kms_key.bucketkey.arn"),
            "Customer-managed key with enable_key_rotation = false referenced by an S3 aws:kms configuration; public-access-block flags all true.",
            "none verified", "SCOF interpretation (best practice)", TWIN_ROWS))
# ---- IAM-NO-WILDCARD-ADMIN
S.append(sc("nc_iam_single_statement_admin", "NC", "IAM-NO-WILDCARD-ADMIN",
            iam("admin", [('["*"]', '["*"]')]),
            "One IAM policy with a single Allow statement: Action [\"*\"] on Resource [\"*\"].",
            "S2", "SCOF interpretation of Rule 6 access control", TWIN_ROWS))
S.append(sc("nc_iam_second_statement_admin", "NC", "IAM-NO-WILDCARD-ADMIN",
            iam("mixed", [('["s3:GetObject"]', '["arn:aws:s3:::scof-eval-reports/*"]'), ('["*"]', '["*"]')]),
            "One IAM policy with two Allow statements: a scoped s3:GetObject statement first, then Action [\"*\"] on Resource [\"*\"].",
            "S2", "SCOF interpretation of Rule 6 access control", TWIN_ROWS))
# ---- LOG-RETENTION (enabled in india-finance and india-healthcare only)
S.append(sc("nc_log_30_days", "NC", "LOG-RETENTION",
            logs("audit", 30),
            "One CloudWatch log group with retention_in_days = 30.",
            "S2 Rule 6(1)(c),(e)", "SCOF baseline derived from DPDP Rule 6(1)(e), not yet in force", INDIA_ROWS))
S.append(sc("nc_log_mixed_groups", "NC", "LOG-RETENTION",
            logs("short", 180) + logs("long", 365),
            "Two CloudWatch log groups: one with retention_in_days = 180, one with 365.",
            "S2 Rule 6(1)(c),(e)", "SCOF baseline derived from DPDP Rule 6(1)(e), not yet in force", INDIA_ROWS))
# ---- ACCESS-EXPOSURE
S.append(sc("nc_acc_s3_block_policy_false", "NC", "ACCESS-EXPOSURE",
            s3("data", sse="kms", key="aws_kms_key.k.arn", pab=(True, False, True, True)) + kms("k"),
            "S3 public-access-block with block_public_policy = false and the other three flags true; aws:kms CMK with rotation true.",
            "S2 Rule 6(1)(b), S5, S7 (supporting)", "SCOF interpretation; explicit exposure only", TWIN_ROWS))
S.append(sc("nc_acc_rds_public", "NC", "ACCESS-EXPOSURE",
            kms("k") + rds("customers", enc=True, key="aws_kms_key.k.arn", backup="7", public=True),
            "RDS instance with publicly_accessible = true; storage encrypted with CMK (rotation true); backup 7.",
            "S2 Rule 6(1)(b), S5, S7 (supporting)", "SCOF interpretation; explicit exposure only", TWIN_ROWS))
# ---- BACKUP-RESILIENCE
S.append(sc("nc_bkp_zero_days", "NC", "BACKUP-RESILIENCE",
            kms("k") + rds("payments", enc=True, key="aws_kms_key.k.arn", backup="0", public=False),
            "RDS backup_retention_period = 0 (automated backups disabled); encrypted with CMK (rotation true); not public.",
            "S8 29(e), S2 Rule 6(1)(d), S5 Art 32(1)(c)", "SCOF baseline (at least 1 day), not a regulatory number", TWIN_ROWS))
S.append(sc("nc_bkp_omitted", "NC", "BACKUP-RESILIENCE",
            kms("k") + rds("claims", enc=True, key="aws_kms_key.k.arn", backup=None, public=False),
            "RDS backup_retention_period omitted (unknown at plan time; provider default 0); encrypted with CMK (rotation true); not public.",
            "S8 29(e), S2 Rule 6(1)(d), S5 Art 32(1)(c)", "SCOF baseline; the matrix states an omitted value is denied", TWIN_ROWS))

# ---- Compliant scenarios (India region for finance/healthcare rows, EU twin for eu rows)
S.append(sc("c_s3_kms_cmk", "C", "", kms("k") + s3("docs", key="aws_kms_key.k.arn"),
            "S3 bucket, aws:kms with a customer-managed key (rotation true), all four public-access-block flags true.", "S2, S5", "", TWIN_ROWS))
S.append(sc("c_rds_cmk_backup14", "C", "", kms("k") + rds("accounts", enc=True, key="aws_kms_key.k.arn", backup="14", public=False),
            "RDS encrypted with a CMK (rotation true), backup_retention_period 14, publicly_accessible false.", "S2, S5, S8", "", TWIN_ROWS))
S.append(sc("c_ec2_cmk_root", "C", "", kms("ebs") + ec2("app", enc=True, key="aws_kms_key.ebs.arn"),
            "EC2 instance, root_block_device encrypted true with a customer-managed key (rotation true).", "S2, S5", "", TWIN_ROWS))
S.append(sc("c_iam_two_scoped", "C", "", iam("scoped", [('["s3:GetObject", "s3:ListBucket"]', '["arn:aws:s3:::scof-eval-reports", "arn:aws:s3:::scof-eval-reports/*"]'), ('["logs:PutLogEvents"]', '["arn:aws:logs:*:*:log-group:/scof/eval/*"]')]),
            "One IAM policy with two scoped Allow statements; no wildcard action on wildcard resource.", "S2", "", TWIN_ROWS))
S.append(sc("c_log_400_days", "C", "", logs("app", 400),
            "One CloudWatch log group with retention_in_days = 400.", "S2", "", TWIN_ROWS))
S.append(sc("c_multi_data_tier", "C", "", kms("k") + s3("lake", key="aws_kms_key.k.arn") + rds("core", enc=True, key="aws_kms_key.k.arn", backup="7", public=False) + logs("core", 365),
            "KMS key (rotation true), S3 aws:kms bucket with all public-access-block flags true, encrypted RDS (backup 7, not public), log group at exactly 365 days.", "S2, S5", "", TWIN_ROWS))
S.append(sc("c_multi_identity_logs", "C", "", kms("k") + iam("ops", [('["cloudwatch:GetMetricData"]', '["*"]')]) + logs("ops"),
            "KMS key (rotation true), IAM policy with a scoped action on all resources (not an admin wildcard), log group with retention omitted (never expires).", "S2", "", TWIN_ROWS))

# ---- Leakage rows: a control is not enabled in the context, so no finding is expected
LEAK = [
    ("nc_log_30_days", "eu", EU_REGION, "LOG-RETENTION is not enabled in eu: a 30-day log group in an EU region must produce no finding"),
    ("nc_region_s3_us_east_1", "india-healthcare", "us-east-1", "REGION-RESTRICTION is not enabled in india-healthcare: a us-east-1 plan must produce no REGION-RESTRICTION finding and no other finding"),
    ("nc_region_s3_us_east_1", "india", "us-east-1", "REGION-RESTRICTION is not enabled in the sector-neutral india context: a us-east-1 plan must produce no REGION-RESTRICTION finding and no other finding"),
]

LABEL_COLS = ["case_id", "case_type", "scenario_id", "scenario_family", "fixture_dir", "plan_file", "context",
              "intended_control", "expected_status", "expected_controls", "terraform_facts", "matrix_sources",
              "basis_kind", "label_date"]


def main():
    FIX.mkdir(parents=True, exist_ok=True)
    rows, made = [], {}
    for s in S:
        for region, ctxs in s["region_rows"]:
            fdir = s["id"] + ("__eu" if region == EU_REGION else "")
            made[fdir] = (s, region)
            for ctx in ctxs:
                exp = [s["control"]] if s["kind"] == "NC" else []
                rows.append(dict(case_id=f"{s['id']}@{ctx}", case_type="NON_COMPLIANT" if s["kind"] == "NC" else "COMPLIANT",
                                 scenario_id=s["id"], scenario_family=s["family"], fixture_dir=fdir,
                                 plan_file=f"evaluation/independent/fixtures/{fdir}/tfplan.json", context=ctx,
                                 intended_control=s["control"], expected_status="FAIL" if exp else "PASS",
                                 expected_controls=";".join(exp), terraform_facts=s["facts"], matrix_sources=s["sources"],
                                 basis_kind=s["basis"] or "n/a", label_date="2026-11-18"))
    for sid, ctx, region, why in LEAK:
        s = next(x for x in S if x["id"] == sid)
        fdir = sid if s["control"] == "REGION-RESTRICTION" else sid + "__eu"
        if fdir not in made:
            made[fdir] = (s, region)
        rows.append(dict(case_id=f"{sid}@{ctx}#leakage", case_type="LEAKAGE", scenario_id=sid, scenario_family=s["family"],
                         fixture_dir=fdir, plan_file=f"evaluation/independent/fixtures/{fdir}/tfplan.json", context=ctx,
                         intended_control="", expected_status="PASS", expected_controls="",
                         terraform_facts=why, matrix_sources=s["sources"], basis_kind="n/a",
                         label_date="2026-11-18"))
    for fdir, (s, region) in sorted(made.items()):
        d = FIX / fdir
        if d.exists() and (d / "main.tf").exists():
            print("exists, not overwritten:", fdir)
            continue
        d.mkdir(parents=True, exist_ok=True)
        (d / "main.tf").write_text(PROV.replace("@REGION@", region) + s["body"], encoding="utf-8", newline="\n")
        shutil.copyfile(LOCK, d / ".terraform.lock.hcl")
    man = OUT / "expected_labels.csv"
    if man.exists():
        sys.exit("expected_labels.csv already exists; refusing to overwrite a possibly signed-off manifest")
    with man.open("w", newline="", encoding="utf-8") as h:
        w = csv.DictWriter(h, fieldnames=LABEL_COLS)
        w.writeheader()
        w.writerows(rows)
    nc = sum(r["case_type"] == "NON_COMPLIANT" for r in rows)
    c = sum(r["case_type"] == "COMPLIANT" for r in rows)
    lk = sum(r["case_type"] == "LEAKAGE" for r in rows)
    print(f"fixtures: {len(made)}  rows: {len(rows)}  non-compliant: {nc}  compliant: {c}  leakage: {lk}")


if __name__ == "__main__":
    main()
