#!/usr/bin/env python3
"""Build the exploratory fixtures and their label manifest (separate from the headline dataset).

Two strata, never pooled with the headline rates:
  X1_BOUNDARY      predicate-level boundary and shape cases; labels follow the matrix check line.
  X2_DECLARED_GAP  cases the matrix itself lists as outside a control's scope, or a literal reading of
                   the matrix text that a documented heuristic may miss. A miss here confirms a known limitation.
Labels are written from the matrix text. This script never runs OPA, Conftest or the SCOF CLI.
"""
import csv
import importlib.util
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "evaluation" / "independent"
FIX = OUT / "exploratory_fixtures"
spec = importlib.util.spec_from_file_location("bd", Path(__file__).with_name("build_dataset.py"))
bd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bd)
REGION = "ap-south-1"
CTX = "india-finance"


def iam_custom(name, statements):
    sts = ",\n".join('      { Effect = "%s", Action = %s, Resource = %s }' % s for s in statements)
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


E = []


def ex(sid, stratum, control, expected, body, facts, sources, basis):
    E.append(dict(id=sid, stratum=stratum, control=control, expected=expected, body=body,
                  facts=facts, sources=sources, basis=basis))


MATRIX_CHECK = "matrix check line"
MATRIX_LIMIT = "matrix 'Limits' / literal matrix text (objective-level)"
ex("x1_log_180_days_nearest_below", "X1_BOUNDARY", "LOG-RETENTION", "FAIL", bd.logs("audit", 180),
   "One log group with retention_in_days = 180, the largest provider-valid value below 365 (the AWS provider only accepts fixed values such as 180, 365, 400, so 364 cannot occur in a real plan).", "S2 Rule 6(1)(e)", MATRIX_CHECK)
ex("x1_log_365_days_exact", "X1_BOUNDARY", "", "PASS", bd.logs("audit", 365),
   "One log group with retention_in_days = 365, exactly at the baseline (matrix: at least 365).", "S2 Rule 6(1)(e)", MATRIX_CHECK)
ex("x1_backup_one_day", "X1_BOUNDARY", "", "PASS",
   bd.kms("k") + bd.rds("sales", enc=True, key="aws_kms_key.k.arn", backup="1", public=False),
   "RDS backup_retention_period = 1, exactly at the SCOF baseline (matrix: at least 1); encrypted with a rotating CMK; not public.", "S8, S2, S5", MATRIX_CHECK)
ex("x1_iam_deny_admin", "X1_BOUNDARY", "", "PASS",
   iam_custom("guard", [("Allow", '["s3:GetObject"]', '["arn:aws:s3:::scof-eval-reports/*"]'), ("Deny", '["*"]', '["*"]')]),
   "IAM policy: a scoped Allow plus a Deny statement on Action \"*\" and Resource \"*\". Matrix: no statement may Allow Action * on Resource *; a Deny is not an Allow.", "S2", MATRIX_CHECK)
ex("x1_iam_service_wildcard", "X1_BOUNDARY", "", "PASS",
   iam_custom("svc", [("Allow", '["s3:*"]', '["*"]')]),
   "IAM policy: Allow Action [\"s3:*\"] on Resource [\"*\"]. Matrix check is Action \"*\" on Resource \"*\"; a service-level wildcard is not that.", "S2", MATRIX_CHECK)
ex("x1_iam_scalar_admin", "X1_BOUNDARY", "IAM-NO-WILDCARD-ADMIN", "FAIL",
   iam_custom("scalar", [("Allow", '"*"', '"*"')]),
   "IAM policy: one Allow statement with scalar string Action \"*\" and scalar string Resource \"*\" (not lists).", "S2", MATRIX_CHECK)
ex("x1_s3_two_buckets_one_open", "X1_BOUNDARY", "ACCESS-EXPOSURE", "FAIL",
   bd.kms("k") + bd.s3("shut", key="aws_kms_key.k.arn") + bd.s3("wide", key="aws_kms_key.k.arn", pab=(False, True, True, True)),
   "Two S3 buckets: one with all four public-access-block flags true, one with block_public_acls = false; both aws:kms with a rotating CMK.", "S2, S5, S7", MATRIX_CHECK)
ex("x2_kown_alias_arn_aws_managed", "X2_DECLARED_GAP", "KEY-OWNERSHIP", "FAIL",
   bd.s3("data", key='"arn:aws:kms:ap-south-1:123456789012:alias/aws/s3"'),
   "S3 SSE aws:kms with kms_master_key_id set to the ARN form of the AWS-managed alias alias/aws/s3. Matrix: key must not be an AWS-managed alias (alias/aws/*).", "none verified", MATRIX_LIMIT)
ex("x2_access_bucket_without_pab", "X2_DECLARED_GAP", "ACCESS-EXPOSURE", "FAIL",
   (lambda t: t[:t.index('resource "aws_s3_bucket_public_access_block"')])(bd.kms("k") + bd.s3("data", key="aws_kms_key.k.arn")),
   "S3 bucket with aws:kms encryption and no public-access-block resource. Matrix Limits: a bucket with no public-access-block resource is not modelled and false negatives are accepted (declared gap).", "S2, S5, S7", MATRIX_LIMIT)
ex("x2_enc_extra_ebs_block_unencrypted", "X2_DECLARED_GAP", "DATA-ENCRYPTION", "FAIL",
   bd.kms("ebs") + '''
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
''',
   "EC2 instance with an encrypted root device and an additional ebs_block_device with encrypted = false. Matrix check names root_block_device only (declared gap).", "S2, S5", MATRIX_LIMIT)
ex("x2_enc_standalone_ebs_unencrypted", "X2_DECLARED_GAP", "DATA-ENCRYPTION", "FAIL",
   '''
resource "aws_ebs_volume" "scratch" {
  availability_zone = "ap-south-1a"
  size              = 8
  encrypted         = false
}
''',
   "Standalone aws_ebs_volume with encrypted = false. Matrix check names S3, RDS and EC2 root device only (declared gap; standalone EBS ownership was never verified).", "S2, S5", MATRIX_LIMIT)

COLS = ["case_id", "stratum", "scenario_id", "fixture_dir", "plan_file", "context", "intended_control", "expected_status",
        "label_basis", "terraform_facts", "matrix_sources", "label_date"]


def main():
    FIX.mkdir(parents=True, exist_ok=True)
    rows = []
    for e in E:
        d = FIX / e["id"]
        if not (d / "main.tf").exists():
            d.mkdir(parents=True, exist_ok=True)
            (d / "main.tf").write_text(bd.PROV.replace("@REGION@", REGION) + e["body"], encoding="utf-8", newline="\n")
            shutil.copyfile(bd.LOCK, d / ".terraform.lock.hcl")
        rows.append(dict(case_id=f"{e['id']}@{CTX}", stratum=e["stratum"], scenario_id=e["id"], fixture_dir=e["id"],
                         plan_file=f"evaluation/independent/exploratory_fixtures/{e['id']}/tfplan.json", context=CTX,
                         intended_control=e["control"], expected_status=e["expected"], label_basis=e["basis"],
                         terraform_facts=e["facts"], matrix_sources=e["sources"], label_date="2026-11-18"))
    man = OUT / "exploratory_labels.csv"
    if man.exists():
        sys.exit("exploratory_labels.csv already exists; refusing to overwrite")
    with man.open("w", newline="", encoding="utf-8") as h:
        w = csv.DictWriter(h, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)
    print(f"exploratory scenarios: {len(rows)}  X1: {sum(r['stratum']=='X1_BOUNDARY' for r in rows)}  X2: {sum(r['stratum']=='X2_DECLARED_GAP' for r in rows)}")


if __name__ == "__main__":
    main()
