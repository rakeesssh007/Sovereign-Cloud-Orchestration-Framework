package scof.key_ownership_test

import data.scof.key_ownership

rc(addr, t, after) := {"address": addr, "mode": "managed", "type": t, "change": {"after": after}}

plan(rcs, cfg) := {"resource_changes": rcs, "configuration": {"root_module": {"resources": cfg}}}

sse(alg) := rc(
	"aws_s3_bucket_server_side_encryption_configuration.b",
	"aws_s3_bucket_server_side_encryption_configuration",
	{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": alg}]}]},
)

sse_cfg(dflt) := [{
	"address": "aws_s3_bucket_server_side_encryption_configuration.b",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {"rule": [{"apply_server_side_encryption_by_default": [dflt]}]},
}]

cmk := {"sse_algorithm": {"constant_value": "aws:kms"}, "kms_master_key_id": {"references": ["aws_kms_key.k.arn", "aws_kms_key.k"]}}

aws_managed := {"sse_algorithm": {"constant_value": "aws:kms"}, "kms_master_key_id": {"constant_value": "alias/aws/s3"}}

no_key := {"sse_algorithm": {"constant_value": "aws:kms"}}

rds := rc("aws_db_instance.d", "aws_db_instance", {"storage_encrypted": true})

rds_cfg(expr) := [{"address": "aws_db_instance.d", "type": "aws_db_instance", "expressions": expr}]

test_s3_cmk_passes if {
	count(key_ownership.deny) == 0 with input as plan([sse("aws:kms")], sse_cfg(cmk))
}

test_s3_aws_managed_alias_denied if {
	count(key_ownership.deny) == 1 with input as plan([sse("aws:kms")], sse_cfg(aws_managed))
}

test_s3_kms_without_key_denied if {
	count(key_ownership.deny) == 1 with input as plan([sse("aws:kms")], sse_cfg(no_key))
}

test_s3_aes256_not_applicable if {
	count(key_ownership.deny) == 0 with input as plan([sse("AES256")], sse_cfg(no_key))
}

test_rds_cmk_passes if {
	count(key_ownership.deny) == 0 with input as plan([rds], rds_cfg({"kms_key_id": {"references": ["aws_kms_key.k.arn", "aws_kms_key.k"]}}))
}

test_rds_without_key_denied if {
	count(key_ownership.deny) == 1 with input as plan([rds], rds_cfg({"storage_encrypted": {"constant_value": true}}))
}

test_rds_unencrypted_not_applicable if {
	count(key_ownership.deny) == 0 with input as plan([rc("aws_db_instance.d", "aws_db_instance", {"storage_encrypted": false})], rds_cfg({}))
}

test_rds_literal_arn_passes if {
	count(key_ownership.deny) == 0 with input as plan([rds], rds_cfg({"kms_key_id": {"constant_value": "arn:aws:kms:ap-south-1:111122223333:key/abc"}}))
}
