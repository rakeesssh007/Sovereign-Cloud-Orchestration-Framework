package scof.encryption_test

import data.scof.encryption

rc(addr, t, after) := {"address": addr, "mode": "managed", "type": t, "change": {"after": after}}

plan(rcs, cfg) := {"resource_changes": rcs, "configuration": {"root_module": {"resources": cfg}}}

bucket := rc("aws_s3_bucket.b", "aws_s3_bucket", {"bucket": "b"})

sse(alg) := rc(
	"aws_s3_bucket_server_side_encryption_configuration.b",
	"aws_s3_bucket_server_side_encryption_configuration",
	{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": alg}]}]},
)

sse_cfg := [{
	"address": "aws_s3_bucket_server_side_encryption_configuration.b",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
}]

test_s3_kms_passes if {
	count(encryption.deny) == 0 with input as plan([bucket, sse("aws:kms")], sse_cfg)
}

test_s3_aes256_denied if {
	count(encryption.deny) == 1 with input as plan([bucket, sse("AES256")], sse_cfg)
}

test_s3_without_sse_config_denied if {
	count(encryption.deny) == 1 with input as plan([bucket], [])
}

test_rds_encrypted_passes if {
	count(encryption.deny) == 0 with input as plan([rc("aws_db_instance.d", "aws_db_instance", {"storage_encrypted": true})], [])
}

test_rds_unencrypted_denied if {
	count(encryption.deny) == 1 with input as plan([rc("aws_db_instance.d", "aws_db_instance", {"storage_encrypted": false})], [])
}

test_ebs_encrypted_passes if {
	count(encryption.deny) == 0 with input as plan([rc("aws_ebs_volume.v", "aws_ebs_volume", {"encrypted": true})], [])
}

test_ebs_unencrypted_denied if {
	count(encryption.deny) == 1 with input as plan([rc("aws_ebs_volume.v", "aws_ebs_volume", {"encrypted": false})], [])
}

test_instance_encrypted_passes if {
	count(encryption.deny) == 0 with input as plan([rc("aws_instance.i", "aws_instance", {"root_block_device": [{"encrypted": true}]})], [])
}

test_instance_unencrypted_denied if {
	count(encryption.deny) == 1 with input as plan([rc("aws_instance.i", "aws_instance", {"root_block_device": [{"encrypted": false}]})], [])
}

test_instance_no_block_denied if {
	count(encryption.deny) == 1 with input as plan([rc("aws_instance.i", "aws_instance", {"root_block_device": []})], [])
}

test_deleted_resource_ignored if {
	count(encryption.deny) == 0 with input as plan([rc("aws_db_instance.d", "aws_db_instance", null)], [])
}
