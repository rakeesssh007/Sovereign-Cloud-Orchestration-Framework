package scof.encryption

import data.scof.lib

control := "DATA-ENCRYPTION"

deny contains msg if {
	some rc in lib.resources_of_type("aws_s3_bucket_server_side_encryption_configuration")
	not lib.s3_uses_kms(rc)
	msg := sprintf("%s: %s: S3 bucket must use KMS encryption (sse_algorithm aws:kms)", [control, rc.address])
}

deny contains msg if {
	some b in lib.resources_of_type("aws_s3_bucket")
	not lib.bucket_has_sse_config(b.address)
	msg := sprintf("%s: %s: S3 bucket has no server-side encryption configuration", [control, b.address])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_db_instance")
	not rc.change.after.storage_encrypted == true
	msg := sprintf("%s: %s: RDS instance must set storage_encrypted = true", [control, rc.address])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_ebs_volume")
	not rc.change.after.encrypted == true
	msg := sprintf("%s: %s: EBS volume must set encrypted = true", [control, rc.address])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_instance")
	some b in lib.device_blocks(rc)
	not b.encrypted == true
	msg := sprintf("%s: %s: EC2 block device must set encrypted = true", [control, rc.address])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_instance")
	count(lib.device_blocks(rc)) == 0
	msg := sprintf("%s: %s: EC2 instance has no explicitly encrypted root_block_device", [control, rc.address])
}
