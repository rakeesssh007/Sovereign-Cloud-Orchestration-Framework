package scof.key_ownership

import data.scof.lib

control := "KEY-OWNERSHIP"

deny contains msg if {
	some rc in lib.resources_of_type("aws_s3_bucket_server_side_encryption_configuration")
	lib.s3_uses_kms(rc)
	not lib.has_cmk(rc.address)
	msg := sprintf("%s: %s: KMS encryption must use a customer-managed key, not an AWS-managed or default key", [control, rc.address])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_db_instance")
	rc.change.after.storage_encrypted == true
	not lib.has_cmk(rc.address)
	msg := sprintf("%s: %s: RDS must use a customer-managed KMS key (kms_key_id)", [control, rc.address])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_ebs_volume")
	rc.change.after.encrypted == true
	not lib.has_cmk(rc.address)
	msg := sprintf("%s: %s: EBS volume must use a customer-managed KMS key (kms_key_id)", [control, rc.address])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_instance")
	some b in lib.device_blocks(rc)
	b.encrypted == true
	not lib.has_cmk(rc.address)
	msg := sprintf("%s: %s: EC2 block devices must use a customer-managed KMS key (kms_key_id)", [control, rc.address])
}
