package scof.access_exposure

import data.scof.lib

control := "ACCESS-EXPOSURE"

public_access_block_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

# A public access block must switch all four protections on. Omitted flags are reported as false in the plan.
deny contains msg if {
	some rc in lib.resources_of_type("aws_s3_bucket_public_access_block")
	some flag in public_access_block_flags
	rc.change.after[flag] == false
	msg := sprintf("%s: %s: %s is false, so public access to the bucket is not fully blocked", [control, rc.address, flag])
}

# Fail closed: a flag that is unknown at plan time cannot be verified.
deny contains msg if {
	some rc in lib.resources_of_type("aws_s3_bucket_public_access_block")
	some flag in public_access_block_flags
	object.get(rc.change, ["after_unknown", flag], false) == true
	msg := sprintf("%s: %s: %s is not known at plan time, cannot verify", [control, rc.address, flag])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_db_instance")
	rc.change.after.publicly_accessible == true
	msg := sprintf("%s: %s: database instance is publicly accessible", [control, rc.address])
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_db_instance")
	object.get(rc.change, ["after_unknown", "publicly_accessible"], false) == true
	msg := sprintf("%s: %s: publicly_accessible is not known at plan time, cannot verify", [control, rc.address])
}
