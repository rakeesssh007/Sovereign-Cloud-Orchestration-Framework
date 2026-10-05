package scof.access_exposure_test

import data.scof.access_exposure

all_true := {
	"block_public_acls": true,
	"block_public_policy": true,
	"ignore_public_acls": true,
	"restrict_public_buckets": true,
}

block(after) := {"resource_changes": [{
	"address": "aws_s3_bucket_public_access_block.b",
	"mode": "managed",
	"type": "aws_s3_bucket_public_access_block",
	"change": {"after": after},
}]}

db(after, unknown) := {"resource_changes": [{
	"address": "aws_db_instance.d",
	"mode": "managed",
	"type": "aws_db_instance",
	"change": {"after": after, "after_unknown": unknown},
}]}

test_all_flags_true_passes if {
	count(access_exposure.deny) == 0 with input as block(all_true)
}

test_one_flag_false_denied if {
	count(access_exposure.deny) == 1 with input as block(object.union(all_true, {"block_public_policy": false}))
}

test_all_flags_false_reports_each_flag if {
	count(access_exposure.deny) == 4 with input as block({
		"block_public_acls": false,
		"block_public_policy": false,
		"ignore_public_acls": false,
		"restrict_public_buckets": false,
	})
}

test_unknown_flag_denied if {
	count(access_exposure.deny) == 1 with input as {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.b",
		"mode": "managed",
		"type": "aws_s3_bucket_public_access_block",
		"change": {
			"after": {"block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
			"after_unknown": {"block_public_acls": true},
		},
	}]}
}

test_public_rds_denied if {
	count(access_exposure.deny) == 1 with input as db({"publicly_accessible": true}, {})
}

test_private_rds_passes if {
	count(access_exposure.deny) == 0 with input as db({"publicly_accessible": false}, {})
}

test_unknown_publicly_accessible_denied if {
	count(access_exposure.deny) == 1 with input as db({}, {"publicly_accessible": true})
}

test_other_resource_types_ignored if {
	count(access_exposure.deny) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.b",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"change": {"after": {"block_public_acls": false, "publicly_accessible": true}},
	}]}
}
