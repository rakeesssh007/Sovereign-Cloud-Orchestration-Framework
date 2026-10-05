package scof.log_retention_test

import data.scof.log_retention

group(after) := {"resource_changes": [{
	"address": "aws_cloudwatch_log_group.g",
	"mode": "managed",
	"type": "aws_cloudwatch_log_group",
	"change": {"after": after},
}]}

test_short_retention_denied if {
	count(log_retention.deny) == 1 with input as group({"retention_in_days": 30})
}

test_364_days_denied if {
	count(log_retention.deny) == 1 with input as group({"retention_in_days": 364})
}

test_365_days_passes if {
	count(log_retention.deny) == 0 with input as group({"retention_in_days": 365})
}

test_longer_retention_passes if {
	count(log_retention.deny) == 0 with input as group({"retention_in_days": 400})
}

test_never_expires_zero_passes if {
	count(log_retention.deny) == 0 with input as group({"retention_in_days": 0})
}

test_omitted_retention_passes if {
	count(log_retention.deny) == 0 with input as group({})
}

test_unknown_retention_denied if {
	count(log_retention.deny) == 1 with input as {"resource_changes": [{
		"address": "aws_cloudwatch_log_group.g",
		"mode": "managed",
		"type": "aws_cloudwatch_log_group",
		"change": {"after": {}, "after_unknown": {"retention_in_days": true}},
	}]}
}

test_other_resource_types_ignored if {
	count(log_retention.deny) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.b",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"change": {"after": {"retention_in_days": 1}},
	}]}
}
