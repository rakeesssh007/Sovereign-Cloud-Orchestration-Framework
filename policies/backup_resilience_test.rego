package scof.backup_resilience_test

import data.scof.backup_resilience

db(address, after, unknown) := {
	"address": address,
	"mode": "managed",
	"type": "aws_db_instance",
	"change": {"after": after, "after_unknown": unknown},
}

test_seven_days_passes if {
	count(backup_resilience.deny) == 0 with input as {"resource_changes": [db("aws_db_instance.d", {"backup_retention_period": 7}, {})]}
}

test_one_day_passes if {
	count(backup_resilience.deny) == 0 with input as {"resource_changes": [db("aws_db_instance.d", {"backup_retention_period": 1}, {})]}
}

test_zero_days_denied if {
	count(backup_resilience.deny) == 1 with input as {"resource_changes": [db("aws_db_instance.d", {"backup_retention_period": 0}, {})]}
}

test_omitted_value_unknown_at_plan_time_denied if {
	count(backup_resilience.deny) == 1 with input as {"resource_changes": [db("aws_db_instance.d", {}, {"backup_retention_period": true})]}
}

test_maximum_value_passes if {
	count(backup_resilience.deny) == 0 with input as {"resource_changes": [db("aws_db_instance.d", {"backup_retention_period": 35}, {})]}
}

test_other_resource_types_ignored if {
	count(backup_resilience.deny) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.b",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"change": {"after": {"backup_retention_period": 0}},
	}]}
}

test_each_instance_reported_separately if {
	count(backup_resilience.deny) == 2 with input as {"resource_changes": [
		db("aws_db_instance.a", {"backup_retention_period": 0}, {}),
		db("aws_db_instance.b", {}, {"backup_retention_period": true}),
	]}
}
