package scof.log_retention

import data.scof.lib

control := "LOG-RETENTION"

# One year read as a floor (our interpretation of DPDP Rules 2025, Rule 6(1)(e)).
min_days := 365

# Retention of 1..364 days is too short. Absent or 0 means the log group never expires, which passes.
deny contains msg if {
	some rc in lib.resources_of_type("aws_cloudwatch_log_group")
	days := rc.change.after.retention_in_days
	is_number(days)
	days > 0
	days < min_days
	msg := sprintf("%s: %s: retains logs for %d days, less than the required %d", [control, rc.address, days, min_days])
}

# Fail closed: a retention value that is unknown at plan time cannot be verified.
deny contains msg if {
	some rc in lib.resources_of_type("aws_cloudwatch_log_group")
	object.get(rc.change, ["after_unknown", "retention_in_days"], false) == true
	msg := sprintf("%s: %s: retention period is not known at plan time, cannot verify", [control, rc.address])
}
