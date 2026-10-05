package scof.backup_resilience

import data.scof.lib

control := "BACKUP-RESILIENCE"

# SCOF technical baseline (not a numeric requirement from any regulation): automated backups enabled.
min_days := 1

deny contains msg if {
	some rc in lib.resources_of_type("aws_db_instance")
	days := rc.change.after.backup_retention_period
	is_number(days)
	days < min_days
	msg := sprintf("%s: %s: backup_retention_period is %d, automated backups are disabled (minimum %d)", [control, rc.address, days, min_days])
}

# An omitted value is unknown at plan time (the provider default is 0), so it cannot be verified.
deny contains msg if {
	some rc in lib.resources_of_type("aws_db_instance")
	object.get(rc.change, ["after_unknown", "backup_retention_period"], false) == true
	msg := sprintf("%s: %s: backup_retention_period is not set to a known value at plan time; set it explicitly to at least %d", [control, rc.address, min_days])
}
