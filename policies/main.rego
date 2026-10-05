package main

import data.scof.access_exposure
import data.scof.backup_resilience
import data.scof.control_set
import data.scof.encryption
import data.scof.iam
import data.scof.key_ownership
import data.scof.key_rotation
import data.scof.log_retention
import data.scof.region

# Control-set configuration errors are always reported.
deny contains msg if {
	some msg in control_set.deny
}

# Every control is evaluated only when the control set of the current context enables it.
deny contains msg if {
	control_set.enabled("REGION-RESTRICTION")
	some msg in region.deny
}

deny contains msg if {
	control_set.enabled("DATA-ENCRYPTION")
	some msg in encryption.deny
}

deny contains msg if {
	control_set.enabled("KEY-OWNERSHIP")
	some msg in key_ownership.deny
}

deny contains msg if {
	control_set.enabled("KEY-ROTATION")
	some msg in key_rotation.deny
}

deny contains msg if {
	control_set.enabled("IAM-NO-WILDCARD-ADMIN")
	some msg in iam.deny
}

deny contains msg if {
	control_set.enabled("LOG-RETENTION")
	some msg in log_retention.deny
}

deny contains msg if {
	control_set.enabled("ACCESS-EXPOSURE")
	some msg in access_exposure.deny
}

deny contains msg if {
	control_set.enabled("BACKUP-RESILIENCE")
	some msg in backup_resilience.deny
}
