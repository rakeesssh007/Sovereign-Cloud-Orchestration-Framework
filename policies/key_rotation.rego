package scof.key_rotation

import data.scof.lib

control := "KEY-ROTATION"

symmetric(rc) if {
	spec := object.get(rc.change.after, "key_spec", "SYMMETRIC_DEFAULT")
	spec in {"SYMMETRIC_DEFAULT", null}
}

deny contains msg if {
	some rc in lib.resources_of_type("aws_kms_key")
	symmetric(rc)
	not rc.change.after.enable_key_rotation == true
	msg := sprintf("%s: %s: KMS key must set enable_key_rotation = true", [control, rc.address])
}
