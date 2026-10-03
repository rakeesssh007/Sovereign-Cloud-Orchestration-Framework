package main

import data.scof.encryption
import data.scof.iam
import data.scof.key_ownership
import data.scof.key_rotation
import data.scof.region

deny contains msg if {
	some msg in region.deny
}

deny contains msg if {
	some msg in encryption.deny
}

deny contains msg if {
	some msg in key_ownership.deny
}

deny contains msg if {
	some msg in key_rotation.deny
}

deny contains msg if {
	some msg in iam.deny
}
