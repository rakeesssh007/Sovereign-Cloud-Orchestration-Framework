package scof.key_rotation_test

import data.scof.key_rotation

key(after) := {"resource_changes": [{"address": "aws_kms_key.k", "mode": "managed", "type": "aws_kms_key", "change": {"after": after}}]}

test_rotation_enabled_passes if {
	count(key_rotation.deny) == 0 with input as key({"enable_key_rotation": true})
}

test_rotation_disabled_denied if {
	count(key_rotation.deny) == 1 with input as key({"enable_key_rotation": false})
}

test_rotation_missing_denied if {
	count(key_rotation.deny) == 1 with input as key({"description": "k"})
}

test_asymmetric_key_skipped if {
	count(key_rotation.deny) == 0 with input as key({"key_spec": "RSA_2048", "enable_key_rotation": false})
}
