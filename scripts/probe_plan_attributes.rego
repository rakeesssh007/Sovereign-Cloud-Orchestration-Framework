package probe

keys := ["storage_encrypted", "kms_key_id", "enable_key_rotation", "root_block_device", "rule", "policy"]

summary contains row if {
    some rc in input.resource_changes
    row := {
        "address": rc.address,
        "type": rc.type,
        "after": object.filter(rc.change.after, keys),
        "unknown": object.filter(rc.change.after_unknown, keys),
    }
}