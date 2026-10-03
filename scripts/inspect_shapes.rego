package inspect

types := [r.type | some r in input.resource_changes]

non_key_config := [r | some r in input.configuration.root_module.resources; r.type != "aws_kms_key"]