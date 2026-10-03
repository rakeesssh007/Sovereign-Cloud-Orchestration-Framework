package scof.lib

kms_algorithms := {"aws:kms", "aws:kms:dsse"}

# Normalize a value that Terraform may present as a list or a single object.
as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

# Managed resources of a type that will exist after apply (deletes excluded).
resources_of_type(t) := {rc |
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type == t
	rc.change.after != null
}

# Configuration entry for a resource address (root module only in the MVP).
config_resource(address) := c if {
	some c in input.configuration.root_module.resources
	c.address == address
}

# Every kms_key_id / kms_master_key_id expression, including those in nested blocks.
key_expressions(address) := {e |
	c := config_resource(address)
	walk(c.expressions, [_, node])
	is_object(node)
	some k in ["kms_key_id", "kms_master_key_id"]
	e := node[k]
}

# A key expression counts as customer-managed if it references an aws_kms_key or
# aws_kms_alias resource, or is a literal that is not an AWS-managed alias.
is_cmk(e) if {
	some ref in e.references
	startswith(ref, "aws_kms_key.")
}

is_cmk(e) if {
	some ref in e.references
	startswith(ref, "aws_kms_alias.")
}

is_cmk(e) if {
	is_string(e.constant_value)
	e.constant_value != ""
	not startswith(e.constant_value, "alias/aws/")
}

has_cmk(address) if {
	some e in key_expressions(address)
	is_cmk(e)
}

# S3 server-side-encryption configuration helpers.
sse_algorithms(rc) := {alg |
	some rule in as_list(rc.change.after.rule)
	some d in as_list(rule.apply_server_side_encryption_by_default)
	alg := d.sse_algorithm
}

s3_uses_kms(rc) if {
	some alg in sse_algorithms(rc)
	alg in kms_algorithms
}

# True if some SSE configuration resource references this bucket address.
bucket_has_sse_config(address) if {
	some c in input.configuration.root_module.resources
	c.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in c.expressions.bucket.references
	ref == address
}

# EC2 instance block devices (root and extra EBS).
device_blocks(rc) := [b |
	some name in ["root_block_device", "ebs_block_device"]
	some b in as_list(rc.change.after[name])
]
