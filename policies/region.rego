package scof.region

control := "REGION-RESTRICTION"

# Region expression of each aws provider block in the plan configuration.
provider_regions[name] := expr if {
	some name, pc in input.configuration.provider_config
	pc.name == "aws"
	expr := object.get(pc, ["expressions", "region"], {})
}

# Allow-list for the current context; undefined when the context has no list.
allowed_regions := data.region_allowlists[data.context]

deny contains msg if {
	not data.context
	msg := sprintf("%s: context.deployment: no deployment context supplied; region cannot be evaluated", [control])
}

deny contains msg if {
	data.context
	not data.context in data.known_contexts
	msg := sprintf("%s: context.deployment: unknown deployment context '%s'", [control, data.context])
}

deny contains msg if {
	some name, expr in provider_regions
	allowed_regions
	region := object.get(expr, "constant_value", null)
	is_string(region)
	not region in allowed_regions
	msg := sprintf("%s: provider.%s: uses region %s, which is not allowed for context %s", [control, name, region, data.context])
}

deny contains msg if {
	some name, expr in provider_regions
	allowed_regions
	not is_string(object.get(expr, "constant_value", null))
	msg := sprintf("%s: provider.%s: region is not a literal value, cannot verify for context %s", [control, name, data.context])
}
