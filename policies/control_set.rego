package scof.control_set

control := "CONTROL-SET"

# Control IDs enabled for the current deployment context.
# Undefined when there is no context or the context has no entry in data.control_sets.
configured := data.control_sets[data.context]

# Fail closed: when no control set can be selected, every control is evaluated.
enabled(_) if not configured

enabled(control_id) if control_id in configured

# A known context without a control set is a configuration error.
deny contains msg if {
	data.context
	data.context in data.known_contexts
	not data.control_sets[data.context]
	msg := sprintf("%s: context.deployment: no control set defined for context '%s'; every control is evaluated", [control, data.context])
}
