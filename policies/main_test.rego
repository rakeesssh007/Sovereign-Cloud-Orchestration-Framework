package main_test

import data.main
import data.scof.control_set

plan := {"configuration": {"provider_config": {"aws": {
	"name": "aws",
	"expressions": {"region": {"constant_value": "us-east-1"}},
}}}}

allowlists := {"eu": ["eu-central-1"], "india-finance": ["ap-south-1"]}

known := ["eu", "india-finance", "india"]

denies(ctx, sets) := d if {
	d := main.deny with input as plan with data.context as ctx with data.known_contexts as known with data.region_allowlists as allowlists with data.control_sets as sets
}

region_only(d) := {m | some m in d; startswith(m, "REGION-RESTRICTION:")}

control_set_only(d) := {m | some m in d; startswith(m, "CONTROL-SET:")}

test_region_runs_when_enabled if {
	d := denies("eu", {"eu": ["REGION-RESTRICTION"]})
	count(region_only(d)) == 1
}

test_region_skipped_when_not_enabled if {
	d := denies("eu", {"eu": ["DATA-ENCRYPTION"]})
	count(region_only(d)) == 0
}

test_known_context_without_control_set_fails_closed if {
	d := denies("india-finance", {"eu": ["DATA-ENCRYPTION"]})
	count(control_set_only(d)) == 1
	count(region_only(d)) == 1
}

test_unknown_context_evaluates_every_control if {
	d := denies("mars", {"eu": ["DATA-ENCRYPTION"]})
	count(region_only(d)) == 1
	count(control_set_only(d)) == 0
}

test_no_context_evaluates_every_control if {
	d := main.deny with input as plan with data.known_contexts as known with data.control_sets as {"eu": ["DATA-ENCRYPTION"]}
	count(region_only(d)) == 1
}

test_enabled_lookup if {
	control_set.enabled("A") with data.context as "x" with data.control_sets as {"x": ["A"]}
	not control_set.enabled("B") with data.context as "x" with data.control_sets as {"x": ["A"]}
}

log_plan := {"resource_changes": [{
	"address": "aws_cloudwatch_log_group.g",
	"mode": "managed",
	"type": "aws_cloudwatch_log_group",
	"change": {"after": {"retention_in_days": 30}},
}]}

log_denies(ctx, sets) := d if {
	d := main.deny with input as log_plan with data.context as ctx with data.known_contexts as known with data.region_allowlists as allowlists with data.control_sets as sets
}

log_only(d) := {m | some m in d; startswith(m, "LOG-RETENTION:")}

# Same plan, different context: the control fires only where the context enables it.
test_log_retention_fires_in_a_context_that_enables_it if {
	d := log_denies("india-finance", {"india-finance": ["LOG-RETENTION"]})
	count(log_only(d)) == 1
}

test_log_retention_silent_in_a_context_that_does_not_enable_it if {
	d := log_denies("eu", {"eu": ["DATA-ENCRYPTION"]})
	count(log_only(d)) == 0
}
