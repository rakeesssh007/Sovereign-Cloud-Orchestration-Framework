package scof.region_test

import data.scof.region

lists := {"india-finance": ["ap-south-1", "ap-south-2"], "eu": ["eu-central-1"]}

known := ["india", "india-finance", "eu"]

plan(r) := {"configuration": {"provider_config": {"aws": {"name": "aws", "expressions": {"region": r}}}}}

test_india_region_allowed if {
	count(region.deny) == 0 with input as plan({"constant_value": "ap-south-1"})
		with data.context as "india-finance"
		with data.region_allowlists as lists
		with data.known_contexts as known
}

test_us_region_denied_for_india_finance if {
	count(region.deny) == 1 with input as plan({"constant_value": "us-east-1"})
		with data.context as "india-finance"
		with data.region_allowlists as lists
		with data.known_contexts as known
}

test_eu_region_denied_for_india_finance if {
	count(region.deny) == 1 with input as plan({"constant_value": "eu-central-1"})
		with data.context as "india-finance"
		with data.region_allowlists as lists
		with data.known_contexts as known
}

test_non_literal_region_denied if {
	count(region.deny) == 1 with input as plan({"references": ["var.aws_region"]})
		with data.context as "india-finance"
		with data.region_allowlists as lists
		with data.known_contexts as known
}

test_missing_context_denied if {
	count(region.deny) == 1 with input as plan({"constant_value": "ap-south-1"})
		with data.region_allowlists as lists
		with data.known_contexts as known
}

test_context_without_list_has_no_region_control if {
	count(region.deny) == 0 with input as plan({"constant_value": "us-east-1"})
		with data.context as "india"
		with data.region_allowlists as lists
		with data.known_contexts as known
}
