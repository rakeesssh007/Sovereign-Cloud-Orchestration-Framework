package scof.iam_test

import data.scof.iam

pol(action, resource) := json.marshal({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]})

policy_plan(p) := {"resource_changes": [{"address": "aws_iam_policy.p", "mode": "managed", "type": "aws_iam_policy", "change": {"after": {"policy": p}}}]}

test_wildcard_admin_denied if {
	count(iam.deny) == 1 with input as policy_plan(pol(["*"], ["*"]))
}

test_wildcard_admin_string_form_denied if {
	count(iam.deny) == 1 with input as policy_plan(pol("*", "*"))
}

test_least_privilege_passes if {
	count(iam.deny) == 0 with input as policy_plan(pol(["s3:GetObject"], ["arn:aws:s3:::scof-finance-data/*"]))
}

test_wildcard_action_on_specific_resource_not_flagged if {
	count(iam.deny) == 0 with input as policy_plan(pol(["*"], ["arn:aws:s3:::scof-finance-data/*"]))
}

test_admin_access_attachment_denied if {
	count(iam.deny) == 1 with input as {"resource_changes": [{"address": "aws_iam_role_policy_attachment.a", "mode": "managed", "type": "aws_iam_role_policy_attachment", "change": {"after": {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}}}]}
}
