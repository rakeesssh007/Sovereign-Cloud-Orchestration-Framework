package scof.iam

import data.scof.lib

control := "IAM-NO-WILDCARD-ADMIN"

policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

attachment_types := {"aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment"}

deny contains msg if {
	some t in policy_types
	some rc in lib.resources_of_type(t)
	is_string(rc.change.after.policy)
	doc := json.unmarshal(rc.change.after.policy)
	some st in lib.as_list(doc.Statement)
	st.Effect == "Allow"
	"*" in lib.as_list(st.Action)
	"*" in lib.as_list(st.Resource)
	msg := sprintf("%s: %s: policy allows all actions on all resources", [control, rc.address])
}

deny contains msg if {
	some t in attachment_types
	some rc in lib.resources_of_type(t)
	is_string(rc.change.after.policy_arn)
	endswith(rc.change.after.policy_arn, "/AdministratorAccess")
	msg := sprintf("%s: %s: attaches the AdministratorAccess managed policy", [control, rc.address])
}
