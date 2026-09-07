package compliance.common

# Generic, operator-driven control evaluation shared by every
# policies/security/*.rego file. Keeping this logic in one place means every
# domain file is just "which controls apply to me" and this module decides
# PASS / FAIL / NOT_APPLICABLE the same way for all of them.
#
# NOT_APPLICABLE is distinct from PASS: it means the parameter was absent
# from the normalized baseline (e.g. vendor doesn't expose the concept, or
# the parser/AI normalization couldn't determine it) — never treated as a
# passing control (see problem-statement RULE 12).

# actual is `null` when the parameter is missing from input.baseline.
result_for(control, actual) = "NOT_APPLICABLE" if {
	actual == null
}

result_for(control, actual) = "PASS" if {
	actual != null
	control.operator == "eq"
	actual == control.expected
}

result_for(control, actual) = "FAIL" if {
	actual != null
	control.operator == "eq"
	actual != control.expected
}

result_for(control, actual) = "PASS" if {
	actual != null
	control.operator == "ne"
	actual != control.expected
}

result_for(control, actual) = "FAIL" if {
	actual != null
	control.operator == "ne"
	actual == control.expected
}

result_for(control, actual) = "PASS" if {
	actual != null
	control.operator == "lte"
	actual <= control.expected
}

result_for(control, actual) = "FAIL" if {
	actual != null
	control.operator == "lte"
	actual > control.expected
}

result_for(control, actual) = "PASS" if {
	actual != null
	control.operator == "gte"
	actual >= control.expected
}

result_for(control, actual) = "FAIL" if {
	actual != null
	control.operator == "gte"
	actual < control.expected
}

result_for(control, actual) = "PASS" if {
	actual != null
	control.operator == "in"
	actual in control.expected
}

result_for(control, actual) = "FAIL" if {
	actual != null
	control.operator == "in"
	not actual in control.expected
}

result_for(control, actual) = "PASS" if {
	actual != null
	control.operator == "exists"
}

result_for(control, actual) = "PASS" if {
	actual != null
	control.operator == "not_true"
	actual != true
}

result_for(control, actual) = "FAIL" if {
	actual != null
	control.operator == "not_true"
	actual == true
}

reason_for(control, actual, "PASS") = sprintf("%s is %v, which satisfies the required policy.", [control.parameter, actual])

reason_for(control, actual, "FAIL") = sprintf("%s is %v, but policy requires %s %v.", [control.parameter, actual, control.operator, control.expected])

reason_for(control, actual, "NOT_APPLICABLE") = sprintf("%s was not present in the normalized configuration baseline.", [control.parameter])

remediation_for(control, "FAIL") = control.remediation

remediation_for(control, "PASS") = null

remediation_for(control, "NOT_APPLICABLE") = null

# make_finding builds the structured finding object returned to the backend.
# Matches the schema required by the problem statement (section 3).
make_finding(control_id, control, actual) = f if {
	r := result_for(control, actual)
	f := {
		"control_id": control_id,
		"framework": control.framework,
		"title": control.title,
		"severity": control.severity,
		"parameter": control.parameter,
		"expected": control.expected,
		"actual": actual,
		"result": r,
		"reason": reason_for(control, actual, r),
		"remediation": remediation_for(control, r),
	}
}
