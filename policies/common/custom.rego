package compliance.custom

import data.compliance.common

# Tenant-defined custom controls (Part 2 problem-statement §10). Supplied at
# evaluation time as input.custom_controls — an array of objects shaped like
# one entry of policies/common/controls.rego's `controls` object
# ({control_id, title, parameter, operator, expected, severity,
# remediation}) — rather than baked into the bundle. This is what makes a
# newly *approved* CustomControl row live on the very next scan with no OPA
# bundle rebuild/reload: it's runtime input data, evaluated by the exact
# same generic operator engine (compliance.common.result_for) every
# built-in control uses, against the same flattened baseline. No vendor
# parser change is required to add one (see
# services/custom_control_service.py and IMPLEMENTATION_AUDIT.md §C).
#
# Deliberately narrower than the UnifiedControl/VendorConfigPattern +
# policy_compiler.py subsystem (compliance.generated.*): that subsystem
# authors a full control — including vendor-specific *detection* regexes —
# out of a hardening-guide document via LLM extraction, and compiles it into
# its own generated Rego package. This module instead assumes the parameter
# already exists on the shared SecurityBaselineModel (built-in or via
# extra_parameters) and only needs a parameter/operator/expected/severity
# tuple — the same shape a security engineer already understands from the
# built-in catalog.
findings[control_id] = f if {
	some c in input.custom_controls
	control_id := c.control_id
	control := {
		"framework": "CUSTOM",
		"title": c.title,
		"parameter": c.parameter,
		"operator": c.operator,
		"expected": c.expected,
		"severity": c.severity,
		"remediation": c.remediation,
	}
	actual := object.get(input.baseline, control.parameter, null)
	f := common.make_finding(control_id, control, actual)
}