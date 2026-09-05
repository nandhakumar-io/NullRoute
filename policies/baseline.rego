package compliance.evaluate

# THE authoritative decision entrypoint. The backend's opa_service.py posts
# to POST /v1/data/compliance/evaluate — OPA returns this entire package as
# JSON under "result". This is the ONLY place decision precedence
# (PASS/REVIEW/BLOCK) is computed for the deterministic-policy layer;
# behavioral (Batfish) and risk-engine results are folded in afterwards by
# backend/app/services/change_validation_service.py, which must never
# downgrade a BLOCK produced here.
#
# Expected input shape (see problem statement section 3):
#   {"input": {"scan_id": ..., "device": {...}, "vendor": ..., "framework": ...,
#              "baseline": {<dotted-path>: <value>, ...}, "metadata": {...}}}
#
# `baseline` MUST already be sanitized by opa_service.sanitize_baseline() —
# secrets (passwords, SNMP community values, SSH keys, tokens) must never
# reach this policy input.

import data.compliance.common.controls
import data.compliance.metadata
import data.compliance.security.management
import data.compliance.security.snmp
import data.compliance.security.aaa
import data.compliance.security.logging
import data.compliance.security.password
import data.compliance.network.segmentation

all_findings[control_id] = f { f := management.findings[control_id] }
all_findings[control_id] = f { f := snmp.findings[control_id] }
all_findings[control_id] = f { f := aaa.findings[control_id] }
all_findings[control_id] = f { f := logging.findings[control_id] }
all_findings[control_id] = f { f := password.findings[control_id] }
all_findings[control_id] = f { f := segmentation.findings[control_id] }

# Only include controls actually requested for the given framework filter
# (input.framework == "ALL" or unset means every control is in scope).
in_scope(control_id) {
	input.framework == "ALL"
}

in_scope(control_id) {
	not input.framework
}

in_scope(control_id) {
	control := controls.controls[control_id]
	control.framework == input.framework
}

findings := [f |
	some control_id
	all_findings[control_id]
	in_scope(control_id)
	f := all_findings[control_id]
]

violations := [f | f := findings[_]; f.result == "FAIL"]

evaluated_controls := [f.control_id | f := findings[_]]

policy_version := metadata.version

# Decision precedence — first matching branch wins:
#   any CRITICAL FAIL              -> BLOCK
#   3+ HIGH FAILs, or any HIGH FAIL -> REVIEW
#   otherwise                      -> PASS
# (Segmentation/behavioral BLOCK escalation from Batfish happens one layer
# up, in change_validation_service.py — OPA only ever speaks to what it can
# actually verify from the static config.)
decision = "BLOCK" {
	some v
	v := violations[_]
	v.severity == "CRITICAL"
} else = "REVIEW" {
	some v
	v := violations[_]
	v.severity == "HIGH"
} else = "REVIEW" {
	count([v | v := violations[_]; v.severity == "MEDIUM"]) >= 3
} else = "PASS" {
	true
}
