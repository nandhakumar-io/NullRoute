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
import data.compliance.custom

all_findings[control_id] = f if { f := management.findings[control_id] }
all_findings[control_id] = f if { f := snmp.findings[control_id] }
all_findings[control_id] = f if { f := aaa.findings[control_id] }
all_findings[control_id] = f if { f := logging.findings[control_id] }
all_findings[control_id] = f if { f := password.findings[control_id] }
all_findings[control_id] = f if { f := segmentation.findings[control_id] }
all_findings[control_id] = f if { f := custom.findings[control_id] }

# Only include controls actually requested for the given framework filter
# (input.framework == "ALL" or unset means every control is in scope).
in_scope(control_id) if {
	input.framework == "ALL"
}

in_scope(control_id) if {
	not input.framework
}

in_scope(control_id) if {
	control := controls.controls[control_id]
	control.framework == input.framework
}

# Tenant-defined custom controls (IMPLEMENTATION_AUDIT.md §C) always count
# as in scope, regardless of the requested built-in framework filter: they
# live in input.custom_controls, not in the controls.controls catalog the
# rule above checks, and a tenant explicitly approved this control for
# every scan -- it shouldn't silently disappear because someone filtered
# the dashboard down to "CIS" for this run.
in_scope(control_id) if {
	custom.findings[control_id]
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

unverified_findings := [f | f := findings[_]; f.result == "UNVERIFIED"]

# Decision precedence — first matching branch wins:
#   any CRITICAL FAIL                    -> BLOCK
#   any HIGH FAIL, or 3+ MEDIUM FAILs    -> REVIEW
#   any UNVERIFIED finding (no FAIL yet) -> REVIEW
#   otherwise                            -> PASS
#
# A known CRITICAL/HIGH violation always outranks an unverified parameter —
# an unreviewed AI normalization is never allowed to mask a violation that's
# already certain. Only once there are no confirmed violations does an
# UNVERIFIED finding get its own say: it still can't resolve to PASS,
# because "not yet human-approved" is not the same as "verified compliant"
# (problem statement RULE 12). This intentionally keeps the top-level
# decision vocabulary (PASS/REVIEW/BLOCK) unchanged — see policies/README or
# IMPLEMENTATION_AUDIT.md §A for why that rename was deliberately NOT made
# alongside this change. (Segmentation/behavioral BLOCK escalation from
# Batfish happens one layer up, in change_validation_service.py — OPA only
# ever speaks to what it can actually verify from the static config.)
decision = "BLOCK" if {
	v1 := violations[_]
	v1.severity == "CRITICAL"
} else = "REVIEW" if {
	v2 := violations[_]
	v2.severity == "HIGH"
} else = "REVIEW" if {
	count([v3 | v3 := violations[_]; v3.severity == "MEDIUM"]) >= 3
} else = "REVIEW" if {
	count(unverified_findings) > 0
} else = "PASS" if {
	true
}
