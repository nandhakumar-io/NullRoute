package compliance.frameworks.cis

# Framework-scoped view used by GET /api/policy-evaluation?framework=CIS
# style filtering — same underlying findings as compliance.evaluate, just
# pre-filtered to one framework so the frontend can query it directly.

import data.compliance.common.controls
import data.compliance.security.management
import data.compliance.security.snmp
import data.compliance.security.aaa
import data.compliance.security.logging
import data.compliance.security.password

merged[control_id] = f if { f := management.findings[control_id] }
merged[control_id] = f if { f := snmp.findings[control_id] }
merged[control_id] = f if { f := aaa.findings[control_id] }
merged[control_id] = f if { f := logging.findings[control_id] }
merged[control_id] = f if { f := password.findings[control_id] }

findings[control_id] = f if {
	some control_id
	control := controls.controls[control_id]
	control.framework == "CIS"
	f := merged[control_id]
}
