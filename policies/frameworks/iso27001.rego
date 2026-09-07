package compliance.frameworks.iso27001

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
	control.framework == "ISO-27001"
	f := merged[control_id]
}
