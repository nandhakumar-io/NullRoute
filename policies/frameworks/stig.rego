package compliance.frameworks.stig

import data.compliance.common.controls
import data.compliance.security.management
import data.compliance.security.snmp
import data.compliance.security.aaa
import data.compliance.security.logging
import data.compliance.security.password

merged[control_id] = f { f := management.findings[control_id] }
merged[control_id] = f { f := snmp.findings[control_id] }
merged[control_id] = f { f := aaa.findings[control_id] }
merged[control_id] = f { f := logging.findings[control_id] }
merged[control_id] = f { f := password.findings[control_id] }

findings[control_id] = f {
	some control_id
	control := controls.controls[control_id]
	control.framework == "DISA-STIG"
	f := merged[control_id]
}
