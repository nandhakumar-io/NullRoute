package compliance.security.snmp

import data.compliance.common
import data.compliance.common.controls

findings[control_id] = f if {
	some control_id
	control := controls.controls[control_id]
	control.domain == "snmp"
	actual := object.get(input.baseline, control.parameter, null)
	f := common.make_finding(control_id, control, actual)
}
