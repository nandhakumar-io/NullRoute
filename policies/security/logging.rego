package compliance.security.logging

import data.compliance.common
import data.compliance.common.controls

findings[control_id] = f {
	some control_id
	control := controls.controls[control_id]
	control.domain == "logging"
	actual := object.get(input.baseline, control.parameter, null)
	f := common.make_finding(control_id, control, actual)
}
