package compliance.security.management

# SSH / Telnet / HTTP / banner controls — anything under the "management"
# domain of the control catalog.

import data.compliance.common
import data.compliance.common.controls

findings[control_id] = f if {
	some control_id
	control := controls.controls[control_id]
	control.domain == "management"
	actual := object.get(input.baseline, control.parameter, null)
	f := common.make_finding(control_id, control, actual)
}
