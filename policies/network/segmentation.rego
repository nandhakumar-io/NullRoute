package compliance.network.segmentation

# IMPORTANT: real network-behavior segmentation checks (e.g. "can Guest VLAN
# reach the Management VLAN?") require forwarding-plane/reachability
# analysis that OPA cannot perform from a single device's config alone —
# that is Batfish's job (backend/app/services/batfish_service.py, not yet
# wired into this deployment).
#
# This file intentionally contributes NO findings today. It must never be
# used to fabricate a segmentation PASS — an absent Batfish integration
# means segmentation is UNVERIFIED, not compliant (problem-statement RULE 13:
# "never treat Batfish unsupported as PASS"). The change_validation_service
# correlation layer is responsible for surfacing that segmentation checks
# were not run, rather than this package inventing a result it cannot back
# with real evidence.

findings = {}
