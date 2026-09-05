package compliance.metadata

# Bump this whenever a control is added/changed/removed. The backend reads
# this via GET /v1/data/compliance/metadata/version and stamps it onto every
# OPA decision and evidence record, so evidence is always traceable to the
# exact policy revision that produced it.
version := "1.0.0"

frameworks := ["CIS", "NIST-800-53", "DISA-STIG", "ISO-27001"]
