# Changes applied to backend/

## 1. `app/main.py` — CORS was wide open (real vuln, `test_cors_configuration.py`)
`main.py` still hard-coded `allow_origin_regex=".*"` + `allow_credentials=True`.
Starlette echoes the request's `Origin` back for that combo, so it granted
**every origin on the internet credentialed access** — the `CORS_ALLOWED_ORIGINS`
env var the test file expects wasn't even read. Replaced with logic that:
- unset/empty → no cross-origin access
- `"*"` → wildcard access, credentials forced off
- comma-separated allow-list → only those origins, with credentials

## 2. `app/main.py` — `custom_controls` router was never mounted
`app/routers/custom_controls.py` (the CRUD + approval endpoints you asked
about) already existed and was fully implemented, but was missing from both
the `from app.routers import (...)` block and the `app.include_router(...)`
calls — every one of those endpoints was a 404 in a running server despite
the code being correct. Added the import and `app.include_router(custom_controls.router)`.

## 3. `app/routers/scans.py` — new `GET /{scan_id}/remediation-suggestions`
`test_change_requests.py::test_remediation_suggestions_never_invents_config`
hits `/api/scans/{scan_id}/remediation-suggestions` expecting a deterministic
response built from each FAIL finding's stored `remediation` text. The only
existing route was `/{scan_id}/remediation`, which calls an LLM
(`remediation_service.generate_remediation_cli_for_scan`) to *synthesize*
CLI config — different path, different (and riskier) behavior. Added the
new endpoint alongside the old one; it never calls the LLM, just echoes
each FAIL finding's `control_id`/`title`/`severity`/`parameter`/`remediation`
and an explicit "has not generated configuration" note.

## What I verified were already fixed (matches your bullet list, but the
code in the zip already has them — no action needed)
- `devices.py`: `DELETE /{device_id}`, `/bulk/delete`, `/bulk/enable`,
  `/bulk/disable` all exist; `_scoped_query()` tenant-scopes every read;
  `create_device` dedups on `management_address` within a tenant (409).
- `evidence.py`: every endpoint now threads `tenant_id` through
  `_tenant_scoped_evidence()` — cross-tenant reads 404 rather than leaking.
- `policies/baseline.rego` already `import data.compliance.custom` and
  folds `custom.findings` into the aggregate + `in_scope()`.
- `compliance.py::evaluate_baseline_via_opa` already calls
  `custom_control_service.for_opa_input()` to build `input.custom_controls`.
- `custom_control_service.py` already has the full `pending_review` →
  `approve()`/`reject()` lifecycle writing `status`/`approved_by`/`approved_at`.

## Not independently re-verified
This sandbox has no network/package access, so I could not `pip install`
and run `pytest`. I statically read `app/services/openbao_service.py`
(`redact_secret_values`) against `test_credential_redaction.py` and it
looks correct; I did not do a full root-cause pass on `test_device_gateway.py`
or `test_network_scan_service.py` (large files, no obvious bugs on a
spot read) — worth running the full suite to confirm before considering
those closed.