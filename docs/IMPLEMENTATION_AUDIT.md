# Implementation Audit

Scope note: this audit and the fixes below were produced from a single pass over
the repository as uploaded. The full 62-section brief (V4 dataset generation,
model retraining, full Keycloak/tenant test matrix, end-to-end demo, etc.) is a
multi-week program of work, not something that can be honestly completed in one
pass — so this document reports what was actually inspected and actually fixed,
not a claim that all 62 sections are done.

## What was inspected
- `backend/app/services/**` (deployment, config_injection, verification, ai,
  evidence/fabric/opa/batfish/minio/openbao wrappers) — all files `py_compile`d
  cleanly after fixes.
- `backend/app/routers/**`, `frontend/src/pages/**` — listed, checked for
  duplicate pages (none found).
- `.env.example` — checked against flags actually read via `os.environ` in code.

## Bugs found and fixed in this pass

1. **Corrupted filename `backend/app/services/registry.[y`** — a stray file
   with a broken extension sitting next to `registry.py`. Removed (dead
   weight, not imported anywhere).

2. **Dead duplicate service modules** at `backend/app/services/` top level:
   `gnmi.py`, `openconfig.py`, `pyats_genie.py`, `registry.py`, `result.py`,
   `ssh.py`. These were byte-for-byte or near-identical earlier drafts of the
   code that now correctly lives in the `services/config_injection/`,
   `services/verification/`, and `services/deployment/` sub-packages. Verified
   with a repo-wide grep that **nothing** imports the top-level versions
   (only `deployment_service.py`, `config_injection/registry.py`, and
   `verification/registry.py` are actually wired in, all pointing at the
   sub-packages). Deleted the six dead files. This directly matches the
   "duplicate implementations / dead code" risk called out in the brief —
   left in place, they're a real hazard: a future edit could touch the dead
   copy and silently do nothing.

3. **Missing `.env.example` entries** for the optional OpenConfig/gNMI and
   pyATS/Genie feature flags. The code already reads `GNMI_ENABLED`,
   `OPENCONFIG_ENABLED`, and `PYATS_ENABLED` via `os.environ.get(...)` with
   safe `false` defaults (confirmed in `config_injection/gnmi.py` and
   `verification/pyats_genie.py`), so behavior was already correct and
   optional-by-default — but the flags were undocumented, so an operator
   reading `.env.example` would not know they exist or how to turn them on.
   Added `OPENCONFIG_ENABLED`, `GNMI_ENABLED`, `GNMI_TIMEOUT`, `GNMI_PORT`,
   `GNMI_TLS_ENABLED`, `GNMI_CA_CERT`, `GNMI_CLIENT_CERT`, `GNMI_CLIENT_KEY`,
   `OPENCONFIG_MODEL_PATH`, `PYATS_ENABLED`, `PYATS_TESTBED_PATH`,
   `PYATS_TIMEOUT`, `PYATS_VERIFY_COMMANDS`, all defaulted off/safe, with
   comments reiterating the ChangeRequest-only workflow rule (section 24)
   and the "never authoritative" rule for pyATS.

4. Full `py_compile` pass over every `.py` file in `backend/` — no syntax
   errors found after the cleanup above (there were none before it either;
   the dead files were syntactically valid, just unused).

## Verified as already correctly implemented (spot-checked, not rewritten)
- `services/deployment/registry.py` — `get_deployer()` never silently
  substitutes a transport; `netconf` returns an explicit
  `NotImplementedError`-carrying result, `gnmi` returns explicit
  `GNMI_DISABLED`/`GNMI_UNAVAILABLE`/etc. statuses from `GnmiDeployer` rather
  than falling back — matches spec section 27.
- `config_injection/gnmi.py` — gated on `GNMI_ENABLED`, returns
  `GnmiResult(success=False, status=GNMI_DISABLED, ...)` rather than raising
  or faking success when disabled.
- `verification/pyats_genie.py` — gated on `PYATS_ENABLED`, and
  `deployment_service.py` only invokes it as supplemental post-deployment
  evidence, not as an authority over OPA/Batfish.
- No duplicate/near-duplicate frontend pages under `frontend/src/pages/`.

## Not inspected / not attempted in this pass (explicitly out of scope here)
- V4 dataset generation, leakage audit, DistilBERT retraining, MiniLM
  reference rebuild, hybrid calibration, error analysis (sections 6–17).
  These require the actual training data/model artifacts and a training run;
  none of that was present in the uploaded archive to operate on.
- Full Keycloak/tenant-isolation/credential-leak test matrix (sections
  18–20, 55) — would need a running Postgres/Keycloak/OpenBao stack to
  execute meaningfully rather than just read code.
- Mocked gNMI/pyATS test suites (sections 28, 34) — not present; adding a
  full suite is a substantial follow-on task, happy to do it as a next step
  if you want to scope it specifically.
- End-to-end demo run (section 56) — requires the docker-compose stack
  actually running.

## Follow-up pass: closed the two missing gNMI test scenarios

The mocked gNMI/pyATS suites (`test_config_injection_gnmi.py`,
`test_verification_pyats.py`, `test_change_request_gnmi_deploy_e2e.py`)
already covered nearly everything section 28/34 asks for. Two scenarios
called out explicitly in section 28 were genuinely missing, so they were
added to `test_change_request_gnmi_deploy_e2e.py` (same router-level,
no-real-network pattern as the existing e2e tests):

- `test_gnmi_deploy_aborts_on_stale_pre_change_hash` — proves
  `deployment_service.deploy_change_request` aborts with
  `status=ABORTED_STALE_HASH` *before* the gNMI injector's `capabilities()`
  or `set()` is ever called, when the device's live config no longer
  matches the hash the ChangeRequest was validated against (spec 25/43).
  The injector in this test raises `AssertionError` if called at all, so
  the test fails loudly if that ordering ever regresses.
- `test_gnmi_deploy_marks_drifted_on_post_verification_mismatch` — proves
  that if the gNMI `Set` reports success but the post-deployment collected
  config hash doesn't match the approved proposed hash, the
  `DeploymentRecord` is marked `DRIFTED` with `post_verification_passed=False`
  (spec 44), while the `ChangeRequest` itself is `DEPLOYED` (the push did
  happen — the drift is the reportable problem, not an undone deployment).

While writing the first test, found that `ChangeRequest.current_config_hash`
is only populated from the device's most recent prior `Scan` at CR-creation
time (`change_request_service.latest_known_config`), not re-collected live —
so a never-before-scanned device has `current_config_hash=None` and the
stale-hash check is a documented no-op. That's existing, intentional
behavior (not a bug), but it meant the test needed to monkeypatch a baseline
config in rather than relying on a bare new device. No production code was
changed for this — the intentional-no-op case just makes the test setup
slightly more deliberate.

Ran the full backend suite after these additions: **138 passed, 0 failed**
(`pytest tests/` from `backend/`), including all pre-existing tests — the
new tests are additive and nothing regressed.

## Follow-up pass 2: tenant-isolation test matrix (section 19)

`test_evidence_tenant_isolation.py`, `test_training_knowledge_tenant_isolation.py`,
and `test_change_requests.py` already covered evidence, training/knowledge-base
mappings, and change requests. Added `tests/test_cross_tenant_isolation_matrix.py`
closing the remaining gaps from the section-19 list, using the same
seed-a-second-tenant-directly-in-the-DB pattern as the existing tests:

- **Devices**: list excludes another tenant's device; get/collection-status/
  drift-by-device all 404 rather than leaking the other tenant's row.
- **Drift events**: list excludes another tenant's drift event.
- **Alerts**: list excludes another tenant's alert; acknowledging another
  tenant's alert 404s, and a DB check confirms it genuinely wasn't mutated.
- **Schedules**: list/get/patch/delete/run all 404 for another tenant's
  schedule; delete is confirmed to be a no-op via a DB check.
- **Compliance exceptions**: list excludes another tenant's exception;
  approve/reject both 404, and a DB check confirms the exception's status
  stayed `PENDING` (a cross-tenant approve/reject would otherwise silently
  override another tenant's OPA-derived finding — spec 45).

Result: **all 15 new tests passed on the first correctness pass** (one
early failure was in the test's own fixture data — `ComplianceException.
expires_at` is `nullable=False` and the first draft omitted it, an
IntegrityError caught immediately by running the test, not a bug in the
application). No application code needed to change: every router already
threaded `get_current_tenant()` through its queries correctly. This is a
genuinely good finding — it means the isolation *behavior* now has test
coverage locking it in place, rather than resting on a one-time manual
code read.

Full suite after this addition: **153 passed, 0 failed**
(`pytest tests/` from `backend/`).

## Follow-up pass 3: OpenBao secret-leak hardening (section 20)

Read every consumer of `openbao_service.get_device_credentials`/
`DeviceCredentials` (collectors, deployers, the pyATS verifier) and every
log/error/evidence/report path that could plausibly touch a secret. The
existing design was already good: `credential_ref` (not hostname/IP) is
the only thing that ever reaches PostgreSQL, `DeviceCredentials.secret` is
consistently scoped tightly to a single call, `VerificationResult.
as_metadata()` explicitly excludes credentials, and grepping for
log statements that mention credential/secret/password/token turned up
nothing suspicious.

The one real, if narrow, gap: several collectors/deployers/verifiers build
`error=f"...: {e}"` strings directly from third-party library exceptions
(netmiko, ncclient, pygnmi, pyats/unicon, httpx, pysnmp) while a
`credentials.secret` dict is in scope. Those libraries' exact exception
wording isn't under this codebase's control, and some versions of some
network-automation libraries are known to echo connection parameters —
including cleartext passwords — into exception messages. That `error`
string then flows into `CollectionResult`/`DeploymentResult`/
`VerificationResult`, which get persisted onto `Device.
last_collection_error`, `DeploymentRecord.error`, alerts, and reports.

Added `redact_secret_values(text, secret)` to `openbao_service.py` (the
one module already permitted to touch secret material) as a
defense-in-depth backstop: before any such exception-derived string is
returned, scrub every value from the in-scope `secret` dict that appears
verbatim in it (skipping values under 4 chars, e.g. port numbers, which
aren't meaningfully secret and would just mangle unrelated text). Wired
this into every exception-to-`error` site that has `secret`/`credentials`
in scope:

- `collectors/base.py` — the shared `timed()` catch-all wrapping every
  collector (SSH/NETCONF/RESTCONF/SNMP)
- `collectors/ssh.py`, `collectors/netconf.py`, `collectors/restconf.py`,
  `collectors/snmp.py` — their own specific except clauses
- `deployment/base.py` — the shared deployer `timed()` catch-all
- `deployment/ssh.py` — its specific except clauses
- `config_injection/gnmi.py` — both `capabilities()` and `set()` except
  blocks
- `verification/pyats_genie.py` — testbed-load and connect except blocks

Added `tests/test_credential_redaction.py`: unit tests for
`redact_secret_values` itself (redacts a leaked password, redacts
multiple distinct secret values, leaves clean text untouched, doesn't
mangle short values like port numbers, handles empty/None secrets, skips
non-string values), plus a regression test that mocks netmiko's
`ConnectHandler` to raise an exception whose message embeds the real
password, and confirms `SSHCollector.collect_config` never lets that
password reach `CollectionResult.error`.

Full suite after this addition: **160 passed, 0 failed**.

## Recommendation for next step
Given the size of the remaining spec, the highest-value next slice is
probably either (a) the mocked gNMI/pyATS test suites in section 28/34,
since the adapters already exist and are wired correctly, or (b) actually
booting `docker-compose` here to smoke-test the stack end-to-end. Let me know
which you'd like to tackle next and I'll go deep on that one instead of
spreading thin across all 62 sections at once.
