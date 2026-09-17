# AI-Driven Multi-Vendor Network Security Compliance Auditor
### SIH Problem Statement 26155 — MVP

A vendor-agnostic platform that ingests network device configurations (Cisco,
Juniper, Fortinet, Palo Alto, Arista, SONiC — extensible to more), normalizes
them into a common **Security Baseline Model**, evaluates them against
**CIS / NIST SP 800-53 / DISA STIG / ISO 27001** controls using a
**deterministic** rule engine (OPA/Rego + Python — never the LLM), and
produces PDF/JSON/CSV compliance reports with full evidence traceability.

Local AI (Ollama + Qwen3-8B + BGE/E5 embeddings + pgvector RAG) interprets
configuration syntax the deterministic parsers don't recognize, and a
**Training Center** lets an administrator approve/correct low-confidence
interpretations, which are stored back into the vector knowledge base so
future scans recognize the same syntax automatically.

**100% free/open-source, self-hostable. No paid cloud APIs required.**

---

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

This starts: PostgreSQL+pgvector, MinIO, NATS JetStream, OPA, Batfish, Ollama,
Keycloak, OpenBao, the FastAPI backend, the React frontend, VictoriaMetrics,
Grafana, and the background workers (scheduler, metrics-poller,
vuln-sync-worker, evidence-verification-worker, training-worker) — then runs
a one-shot `seed` container that pushes the bundled `sample_configs/`
through the real pipeline so the dashboard is populated immediately.

- Frontend: http://localhost:5173
- Backend API docs: http://localhost:8000/docs
- Grafana: http://localhost:3001 (admin/admin)
- MinIO console: http://localhost:9001 (compliance/compliance123)
- Keycloak admin: http://localhost:8081 (admin/admin)

**Pull the local AI models once Ollama is up** (first run only):
```bash
docker exec compliance-ollama ollama pull qwen3:8b
docker exec compliance-ollama ollama pull bge-m3
```
Until the models are pulled, the AI normalization stage automatically falls
back to a deterministic keyword-similarity heuristic (see
`backend/app/ai/normalize.py`) so the full pipeline still runs end-to-end —
useful for grading/demo environments without GPU access. Swap in Ollama at
any time with zero code changes.

## Local (non-Docker) backend dev

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```
If PostgreSQL isn't reachable, `app/db.py` automatically falls back to a
local SQLite file (`compliance_local.db`) so the API works standalone.

```bash
cd frontend
npm install
npm run dev
```

---

## Demo script (matches the problem statement's target scenario)

1. **Ingestion → Compliance**: Upload `sample_configs/cisco_iosxe_core_sw01.cfg`
   on the *Ingestion* page. Watch the pipeline stages
   (Uploaded → Parsed → Normalized → Evaluated → Completed) on the *Scan
   Detail* page, see the normalized Security Baseline Model, PASS/FAIL
   findings with exact evidence lines, and download a PDF report.
2. **Unknown syntax → Training → Recognition**: The sample Cisco config
   includes one intentionally unmapped line
   (`set fabric-path core-isis-instance enable`). It shows up in the
   *Training Center* with an AI-suggested meaning and confidence score.
   Approve/correct the mapping, then hit **Re-run evaluation** on the scan —
   the mapping is now pulled from the pgvector-backed knowledge base
   (*Knowledge Base* page).

---

## Architecture

```
React (Vite/TS/Tailwind/Monaco/Recharts)
        │
        ▼
FastAPI (Pydantic, SQLAlchemy)  ←→  Keycloak (auth/RBAC)
        │
        ▼
   NATS JetStream (event bus)
        │
 ┌──────┼──────────────┬─────────────────┐
 ▼                      ▼                 ▼
Parsers            Ollama+Qwen3-8B     OPA / Rego
(deterministic)     + BGE/E5 + RAG    + Python rule
                    (pgvector KB)       engine
 └──────────────────────┼─────────────────┘
                         ▼
              Security Baseline Model
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
     PostgreSQL + pgvector        MinIO
              │                     │
              ▼                     ▼
          Findings            Evidence/Reports
              │
              ▼
      Remediation Engine → PDF/JSON/CSV (ReportLab)

OpenTelemetry → VictoriaMetrics → Grafana
```

### Why the LLM never decides compliance
`app/services/compliance.py` and `policies/baseline.rego` are the **only**
places a PASS/FAIL verdict is produced. Both consume nothing but the
flattened, Pydantic-validated Security Baseline Model — no raw AI text ever
reaches the evaluation layer. The AI's confidence score only controls
whether a mapping is auto-applied or routed to the Training Center for human
sign-off (`AI_CONFIDENCE_THRESHOLD`, default 0.75).

### Adding a new vendor
1. Add detection signatures in `backend/app/services/vendor_detect.py`.
2. Add a deterministic rule list in `backend/app/services/parsers.py`
   (`VENDOR_RULES["NewVendor"] = [...]`).
3. Nothing else changes — the compliance engine, controls catalog,
   Training Center, and reporting all operate purely on the normalized
   Security Baseline Model, so they're automatically vendor-agnostic.

### Adding a new control
Add one entry to `backend/app/policies/controls.py` (and, if using the OPA
path, mirror it in `policies/baseline.rego`). It applies to every vendor
immediately.

---

## Project layout

```
backend/            FastAPI service (parsers, AI/RAG, compliance engine, reports)
  app/models/        Pydantic Security Baseline Model + SQLAlchemy ORM
  app/services/      vendor detection, parsers, pipeline, compliance, reports,
                      opa_service, batfish_service, risk_engine, evidence_service, fabric_service
  app/ai/            Ollama/RAG normalization (with offline fallback)
  app/policies/      framework-independent control catalog
  app/routers/       REST API endpoints
frontend/           React + TS + Vite + Tailwind SOC dashboard
policies/           Rego policy bundle (OPA authoritative decision engine)
fabric/             Hyperledger Fabric chaincode + network bootstrap scripts
fabric-gateway/     Node/TS bridge between FastAPI and the Fabric Gateway API
sample_configs/     Realistic demo configs (Cisco, Juniper, Fortinet, PAN-OS, Arista, SONiC)
docker-compose.yml  Full self-hosted stack
Makefile            up / down / reset / demo / fabric-* convenience targets
```

## What's intentionally scoped down for the MVP
- **Auth**: Keycloak is wired into docker-compose and the architecture, but
  the FastAPI routes are not yet gated behind a validated JWT — see
  `app/main.py` CORS/middleware comment. Wiring `python-jose` token
  validation against Keycloak's JWKS endpoint is the next step before any
  non-demo deployment.
- **Live device collection** (Scrapli/Netmiko/ncclient/RESTCONF/PySNMP) is
  designed for in the architecture but the MVP ships with file-upload
  ingestion only; the parser layer is agnostic to how bytes arrive, so
  wiring a `services/collectors.py` that calls Netmiko and feeds the same
  `run_pipeline()` is additive, not a redesign.
- **OpenTelemetry instrumentation** is not yet emitting spans/metrics from
  the FastAPI app; VictoriaMetrics/Grafana containers are running and ready
  to receive them (`docs/observability-todo.md`).
- **MinIO** is provisioned in docker-compose for raw config/evidence/report
  storage per the architecture, but the MVP currently keeps the baseline
  JSON in Postgres and streams reports directly to the client rather than
  persisting them to a bucket first — swapping in a MinIO write in
  `services/reports.py` is a small addition.

These are flagged explicitly rather than silently omitted so a reviewer can
see exactly what's demo-ready today versus what's next on the roadmap.

## Batfish — network-behavior analysis engine

`backend/app/services/batfish_service.py` integrates the official
`batfish/allinone` Docker image (pinned, see `docker-compose.yml`) via
PyBatfish to answer the question OPA structurally can't: *given this
config, what can actually reach what?*

**Pipeline placement**: runs immediately after OPA (`pipeline.py` stage 5),
before the risk engine and correlation layer. Its output — a list of
behavioral findings plus a `critical_violation` flag — feeds directly into
`risk_engine.calculate_risk()` and `change_validation_service.correlate()`,
which already had the parameters wired for this from the OPA phase.

**What it checks, at minimum, per scan**: Guest→Management reachability,
Internet→Management reachability, User→Server reachability, management
VLAN isolation from Guest/User/Internet, ACL reachability/shadowed-rule
analysis, and default-route presence. Zone membership (which
interfaces/VLANs are "Guest" vs "Management" etc.) is inferred from
interface descriptions and VLAN naming conventions in the raw config text
(`batfish_service.infer_zones`) — when a zone can't be located for a given
vendor/config, that specific check reports `BATFISH_UNSUPPORTED` rather
than being skipped silently or reported as a pass.

**Explicit status contract** (RULE 13 — a Batfish-unsupported or
-unavailable result is never reported as compliant):

| Status | Meaning |
|---|---|
| `BATFISH_PASS` | Behavior matched the expected policy (e.g. Guest genuinely cannot reach Management). |
| `BATFISH_FAIL` | A behavioral violation was found — feeds `risk_engine` and can escalate `correlate()` to BLOCK. |
| `BATFISH_UNSUPPORTED` | Vendor (Fortinet/PAN-OS) or zone data isn't available for this check. |
| `BATFISH_UNAVAILABLE` | The Batfish coordinator container couldn't be reached. |
| `BATFISH_ERROR` | Batfish ran but the query itself raised. |
| `NOT_INTEGRATED` | `BATFISH_ENABLED=false`. |

**Snapshots**: each scan gets its own working directory under
`BATFISH_SNAPSHOT_ROOT/scan-<id>/candidate/configs/` (never overwriting the
originally uploaded file), cleaned up after analysis completes.
`BATFISH_REQUIRED=true` makes an unsupported/unavailable result escalate
the final compliance decision to REVIEW even if OPA alone would PASS.

**Backend endpoints**: `GET /api/scans/{id}/batfish` (full result: nodes,
interfaces, routes, reachability checks, init issues) and `GET
/api/scans/{id}/opa` (policy decision detail), both backing new frontend
pages.

**Frontend**: `frontend/src/pages/BatfishAnalysis.tsx` (linked from Scan
Detail's new OPA/Batfish/Risk summary row) shows network/snapshot identity,
node count, the critical-violation flag, every reachability/behavioral
check with source→destination zone and PASS/FAIL/UNSUPPORTED state, and
every Batfish initialization issue (parser warnings are always visible,
never hidden).

**Tests**: `backend/tests/test_batfish_service.py` covers vendor-support
detection, zone inference, the disabled/unavailable/unsupported/error
short-circuit paths, reachability PASS/FAIL/ERROR outcomes, init-issue
surfacing, and that `correlate()` correctly escalates to BLOCK on a
critical Batfish violation and to REVIEW-or-PASS (per
`BATFISH_REQUIRED`) on an unsupported result.

**Still open for a future phase**: before/after (CURRENT vs PROPOSED)
snapshot comparison wired into the pipeline (the `compare_snapshots()`
function exists in the service but isn't yet called from `pipeline.py`,
since today's pipeline only evaluates a single uploaded config rather than
a proposed-change diff), and OpenTelemetry-style structured metrics for
`batfish_analysis_duration`/`batfish_failures`/`batfish_unsupported`.

## Hyperledger Fabric — immutable evidence anchor

`backend/app/services/fabric_service.py` never talks to Fabric directly.
It calls an internal-only bridge, `fabric-gateway/` (Node.js/TypeScript,
`@hyperledger/fabric-gateway`), which holds the actual peer connection,
MSP identity, and TLS material. FastAPI/the browser never see Fabric
certificates or private keys (section 18/35).

**Chaincode**: `fabric/chaincode/compliance-evidence/` (Go,
`fabric-contract-api-go`) implements `CreateEvidence` (idempotent —
re-anchoring the same `evidenceId` returns the original anchor rather than
erroring or duplicating), `GetEvidence`, `VerifyEvidence`,
`GetEvidenceHistory`, `GetEvidenceByScan`, and `GetEvidenceByHash`. The
on-chain `EvidenceAnchor` asset holds only hashes, decisions, and ids —
never raw configuration text or credentials (RULE 11).

**Network**: `fabric/scripts/up.sh` bootstraps a local network using the
official `hyperledger/fabric-samples` test-network (pinned Fabric/CA
versions, TLS + CouchDB enabled), creates the `compliance-audit-channel`
channel, and exports the connection/crypto material `fabric-gateway` needs
into `fabric/network/`. `fabric/scripts/deploy-chaincode.sh` packages,
installs, approves, and commits the chaincode via the network's own
multi-org approval flow. `down.sh`/`reset.sh`/`health.sh` round out the
lifecycle (section 36); `make fabric-up`, `make fabric-deploy`, `make
demo` wrap these at the repo root.

**Pipeline placement**: after evidence is built, canonicalized, hashed,
and stored off-chain (`pipeline.py` stage 8), the pipeline anchors it —
best-effort, never blocking the scan result. If `FABRIC_ENABLED=false`
(the default), evidence stays fully valid off-chain with
`fabric_status=NOT_ANCHORED`. If Fabric is enabled but `fabric-gateway`
is unreachable, the record is marked `FABRIC_UNAVAILABLE` — the pipeline
never reports a false "anchored" status or a fabricated transaction id
(section 19, RULE 15).

**Verification**: `POST /api/evidence/{id}/verify` recomputes the SHA-256
of the stored evidence JSON (off-chain check, always run) and — when
Fabric is enabled and the record was anchored — additionally asks
`fabric-gateway` to compare that hash against the on-chain `evidenceHash`
(on-chain check). Either side reporting a mismatch flips the result to
`INTEGRITY_FAILURE`. The Evidence Ledger UI
(`frontend/src/pages/EvidenceLedger.tsx`) shows Stored Hash vs Calculated
Hash side by side plus the on-chain match result, and the existing
**Simulate Evidence Tampering** / **Restore** actions only ever touch the
off-chain PostgreSQL record — never Fabric — so tampering is reliably
caught by the on-chain comparison even if someone edits the database
directly (section 30).

**Enabling it**:
```bash
make fabric-up        # clones+builds fabric-samples test-network on first run (needs internet)
make fabric-deploy     # packages/installs/commits the compliance-evidence chaincode
docker compose --profile fabric up --build -d fabric-gateway
# then set FABRIC_ENABLED=true in .env (or export it) and restart the backend
```

**Tests**: `backend/tests/test_fabric_service.py` covers the
disabled/not-configured path, gateway-unreachable-after-retries, a 5xx
gateway response never being reported as a successful anchor, and
verify/history round-trips against a mocked gateway (`respx`).

**Known limitation**: the Fabric network bring-up (`fabric/scripts/up.sh`)
and `fabric-gateway`'s live gRPC connection to a real peer have not been
executed end-to-end in this environment (no Docker daemon / no access to
Fabric's binary distribution host from this sandbox) — the chaincode,
gateway service, and Python client were built and, where the environment
allowed, compiled/type-checked and unit-tested against a mocked gateway,
but a full `make demo` run against real Fabric peers is unverified. Please
run it in a normal Docker-enabled environment and report back if
`up.sh`/`deploy-chaincode.sh` need adjustment for your Fabric version.

