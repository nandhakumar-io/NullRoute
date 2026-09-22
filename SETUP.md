# NullRoute Setup Guide

Welcome to NullRoute! This document details the steps required to set up the multi-vendor network security compliance auditor environment cleanly and safely, including backend services, frontend application, and AI/metric orchestration.

## Prerequisites

- **Docker & Docker Compose**: The entire application relies on Docker for database, AI components, Batfish networks, and message queuing.
- **Node.js** (Optional, for Frontend local dev): If you intend to run the Vite dev server for the frontend layout creation, Node 18+ is recommended.
- **Golang** (Optional, for Fabric Chaincode): Required if you are packaging or building the Hyperledger Fabric Go chaincode locally. Go 1.20+ is recommended.

---

## 1. Environment Configuration

You must create and populate the environment configuration files before starting the containers.

1. **Copy the environment template**:
   ```bash
   cp .env.example .env
   ```

2. **Generate Secret Tokens**:
   The `AUTH_JWT_SECRET` must be set in your `.env` for user authentication to function properly. Without a valid JWT secret, logging into the application will result in a HTTP 500 error.
   
   Generate a secure hex key:
   ```bash
   openssl rand -hex 32
   ```
   *Copy the output of the command and paste it as the value for `AUTH_JWT_SECRET` in `.env`*.

3. **Bootstrap Passwords**:
   In your `.env` file, populate values for initial access:
   - `BOOTSTRAP_ADMIN_PASSWORD`: A secure password (minimum 12 characters). If intentionally left blank, a random one-time-password will be generated and printed to the backend console on the first boot.
   - `MINIO_SECRET_KEY`: Set this to a secure random string for object storage protection.

---

## 2. Docker Service Deployment

The infrastructure spans multiple microservices, primarily: FastAPI, Postgres (pgvector), NATS, Batfish, OPA, and VictoriaMetrics.

To start the full stack, execute:

```bash
docker compose up -d --build
```

**Services Orchestrated:**
- `compliance-backend`: The core Python API.
- `compliance-postgres`: Database instance fitted with PGVector for AI Embeddings.
- `compliance-nats` & `compliance-batfish`: Message queuing handling + config reachability/policy engines.
- **Background Workers**: `scheduler`, `training-worker`, `metrics-poller`, `evidence-verification-worker`.
- **Observability**: `victoriametrics` and `grafana`.

Wait approx 30 seconds for the database schemas and AI models to fully scaffold. You can guarantee the initial bootstrap completed by checking:

```bash
docker compose logs backend | grep -i bootstrap
```

---

## 3. Frontend Application

### Deploying using Docker 
When you execute `docker compose up -d`, the frontend React app mounts via Vite at port `5173`.
Navigate to: [http://localhost:5173/](http://localhost:5173/)

### Developing Locally with Hot-Reloads
If you are modifying react components and need Hot Module Reloading:
```bash
cd frontend
npm install
npm run dev
```
*(Note: Your local Vite server (`vite.config.ts`) acts as a proxy specifically redirecting all `/api/*` requests to the dockerized `localhost:8000` backend in order to naturally avoid CORS constraints).*

---

## 4. Useful Commands for Troubleshooting & Administration

- **Watch Backend Application Logs**:
  ```bash
  docker compose logs -f backend
  ```

- **Encountering Migration State Errors?**:
  If Alembic throws a duplicate tables error preventing boot, fast-forward the state:
  ```bash
  docker compose exec backend alembic stamp head
  ```

- **Check API Swagger Documentation**:
  Available out-of-the-box at [http://localhost:8000/docs](http://localhost:8000/docs) 

- **Demo Configuration Behaviors**:
  If the application appears to log you in automatically upon `/login` landing, double verify that you don't have `AUTH_ENABLED="false"` explicitly hardcoded inside the overarching system `.env` file or `docker-compose.yaml` variable mapping arrays.

---

## 5. Subsystem: Hyperledger Fabric
NetSecAuditor features an immutable evidence anchoring layer backed by Hyperledger Fabric to ensure audit records cannot be retroactively manipulated (compliance requirements). It is isolated inside the `/fabric` directory.

### Bootstrapping the Ledger
You can start the local test-network by executing the bash orchestrator:
```bash
./fabric/scripts/up.sh
```
What this does:
- Clones Hyperledger's official `fabric-samples` into `fabric/network/.fabric-samples`.
- Automatically pulls the required pinned Fabric Docker images (e.g., binaries & CAs).
- Spins up `test-network` along with CouchDB for state storage.
- Creates the dedicated channel `compliance-audit-channel`.
- Generates required crypto material and connection JSONs implicitly utilized by the FastAPI `fabric-gateway`.

### Deploying the Evidence Chaincode
Once the overall network has initialized, you must install the smart contract logic onto the ledger:
```bash
./fabric/scripts/deploy-chaincode.sh
```
This mounts the Go chaincode located traversing `/fabric/chaincode/compliance-evidence/` and approves it onto the channel for incoming audit evidence processing.
