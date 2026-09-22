# AI-Driven Multi-Vendor Network Security Compliance Auditor

### SIH Problem Statement 26155 — MVP

A vendor-agnostic platform that categorizes and normalizes network device configurations against **CIS / NIST SP 800-53 / DISA STIG / ISO 27001** standards using a deterministic rule engine.

The platform uses a dedicated **local AI server** as a supplementary heuristic analyzer for unrecognized or ambiguous configurations.

The AI server provides:

- **DistilBERT** — intent classification
- **MiniLM** — semantic embeddings and retrieval
- **Qwen3-8B** — configuration normalization and remediation generation

**100% free/open-source and self-hostable. No paid cloud AI APIs are required.**

---

## 🚀 Quick Start — Docker Compose

```bash
cp .env.example .env
docker compose up --build -d
```

The Docker stack contains:

- PostgreSQL / pgvector
- MinIO
- OPA
- FastAPI backend
- Vite frontend
- Grafana
- Background workers

The AI models are served by the **Unified AI Server**.

---

# 🤖 Unified AI Server

The project does **not require Ollama**.

The AI models run through a dedicated FastAPI-based server, which can run on a separate GPU machine or on the same machine as the backend.

| Model | Purpose | Endpoint |
|---|---|---|
| `kenpachi-zaraki36/netsecauditor-distilbert-v06` | Intent classification | `/classify` |
| `kenpachi-zaraki36/netsecauditor-minilm-v02` | Semantic embeddings and retrieval | `/embed` |
| `Qwen/Qwen3-8B` | Normalization and remediation generation | `/generate` |

Qwen3-8B uses **4-bit quantization** to reduce GPU memory usage. Qwen generation is limited to one concurrent generation at a time to reduce GPU memory exhaustion.

## AI Server Requirements

Recommended:

- Ubuntu Linux
- NVIDIA GPU
- NVIDIA driver with CUDA support
- Python 3.12+
- Python virtual environment
- Hugging Face token for the private DistilBERT and MiniLM repositories

```bash
sudo apt update
sudo apt install -y python3 python3-venv
nvidia-smi
```

## Create the AI Server Environment

```bash
mkdir -p ~/nullroute
cd ~/nullroute

python3 -m venv .venv
source .venv/bin/activate

pip install torch transformers accelerate bitsandbytes sentence-transformers fastapi uvicorn huggingface_hub
```

## Configure Hugging Face Authentication

```bash
export HF_TOKEN="YOUR_HUGGINGFACE_TOKEN"
```

Do **not** hard-code the token in `server.py`.

The server automatically pulls/verifies these models at startup:

```text
Qwen/Qwen3-8B
kenpachi-zaraki36/netsecauditor-distilbert-v06
kenpachi-zaraki36/netsecauditor-minilm-v02
```

The first startup downloads the models. Later startups use the Hugging Face cache.

## Start the AI Server

Place the unified `server.py` at:

```text
~/nullroute/server.py
```

Start it with:

```bash
cd ~/nullroute
source .venv/bin/activate
uvicorn server:app --host 0.0.0.0 --port 8000
```

The AI server is available at:

```text
http://<AI_SERVER_IP>:8000
```

---

# AI Server API

## Health

```bash
curl http://127.0.0.1:8000/health
```

The endpoint reports the GPU and all loaded models.

Example:

```json
{
  "status": "online",
  "models": {
    "qwen": {
      "status": "loaded",
      "model": "Qwen/Qwen3-8B"
    },
    "distilbert": {
      "status": "loaded",
      "model": "kenpachi-zaraki36/netsecauditor-distilbert-v06"
    },
    "minilm": {
      "status": "loaded",
      "model": "kenpachi-zaraki36/netsecauditor-minilm-v02",
      "embedding_dimension": 384
    }
  }
}
```

## DistilBERT — Intent Classification

```bash
curl -X POST http://127.0.0.1:8000/classify   -H "Content-Type: application/json"   -d '{"text":"set system services ssh"}'
```

## MiniLM — Semantic Embeddings

```bash
curl -X POST http://127.0.0.1:8000/embed   -H "Content-Type: application/json"   -d '{"text":"set system services ssh"}'
```

MiniLM returns a **384-dimensional embedding** used by semantic retrieval and pgvector.

## Qwen3-8B — Normalization and Remediation

```bash
curl -X POST http://127.0.0.1:8000/generate   -H "Content-Type: application/json"   -d '{
    "prompt":"Normalize this Juniper command: set system services ssh",
    "max_new_tokens":128
  }'
```

Qwen is a supplementary AI component. The deterministic compliance engine remains authoritative for compliance evaluation.

---

# 🔗 Backend → AI Server Configuration

Configure the backend `.env`:

```env
AI_CLASSIFIER_REMOTE_URL=http://192.168.1.50:8000/classify
AI_EMBEDDING_REMOTE_URL=http://192.168.1.50:8000/embed
AI_GENERATION_REMOTE_URL=http://192.168.1.50:8000/generate

AI_REMOTE_API_KEY=
AI_REMOTE_TIMEOUT_SECONDS=30

AI_CLASSIFIER_CONFIDENCE_THRESHOLD=0.75
AI_SEMANTIC_THRESHOLD=0.60

AI_MODEL_VERSION=distilbert-v06-minilm-v02-qwen3-8b
```

Replace `192.168.1.50` with the actual AI server address.

### Important

The old Ollama settings are no longer required:

```env
OLLAMA_BASE_URL=
OLLAMA_HOST_URL=
```

The backend communicates directly with the FastAPI AI server.

---

# 🧠 AI Processing Pipeline

```text
Network Configuration
        │
        ▼
Configuration Parser
        │
        ▼
Deterministic Normalization
        │
        ├───────────────┐
        │               │
        ▼               ▼
   DistilBERT        MiniLM
   Classification    Embedding
        │               │
        │               ▼
        │          pgvector Retrieval
        │               │
        └───────┬───────┘
                │
                ▼
          Confidence Check
                │
        ┌───────┴────────┐
        │                │
     Confident        Ambiguous
        │                │
        ▼                ▼
   Known Intent        Qwen3-8B
                         │
                         ▼
                  Normalization /
                  Remediation
                         │
                         ▼
                 Human Review
                         │
                         ▼
               Deterministic Rules
                         │
                         ▼
                  Compliance
                  Evaluation
```

The AI models **supplement** the deterministic compliance engine rather than replacing it.

---

# 💻 Local Development Setup

## Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

---

# 🌐 Accessing the Services

Once the Docker services have stabilized:

- **Frontend SOC Dashboard:** `http://localhost:5173`
- **Backend API Docs:** `http://localhost:8000/docs`
- **Grafana:** `http://localhost:3001`
- **MinIO Console:** `http://localhost:9001`
- **Keycloak Admin:** `http://localhost:8081`

The AI server is accessed separately:

```text
http://<AI_SERVER_IP>:8000
```

---

# 🎯 Running a Demonstration

1. Locate sample configurations in:

```text
sample_configs/
```

2. Upload:

```text
sample_configs/cisco_iosxe_core_sw01.cfg
```

through the **Ingestion** page.

3. Open the **Scan Detail** page.

4. Review:

```text
Parsed
   ↓
Normalized
   ↓
Evaluated
```

5. Review PASS/FAIL compliance results.

6. Inspect parsed evidence and line numbers.

7. Download the results as **PDF/CSV**.

---

# ⛓️ Hyperledger Fabric Integration — Optional

The platform supports optional Hyperledger Fabric integration for non-repudiation and immutable evidence anchoring.

## Prerequisites

```bash
sudo apt update
sudo apt install -y golang
go version
```

## Start Fabric

```bash
make fabric-up
make fabric-deploy
```

Start the gateway:

```bash
FABRIC_ENABLED=true docker compose --profile fabric up --build -d fabric-gateway
```

Configure:

```env
FABRIC_ENABLED=true
```

in `.env`.

---

# 🏗️ Technical Architecture

For the complete architecture covering:

- Configuration ingestion
- Vendor parsing
- Deterministic normalization
- DistilBERT intent classification
- MiniLM semantic retrieval
- pgvector
- Qwen3-8B normalization/remediation
- OPA policy evaluation
- Batfish network simulation
- Human-in-the-loop review
- Compliance standards
- Asynchronous processing
- Evidence generation
- Hyperledger Fabric

see:

```text
ARCHITECTURE.md
```

---

## AI Architecture Summary

```text
┌─────────────────────────────────────────────┐
│          NetSecAuditor AI Server            │
│                                             │
│  DistilBERT v0.6                           │
│  Intent Classification                      │
│                                             │
│  MiniLM v0.2                               │
│  384-d Embeddings / Retrieval               │
│                                             │
│  Qwen3-8B                                  │
│  Normalization / Remediation                │
│                                             │
│              NVIDIA GPU                     │
└──────────────────────┬──────────────────────┘
                       │
                       │ HTTP
                       ▼
┌─────────────────────────────────────────────┐
│           NetSecAuditor Backend             │
│                                             │
│ FastAPI + PostgreSQL + pgvector             │
│ OPA + Batfish + Background Workers          │
└─────────────────────────────────────────────┘
```

---

## Removed from the Old Architecture

The following Ollama configuration is no longer required:

```text
Ollama
compliance-ollama
ollama pull qwen3:8b
ollama pull bge-m3
OLLAMA_BASE_URL
OLLAMA_HOST_URL
```

The current AI stack is:

```text
Qwen3-8B
    +
DistilBERT v0.6
    +
MiniLM v0.2
    ↓
Unified FastAPI AI Server
    ↓
NetSecAuditor Backend
```
