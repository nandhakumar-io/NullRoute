# AI-Driven Multi-Vendor Network Security Compliance Auditor

### SIH Problem Statement 26155 — MVP

A vendor-agnostic platform that categorizes and normalizes network device configurations against **CIS / NIST SP 800-53 / DISA STIG / ISO 27001** standards using a deterministic rule engine.

## 🚀 Live Demo

A deployed instance of NetSecAuditor is available for evaluation:

https://nullroute.notoriousdev.in 

## 🛠️ Full Local Capability & Air-Gapped Setup

NullRoute is designed with **100% Full Local Capability**. The entire application stack—including the database, backend, frontend, policy engine, and all AI processing—runs strictly local on your own hardware via Docker Compose.

**Absolutely no data sends external to your network.** The AI models are run through a dedicated on-premise inference server, making it fully suitable for highly secure, strictly air-gapped environments.

The local AI server provides:

- **DistilBERT** — intent classification
- **MiniLM** — semantic embeddings and retrieval
- **Qwen3-8B** — configuration normalization and remediation generation

**100% free/open-source and self-hostable. No paid cloud AI APIs are required.**

---

## 🚀 Quick Start — Docker Compose

```bash
git clone https://github.com/nandhakumar-io/Tesseract.git
cd Tesseract
cp .env.example .env

For a strong random MinIO secret key, run:

openssl rand -base64 32

Install docker and compose

sudo apt install docker.io docker-compose-v2

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

- Ubuntu 22.04 / 24.04 LTS (recommended)
- NVIDIA GPU with ≥ 8 GB VRAM (16 GB recommended for Qwen3-8B)
- NVIDIA driver ≥ 525 and **CUDA 12.x**
- Python 3.10 – 3.12
- Python virtual environment
- Hugging Face token (only needed for private/gated repos)

---

## 1 — Install NVIDIA Driver & CUDA Toolkit

> Skip this section if `nvidia-smi` already shows CUDA 12.x.

```bash
# Verify your current driver / CUDA version
nvidia-smi

# --- Ubuntu 22.04 / 24.04 ---

# Add the official NVIDIA CUDA repo keyring
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt update

# Install CUDA 12.4 toolkit (includes compiler, libraries, cuDNN stub)
sudo apt install -y cuda-toolkit-12-4

# Install cuDNN 9 (required by PyTorch for GPU acceleration)
sudo apt install -y libcudnn9-cuda-12 libcudnn9-dev-cuda-12

# Reload PATH so nvcc is found
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# Confirm
nvcc --version
nvidia-smi
```

> **Reboot** after a fresh driver install before proceeding:
> ```bash
> sudo reboot
> ```

---

## 2 — Create the AI Server Python Environment

```bash
mkdir -p ~/nullroute
cd ~/nullroute

# Install venv support if missing
sudo apt install -y python3.12-venv

python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip first
pip install --upgrade pip

# Install PyTorch with CUDA 12.4 wheels (matches the toolkit above)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# Install remaining AI server dependencies
pip install \
  transformers \
  accelerate \
  bitsandbytes \
  sentence-transformers \
  fastapi \
  uvicorn \
  huggingface_hub

# Verify CUDA is visible to PyTorch
python3 -c "import torch; print('CUDA available:', torch.cuda.is_available()); print('GPU:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'None')"
```

Expected output:
```
CUDA available: True
GPU: NVIDIA GeForce RTX ...
```

If `CUDA available: False`:
- Check `nvidia-smi` is working (driver issue)
- Confirm the `torch` wheel matches your CUDA version (`cu124` above)
- See [PyTorch Get Started](https://pytorch.org/get-started/locally/) for other CUDA versions

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

Place the unified `ai_server.py` at:

```text
~/nullroute/ai_server.py
```

Start it with:

```bash
cd ~/nullroute
source .venv/bin/activate
uvicorn ai_server:app --host 0.0.0.0 --port 8000
```

The AI server is available at:

```text
http://<AI_SERVER_IP>:8000
```

## Run as a Persistent systemd Service (Recommended)

A ready-made systemd unit file is included in the repo at `deploy/nullroute-ai.service`.

This keeps the AI server running across reboots and restarts it automatically if it crashes.

```bash
# 1. Copy the service file to the system directory
sudo cp deploy/nullroute-ai.service /etc/systemd/system/nullroute-ai.service

# 2. Edit the file if your username or path differs from the defaults
#    (default: User=mine, WorkingDirectory=/home/mine/nullroute)
sudo nano /etc/systemd/system/nullroute-ai.service

# 3. Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable nullroute-ai
sudo systemctl start nullroute-ai

# Check status
sudo systemctl status nullroute-ai

# Watch live logs
sudo journalctl -u nullroute-ai -f
```

To stop or restart manually:

```bash
sudo systemctl stop nullroute-ai
sudo systemctl restart nullroute-ai
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
      "model": "kenpachi-zaraki36/nullrouteauditor-distilbert-v06"
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

**Replace `192.168.1.50` with the actual AI server address.**

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
sudo apt install make
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
##  Remediations generated by local llm(qwen 3 used in our prototype) is not 100% accurate but can be imporved if used higher parameter reasoning models in future
