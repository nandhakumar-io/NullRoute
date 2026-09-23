# 🏗️ Deep Technical Architecture

This document breaks down the structural design and critical technical decisions powering the NullRoute compliance platform.

```text
React (Vite/TS/Tailwind/Monaco)
       │
       ▼
FastAPI (Pydantic, SQLAlchemy)  ←─→  Keycloak (OIDC/RBAC)
       │
       ▼
  NATS JetStream (Async Event Bus)
       │
 ┌─────┼────────────────────────┬──────────────────┐
 ▼     ▼                        ▼                  ▼
CLI   Deterministic Parsers   Unified AI Server  OPA / Rego Engine
      (Regex/AST driven)      (FastAPI/Qwen3)
 └──────────────────────────────┼──────────────────┘
                                ▼
                   Security Baseline Model (Pydantic)
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
   PostgreSQL/pgvector                   MinIO (S3 Object Store)
             │                                     │
             ▼                                     ▼
        Scan Findings                        Immutable Evidence / Reports
             │                                     │
             ▼                                     ▼
  Remediation Generation               Hyperledger Fabric Chaincode
```

## 1. Compliance Determinism and AI Boundaries
- **Separation of Concerns**: The LLM engine is strictly prohibited from making authoritative compliance decisions. Evaluative pass/fail judgments are exclusively the domain of `app/services/compliance.py` and the `policies/baseline.rego` engine. The evaluation layer consumes **only** the flattened, Pydantic-validated Security Baseline Model (meaning raw AI-generated text is never evaluated for compliance rules).
- **RAG Normalization pipeline**: `app/ai/staged.py` orchestrates the AI interpretation of unknown configuration lines. It caches known meanings, uses pgvector for semantic search (BGE-m3 embeddings) against a continuous `CommandMapping` feedback loop, and only queries the Unified AI Server for novel, unmapped instructions.
- **Automated Human-In-The-Loop (HITL)**: Unrecognized configuration parameters translated by the LLM are bound by an `AI_CONFIDENCE_THRESHOLD` (defaults to 0.75). Interpretations beneath this threshold pause the baseline execution pipeline and seamlessly route into the Training Center for human operator sign-off before being introduced into the validated Security Baseline.

## 2. Advanced Network Behavior Profiling (Batfish Integration)
A significant element of the pipeline is executing dynamically simulated reachability tests outside the static confines of a router configuration.
- **Batfish Event Trigger**: Executes explicitly post-OPA normalization (`pipeline.py` stage 5).
- **Inherent Threat Escalation**: It evaluates cross-vlan boundaries dynamically (e.g., verifying if the Guest VLAN can route to the Management VLAN despite OSPF boundaries). If Batfish registers a critical constraint failure (`BATFISH_FAIL`), it directly correlates into the `risk_engine`, overriding general policy findings and instituting a hard pipeline `BLOCK`.

## 3. Structural Parsing & Topology Fallback
- **Dual Pipeline Extraction:** NullRoute splits factual parameter extraction (like `ssh.enabled`) from structural extraction (like VLAN definitions). `structure_parser.py` maps known hierarchical or flattened topology syntax (`EXTRACTED_VLAN`, `EXTRACTED_INTERFACE`) into memory.
- **LLM Topology Fallback:** Any line that evades the deterministic structural regex is dynamically analyzed by `topology_llm_fallback.py` (which leverages robust JSON parsing against `<think>` tags). These facts securely append into `baseline.vlans` and the `NetworkInterface` SQL database.

## 4. Decentralized and Immutable Evidence Anchoring
The platform guarantees non-repudiation of all scan results by tying outputs strictly to a verified local blockchain instance.
- Completed compliance scans generate deterministic JSON payloads, which are canonically hashed by `fabric_service.py`.
- The `fabric-gateway` acts as a bridging layer to the Hyperledger Fabric chain. 
- At verification time, `/api/evidence/{id}/verify` cryptographically recomputes the SHA-256 hash array of the stored JSON record, comparing it symmetrically against the immutable `evidenceHash` situated on-chain. If any database manipulation is detected out-of-bounds of the Fabric log, it registers as a fundamental `INTEGRITY_FAILURE`.
- **MinIO Object Store**: Used inherently as the immutable hot-storage for snapshots. Whenever a scan uploads raw text, it is pushed to MinIO (`raw_config.txt`), making the scan structurally resumable and replayable across state disruptions.

## 5. Robust Asynchronous Pipeline Lifecycle
The core processing is wrapped inside a robust, resilient multitasking core orchestrated by `scan_runner.py`.
- **Concurrency Gates**: Background tasks limit starvation by locking throughput on an `asyncio` Semaphore variable (`SCAN_PIPELINE_CONCURRENCY`). 
- **Graceful Lifecycle Management**: The runner natively supports pausing mid-cycle, stopping forcibly across nodes via NATS eventing, and cleaning up "orphaned" scans. Any pipeline dropped due to catastrophic host un-availability will be reconciled automatically to `PAUSED` through Database state-stamps when the service resurfaces.
