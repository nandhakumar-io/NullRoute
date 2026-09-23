# 🏗️ NullRoute Architecture & Overview

## 1. Executive Summary & Problem Statement

**The Problem**: Modern network infrastructure is incredibly complex, distributed, and strictly regulated (e.g., CIS, HIPAA, PCI-DSS). Ensuring that routers, switches, and firewalls comply with security baselines is traditionally a manual, error-prone, and slow process. When organizations update their networks, they risk introducing non-compliant configurations (like weak encryption or exposed management ports). 

**The Solution**: NullRoute is an intelligent, automated compliance platform. It continuously audits network device configurations against security policies, providing deterministic pass/fail reports. By combining the precision of deterministic parsing with the flexibility of modern AI, NullRoute can map even obscure, proprietary configurations into a standardized, analyzable model.

---

## 2. Platform Architecture & Local First Design

NullRoute is built around a robust, event-driven microservices architecture. Crucially, the entire platform is designed to be **100% self-hosted and air-gapped**. From the AI models to the blockchain and databases, every component runs locally out of the box via Docker Compose, guaranteeing that sensitive network configurations never leave your internal network.

It securely ingests configurations, extracts data, evaluates compliance, and stores immutable evidence of its findings.

```text
React (Vite/TS/Tailwind/Monaco)
       │
       ▼
FastAPI (Pydantic, SQLAlchemy) 
       │
       ▼
  NATS JetStream (Async Event Bus)
       │
 ┌─────┼─────────────────────────┬──────────────────────────┬──────────────────┐
 ▼     ▼                         ▼                          ▼                  ▼
CLI   Deterministic Parsers   Semantic Router (MiniLM)    Unified AI Server  OPA / Rego Engine
      (Regex/AST driven)      (pgvector/DistilBERT)       (Fallback/Qwen3)
 └───────────────────────────────┴──────────────────────────┴──────────────────┘
                                 ▼
                    Security Baseline Model (Pydantic)
                                 │
             ┌───────────────────┴───────────────────┐
             ▼                                       ▼
   PostgreSQL/pgvector                     MinIO (S3 Object Store)
             │                                       │
             ▼                                       ▼
        Scan Findings                          Immutable Evidence / Reports
             │                                       │
             ▼                                       ▼
  Remediation Generation                 Hyperledger Fabric Chaincode
```

---

## 3. Core Components (How It Works)

### 3.1. Hybrid Data Extraction (Determinism + AI)
Network configs come in many obscure vendor formats. NullRoute extracts this data using a dual-pipeline:
- **Deterministic Parsers**: Known configuration syntax (e.g., standard Cisco VLANs) is extracted instantly with 100% accuracy via `structure_parser.py`.
- **Intelligent Extractor**: When configurations are unrecognizable to regex (or are newer vendor syntaxes), the **Semantic Router** uses an incredibly fast embedding model (DistilBERT/MiniLM) to match the text to previously human-verified mappings. If it's completely new, it falls back to the **Unified AI Server (Qwen3)** to intelligently infer the meaning.
- *Note:* The AI acts solely as a translator. **AI never makes compliance decisions.**

### 3.2. Authoritative Policy Engine
Once the configuration is translated into a clean, standardized format (The Pydantic Security Baseline Model), it is sent to the **OPA / Rego Engine**. This engine contains the hardcoded compliance rules and executes deterministic pass/fail judgments against the data.

### 3.3. Advanced Network Simulation
NullRoute doesn't just read text; it simulates behavior. Through **Batfish Integration**, NullRoute actively simulates network topologies to verify if a threat exists—such as dynamically proving that a Guest VLAN is accidentally allowed to reach the Management VLAN due to an OSPF routing flaw. 

### 3.4. Immutable Auditing & Evidence
To prevent tampering and ensure non-repudiation for auditors:
- **Hyperledger Fabric**: The cryptographic hash of every compliance scan report is anchored into a local blockchain (`fabric-gateway`). Any tampering with backend data immediately raises an Integrity Failure.
- **MinIO Object Storage**: Raw network snapshots and parsed artifacts are safely preserved, making auditing 100% transparent and replayable.

### 3.5. Resilient Job Processing
The entire platform is stitched together using **NATS JetStream**. This allows the platform to run thousands of scans simultaneously without dropping data. If the server crashes mid-audit, the job runner (`scan_runner.py`) safely resumes or cleans up the orphaned tasks upon reboot.

---

## 4. Key Use Cases

1. **Automated Network Compliance**
   Network engineers and security teams can run daily audits of all routers and switches, instantly catching any drift from CIS Benchmarks or internal security standards.
2. **Pre-Deployment Checks (Drift Analysis)**
   Before pushing a massive configuration change to production, NullRoute simulates the new configuration to ensure it won't break compliance (e.g., unintentionally leaving a firewall open).
3. **Auditor Transparency & Proof**
   When external auditors require proof of past compliance, the immutable blockchain storage provided by Hyperledger Fabric allows organizations to prove that a configuration was fully compliant on a specific date in the past, and that the report has never been altered.

---

## 5. Technology Stack Summary

- **Frontend**: React (Vite / TypeScript / Tailwind CSS) with Monaco Editor for configuration diffing.
- **Backend Core**: FastAPI (Python), utilizing Pydantic for rigid data validation and SQLAlchemy for ORM.
- **Message Broker**: NATS JetStream for high-throughput, horizontally scalable event processing.
- **AI/ML Layer**: Qwen3 (LLM Fallback), DistilBERT/MiniLM (Semantic Embedding), and pgvector (Vector DB) for the Hybrid Extraction pipeline.
- **Policy Engine**: Open Policy Agent (OPA) / Rego for deterministic rule engines.
- **Storage & Evidence**: PostgreSQL (app state), MinIO (object storage), and Hyperledger Fabric (blockchain audit trail).
- **Graceful Lifecycle Management**: The runner natively supports pausing mid-cycle, stopping forcibly across nodes via NATS eventing, and cleaning up "orphaned" scans. Any pipeline dropped due to catastrophic host un-availability will be reconciled automatically to `PAUSED` through Database state-stamps when the service resurfaces.
