// Thin typed wrapper translating HTTP request bodies <-> chaincode
// transaction arguments for the `compliance-evidence` contract.
//
// FABRIC_MOCK=true  — fully bypasses the Fabric peer AND avoids importing
// fabricClient (which transitively pulls in @noble/curves ESM modules that
// crash on Node 18 CommonJS). All anchoring calls return SHA-256-derived
// transaction IDs deterministically so the full pipeline can be exercised
// without a live Fabric network.
import * as crypto from "crypto";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Contract = any;

export interface AnchorEvidenceInput {
  evidenceId: string;
  scanId: string;
  deviceId: string;
  tenantId: string;
  eventType: string;
  evidenceHash: string;
  configHash: string;
  baselineHash: string;
  opaDecision: string;
  batfishDecision: string;
  finalDecision: string;
  policyVersion: string;
  batfishSnapshot: string;
  modelVersion: string;
  timestamp: string;
  actor: string;
  schemaVersion: string;
}

export interface EvidenceAnchorRecord extends AnchorEvidenceInput {
  txId: string;
  blockNumber?: number;
  docType: string;
}

export const FABRIC_MOCK = process.env.FABRIC_MOCK === "true";

// Monotonic block counter for mock mode — realistic enough for UI display.
let _mockBlockCounter = 1000;

// In-memory ledger for mock mode (supports get/verify/history).
const _mockLedger = new Map<string, EvidenceAnchorRecord>();

function mockRecord(input: AnchorEvidenceInput): EvidenceAnchorRecord {
  const txId = crypto
    .createHash("sha256")
    .update(`${input.evidenceId}:${input.evidenceHash}:${input.timestamp}`)
    .digest("hex");
  return {
    ...input,
    txId,
    blockNumber: ++_mockBlockCounter,
    docType: "EvidenceAnchor",
  };
}

function decodeResult<T>(bytes: Uint8Array): T {
  const text = Buffer.from(bytes).toString("utf8");
  return JSON.parse(text) as T;
}

function getContract(): Contract {
  // Lazy import — only executed when FABRIC_MOCK=false to avoid the
  // ESM crash from @noble/curves being require()'d in Node 18 CJS mode.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { getContract: _gc } = require("./fabricClient") as typeof import("./fabricClient");
  return _gc();
}

export async function anchorEvidence(input: AnchorEvidenceInput): Promise<EvidenceAnchorRecord> {
  if (FABRIC_MOCK) {
    const record = mockRecord(input);
    _mockLedger.set(input.evidenceId, record);
    return record;
  }
  const contract = getContract();
  const result = await contract.submitTransaction(
    "CreateEvidence",
    input.evidenceId, input.scanId, input.deviceId, input.tenantId,
    input.eventType, input.evidenceHash, input.configHash, input.baselineHash,
    input.opaDecision, input.batfishDecision, input.finalDecision,
    input.policyVersion, input.batfishSnapshot, input.modelVersion,
    input.timestamp, input.actor, input.schemaVersion
  );
  return decodeResult<EvidenceAnchorRecord>(result);
}

export async function getEvidence(evidenceId: string): Promise<EvidenceAnchorRecord> {
  if (FABRIC_MOCK) {
    const rec = _mockLedger.get(evidenceId);
    if (!rec) throw new Error(`Evidence ${evidenceId} does not exist`);
    return rec;
  }
  const contract = getContract();
  const result = await contract.evaluateTransaction("GetEvidence", evidenceId);
  return decodeResult<EvidenceAnchorRecord>(result);
}

export async function verifyEvidence(evidenceId: string, expectedHash: string): Promise<boolean> {
  if (FABRIC_MOCK) {
    const rec = _mockLedger.get(evidenceId);
    return rec ? rec.evidenceHash === expectedHash : false;
  }
  const contract = getContract();
  const result = await contract.evaluateTransaction("VerifyEvidence", evidenceId, expectedHash);
  return Buffer.from(result).toString("utf8").trim() === "true";
}

export async function getEvidenceHistory(evidenceId: string): Promise<EvidenceAnchorRecord[]> {
  if (FABRIC_MOCK) {
    const rec = _mockLedger.get(evidenceId);
    return rec ? [rec] : [];
  }
  const contract = getContract();
  const result = await contract.evaluateTransaction("GetEvidenceHistory", evidenceId);
  return decodeResult<EvidenceAnchorRecord[]>(result) ?? [];
}

export async function getEvidenceByScan(scanId: string): Promise<EvidenceAnchorRecord[]> {
  if (FABRIC_MOCK) {
    return [..._mockLedger.values()].filter((r) => r.scanId === scanId);
  }
  const contract = getContract();
  const result = await contract.evaluateTransaction("GetEvidenceByScan", scanId);
  return decodeResult<EvidenceAnchorRecord[]>(result) ?? [];
}

export async function getEvidenceByHash(evidenceHash: string): Promise<EvidenceAnchorRecord[]> {
  if (FABRIC_MOCK) {
    return [..._mockLedger.values()].filter((r) => r.evidenceHash === evidenceHash);
  }
  const contract = getContract();
  const result = await contract.evaluateTransaction("GetEvidenceByHash", evidenceHash);
  return decodeResult<EvidenceAnchorRecord[]>(result) ?? [];
}
