// Thin typed wrapper translating HTTP request bodies <-> chaincode
// transaction arguments for the `compliance-evidence` contract
// (fabric/chaincode/compliance-evidence). Every field mirrors
// EvidenceAnchor exactly — see that Go source for the authoritative shape.
import { getContract } from "./fabricClient";

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
  docType: string;
}

function decodeResult<T>(bytes: Uint8Array): T {
  const text = Buffer.from(bytes).toString("utf8");
  return JSON.parse(text) as T;
}

export async function anchorEvidence(input: AnchorEvidenceInput): Promise<EvidenceAnchorRecord> {
  const contract = getContract();
  const result = await contract.submitTransaction(
    "CreateEvidence",
    input.evidenceId,
    input.scanId,
    input.deviceId,
    input.tenantId,
    input.eventType,
    input.evidenceHash,
    input.configHash,
    input.baselineHash,
    input.opaDecision,
    input.batfishDecision,
    input.finalDecision,
    input.policyVersion,
    input.batfishSnapshot,
    input.modelVersion,
    input.timestamp,
    input.actor,
    input.schemaVersion
  );
  return decodeResult<EvidenceAnchorRecord>(result);
}

export async function getEvidence(evidenceId: string): Promise<EvidenceAnchorRecord> {
  const contract = getContract();
  const result = await contract.evaluateTransaction("GetEvidence", evidenceId);
  return decodeResult<EvidenceAnchorRecord>(result);
}

export async function verifyEvidence(evidenceId: string, expectedHash: string): Promise<boolean> {
  const contract = getContract();
  const result = await contract.evaluateTransaction("VerifyEvidence", evidenceId, expectedHash);
  return Buffer.from(result).toString("utf8").trim() === "true";
}

export async function getEvidenceHistory(evidenceId: string): Promise<EvidenceAnchorRecord[]> {
  const contract = getContract();
  const result = await contract.evaluateTransaction("GetEvidenceHistory", evidenceId);
  return decodeResult<EvidenceAnchorRecord[]>(result) ?? [];
}

export async function getEvidenceByScan(scanId: string): Promise<EvidenceAnchorRecord[]> {
  const contract = getContract();
  const result = await contract.evaluateTransaction("GetEvidenceByScan", scanId);
  return decodeResult<EvidenceAnchorRecord[]>(result) ?? [];
}

export async function getEvidenceByHash(evidenceHash: string): Promise<EvidenceAnchorRecord[]> {
  const contract = getContract();
  const result = await contract.evaluateTransaction("GetEvidenceByHash", evidenceHash);
  return decodeResult<EvidenceAnchorRecord[]>(result) ?? [];
}
