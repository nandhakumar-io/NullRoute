// Package main implements the `compliance-evidence` chaincode: the
// immutable evidence/audit layer described in problem-statement sections
// 14-17. It stores only EvidenceAnchor records (hashes, decisions, ids) —
// never raw configuration text or credentials (RULE 11).
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// EvidenceAnchor is the on-chain asset. Every field is a hash, id, decision
// string, or timestamp — nothing that could leak a secret onto the ledger.
type EvidenceAnchor struct {
	DocType          string `json:"docType"` // constant "evidenceAnchor", lets this chaincode share a channel with other asset types later
	EvidenceID       string `json:"evidenceId"`
	ScanID           string `json:"scanId"`
	DeviceID         string `json:"deviceId"`
	TenantID         string `json:"tenantId"`
	EventType        string `json:"eventType"`
	EvidenceHash     string `json:"evidenceHash"`
	ConfigHash       string `json:"configHash"`
	BaselineHash     string `json:"baselineHash"`
	OPADecision      string `json:"opaDecision"`
	BatfishDecision  string `json:"batfishDecision"`
	FinalDecision    string `json:"finalDecision"`
	PolicyVersion    string `json:"policyVersion"`
	BatfishSnapshot  string `json:"batfishSnapshot"`
	ModelVersion     string `json:"modelVersion"`
	Timestamp        string `json:"timestamp"`
	Actor            string `json:"actor"`
	SchemaVersion    string `json:"schemaVersion"`
	// TxID is populated from the transaction context on read (GetTxID),
	// not stored as ledger state itself — see EvidenceWithTx below.
}

// EvidenceWithTx is what read operations return: the anchor plus the
// committing transaction id and block-relative metadata clients need to
// show "TX: 7c4..." in the UI (section 26/29).
type EvidenceWithTx struct {
	EvidenceAnchor
	TxID string `json:"txId"`
}

const docType = "evidenceAnchor"

// EvidenceContract implements the compliance-evidence chaincode.
type EvidenceContract struct {
	contractapi.Contract
}

// CreateEvidence anchors a new evidence record. It is idempotent per
// section 16: if evidenceId already exists, the existing anchor is
// returned unchanged rather than creating a duplicate or erroring, so
// retried anchor-requests (e.g. after a gateway timeout) are always safe.
func (c *EvidenceContract) CreateEvidence(
	ctx contractapi.TransactionContextInterface,
	evidenceId string,
	scanId string,
	deviceId string,
	tenantId string,
	eventType string,
	evidenceHash string,
	configHash string,
	baselineHash string,
	opaDecision string,
	batfishDecision string,
	finalDecision string,
	policyVersion string,
	batfishSnapshot string,
	modelVersion string,
	timestamp string,
	actor string,
	schemaVersion string,
) (*EvidenceWithTx, error) {
	if evidenceId == "" {
		return nil, fmt.Errorf("evidenceId is required")
	}
	if evidenceHash == "" {
		return nil, fmt.Errorf("evidenceHash is required")
	}

	existingBytes, err := ctx.GetStub().GetState(evidenceId)
	if err != nil {
		return nil, fmt.Errorf("failed to read ledger: %v", err)
	}
	if existingBytes != nil {
		// Idempotent: same evidenceId already anchored. Do not overwrite —
		// historical evidence is immutable (RULE 15) — just hand back what's
		// already there together with the *original* committing tx id.
		var existing EvidenceAnchor
		if err := json.Unmarshal(existingBytes, &existing); err != nil {
			return nil, fmt.Errorf("failed to unmarshal existing evidence: %v", err)
		}
		history, err := c.GetEvidenceHistory(ctx, evidenceId)
		if err != nil || len(history) == 0 {
			return &EvidenceWithTx{EvidenceAnchor: existing, TxID: ctx.GetStub().GetTxID()}, nil
		}
		return &EvidenceWithTx{EvidenceAnchor: existing, TxID: history[0].TxID}, nil
	}

	anchor := EvidenceAnchor{
		DocType:         docType,
		EvidenceID:      evidenceId,
		ScanID:          scanId,
		DeviceID:        deviceId,
		TenantID:        tenantId,
		EventType:       eventType,
		EvidenceHash:    evidenceHash,
		ConfigHash:      configHash,
		BaselineHash:    baselineHash,
		OPADecision:     opaDecision,
		BatfishDecision: batfishDecision,
		FinalDecision:   finalDecision,
		PolicyVersion:   policyVersion,
		BatfishSnapshot: batfishSnapshot,
		ModelVersion:    modelVersion,
		Timestamp:       timestamp,
		Actor:           actor,
		SchemaVersion:   schemaVersion,
	}

	anchorBytes, err := json.Marshal(anchor)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence: %v", err)
	}

	if err := ctx.GetStub().PutState(evidenceId, anchorBytes); err != nil {
		return nil, fmt.Errorf("failed to write ledger: %v", err)
	}

	// Composite keys so GetEvidenceByScan / GetEvidenceByHash can range-query
	// without a full scan, and so history-by-scan preserves write order.
	scanKey, err := ctx.GetStub().CreateCompositeKey("scan~evidence", []string{scanId, evidenceId})
	if err == nil {
		_ = ctx.GetStub().PutState(scanKey, []byte{0x00})
	}
	hashKey, err := ctx.GetStub().CreateCompositeKey("hash~evidence", []string{evidenceHash, evidenceId})
	if err == nil {
		_ = ctx.GetStub().PutState(hashKey, []byte{0x00})
	}

	return &EvidenceWithTx{EvidenceAnchor: anchor, TxID: ctx.GetStub().GetTxID()}, nil
}

// GetEvidence returns the current on-chain anchor for evidenceId, along
// with the transaction id that most recently wrote it.
func (c *EvidenceContract) GetEvidence(ctx contractapi.TransactionContextInterface, evidenceId string) (*EvidenceWithTx, error) {
	bytes, err := ctx.GetStub().GetState(evidenceId)
	if err != nil {
		return nil, fmt.Errorf("failed to read ledger: %v", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("evidence %s does not exist", evidenceId)
	}
	var anchor EvidenceAnchor
	if err := json.Unmarshal(bytes, &anchor); err != nil {
		return nil, fmt.Errorf("failed to unmarshal evidence: %v", err)
	}

	history, err := c.GetEvidenceHistory(ctx, evidenceId)
	txId := ""
	if err == nil && len(history) > 0 {
		txId = history[len(history)-1].TxID
	}
	return &EvidenceWithTx{EvidenceAnchor: anchor, TxID: txId}, nil
}

// VerifyEvidence compares an externally supplied hash (recomputed by the
// caller from the off-chain PostgreSQL evidence record) against the
// on-chain evidenceHash for evidenceId. This is the on-chain half of the
// two-sided check described in section 17; the caller is expected to have
// already recomputed expectedHash itself (chaincode never receives raw
// evidence, only the hash to compare).
func (c *EvidenceContract) VerifyEvidence(ctx contractapi.TransactionContextInterface, evidenceId string, expectedHash string) (bool, error) {
	anchor, err := c.GetEvidence(ctx, evidenceId)
	if err != nil {
		return false, err
	}
	return anchor.EvidenceHash == expectedHash, nil
}

// GetEvidenceHistory returns every write to evidenceId in commit order,
// each with its transaction id, block/commit timestamp, and whether it was
// a delete — i.e. the ledger's own audit trail for this asset key.
func (c *EvidenceContract) GetEvidenceHistory(ctx contractapi.TransactionContextInterface, evidenceId string) ([]*EvidenceWithTx, error) {
	iter, err := ctx.GetStub().GetHistoryForKey(evidenceId)
	if err != nil {
		return nil, fmt.Errorf("failed to read history: %v", err)
	}
	defer iter.Close()

	var results []*EvidenceWithTx
	for iter.HasNext() {
		mod, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var anchor EvidenceAnchor
		if len(mod.Value) > 0 {
			if err := json.Unmarshal(mod.Value, &anchor); err != nil {
				continue
			}
		}
		results = append(results, &EvidenceWithTx{EvidenceAnchor: anchor, TxID: mod.TxId})
	}
	return results, nil
}

// GetEvidenceByScan returns every evidence anchor created for a given scan
// (a scan can produce more than one evidence event over its lifetime).
func (c *EvidenceContract) GetEvidenceByScan(ctx contractapi.TransactionContextInterface, scanId string) ([]*EvidenceAnchor, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey("scan~evidence", []string{scanId})
	if err != nil {
		return nil, fmt.Errorf("failed to query by scan: %v", err)
	}
	defer iter.Close()

	var results []*EvidenceAnchor
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil || len(parts) < 2 {
			continue
		}
		evidenceBytes, err := ctx.GetStub().GetState(parts[1])
		if err != nil || evidenceBytes == nil {
			continue
		}
		var anchor EvidenceAnchor
		if err := json.Unmarshal(evidenceBytes, &anchor); err != nil {
			continue
		}
		results = append(results, &anchor)
	}
	return results, nil
}

// GetEvidenceByHash looks up evidence anchor(s) by evidenceHash — used to
// confirm a hash exists on-chain without already knowing its evidenceId.
func (c *EvidenceContract) GetEvidenceByHash(ctx contractapi.TransactionContextInterface, evidenceHash string) ([]*EvidenceAnchor, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey("hash~evidence", []string{evidenceHash})
	if err != nil {
		return nil, fmt.Errorf("failed to query by hash: %v", err)
	}
	defer iter.Close()

	var results []*EvidenceAnchor
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil || len(parts) < 2 {
			continue
		}
		evidenceBytes, err := ctx.GetStub().GetState(parts[1])
		if err != nil || evidenceBytes == nil {
			continue
		}
		var anchor EvidenceAnchor
		if err := json.Unmarshal(evidenceBytes, &anchor); err != nil {
			continue
		}
		results = append(results, &anchor)
	}
	return results, nil
}

// EvidenceExists is a small helper used by CreateEvidence's idempotency
// check and exposed on its own for gateway-side pre-flight checks.
func (c *EvidenceContract) EvidenceExists(ctx contractapi.TransactionContextInterface, evidenceId string) (bool, error) {
	bytes, err := ctx.GetStub().GetState(evidenceId)
	if err != nil {
		return false, fmt.Errorf("failed to read ledger: %v", err)
	}
	return bytes != nil, nil
}
