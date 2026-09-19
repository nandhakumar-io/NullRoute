import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { endpoints, EvidenceRecord, VerifyResult } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

function FabricPill({ status }: { status: string | null }) {
  const s = status || "NOT_ANCHORED";
  const cls =
    s === "ANCHORED" ? "badge-pass" : s === "FABRIC_UNAVAILABLE" ? "badge-fail" : "badge-na";
  return <span className={`badge ${cls}`}>{s.replace(/_/g, " ")}</span>;
}

function DecisionPill({ decision }: { decision: string | null }) {
  const cls =
    decision === "PASS" ? "badge-pass" : decision === "BLOCK" ? "badge-fail" : "badge-medium";
  return <span className={`badge ${cls}`}>{decision || "UNKNOWN"}</span>;
}

export default function EvidenceLedger() {
  const [records, setRecords] = useState<EvidenceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    endpoints
      .evidenceList()
      .then((r) => setRecords(r.data))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  async function handleVerify(evidenceId: string) {
    setSelected(evidenceId);
    setVerifyResult(null);
    setError(null);
    setBusy(true);
    try {
      const r = await endpoints.evidenceVerify(evidenceId);
      setVerifyResult(r.data);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Verification failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleTamper(evidenceId: string) {
    setBusy(true);
    setError(null);
    try {
      await endpoints.evidenceSimulateTamper(evidenceId);
      await handleVerify(evidenceId);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Tamper simulation failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleRestore(evidenceId: string) {
    setBusy(true);
    setError(null);
    try {
      await endpoints.evidenceRestore(evidenceId);
      await handleVerify(evidenceId);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Restore failed");
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Loading />;

  return (
    <div>
      <PageHeader
        title="Evidence Ledger"
        subtitle="Immutable evidence packages — SHA-256 hashed, anchored to Hyperledger Fabric when enabled"
      />
      <div className="px-8 pb-8 space-y-4">
        {records.length === 0 && <EmptyState message="No evidence has been generated yet — run a scan first." />}

        {records.map((rec) => (
          <div key={rec.evidence_id} className="card">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs text-slate-400">{rec.evidence_id}</span>
                  <DecisionPill decision={rec.final_decision} />
                  <FabricPill status={rec.fabric_status} />
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  <Link className="text-cyan-400 hover:underline" to={`/scans/${rec.scan_id}`}>
                    scan {rec.scan_id}
                  </Link>
                  {" · "}
                  {rec.event_type || "scan_completed"}
                  {" · "}
                  {rec.created_at ? new Date(rec.created_at).toLocaleString() : ""}
                </div>
                <div className="text-xs font-mono text-slate-500 mt-1 truncate">
                  hash: {rec.evidence_hash}
                  {rec.fabric_tx_id ? ` · tx: ${rec.fabric_tx_id}` : ""}
                  {rec.fabric_block_number != null ? ` · block: ${rec.fabric_block_number}` : ""}
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <button className="btn-secondary" disabled={busy} onClick={() => handleVerify(rec.evidence_id)}>
                  Verify Integrity
                </button>
                <button className="btn-secondary" disabled={busy} onClick={() => handleTamper(rec.evidence_id)}>
                  Simulate Evidence Tampering
                </button>
                <button className="btn-secondary" disabled={busy} onClick={() => handleRestore(rec.evidence_id)}>
                  Restore
                </button>
              </div>
            </div>

            {selected === rec.evidence_id && (
              <div className="mt-3 border-t border-soc-border pt-3">
                {error && <div className="text-sm text-red-400">{error}</div>}
                {verifyResult && (
                  <div>
                    <span className={`badge ${verifyResult.match ? "badge-pass" : "badge-fail"}`}>
                      {verifyResult.status.replace(/_/g, " ")}
                    </span>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2 text-xs font-mono">
                      <div>
                        <div className="text-slate-500 mb-1">Stored Hash</div>
                        <div className="text-slate-300 break-all">{verifyResult.stored_hash}</div>
                      </div>
                      <div>
                        <div className="text-slate-500 mb-1">Calculated Hash</div>
                        <div className="text-slate-300 break-all">{verifyResult.calculated_hash}</div>
                      </div>
                    </div>
                    {verifyResult.fabric_checked && (
                      <div className="mt-2 text-xs">
                        <span className="text-slate-500">On-chain (Fabric): </span>
                        <span className={verifyResult.fabric_match ? "text-emerald-400" : "text-red-400"}>
                          {verifyResult.fabric_match ? "MATCHES LEDGER" : "MISMATCH WITH LEDGER"}
                        </span>
                      </div>
                    )}
                    {verifyResult.fabric_status === "FABRIC_UNAVAILABLE" && (
                      <div className="mt-2 text-xs text-amber-400">
                        On-chain check skipped — Fabric gateway unavailable, off-chain result shown above.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
