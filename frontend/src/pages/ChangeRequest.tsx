import { useEffect, useState } from "react";
import { endpoints, ChangeRequest, DeploymentRecord } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

const STATUS_TONE: Record<string, string> = {
  APPROVED: "badge-pass",
  DEPLOYED: "badge-pass",
  VERIFIED: "badge-pass",
  REJECTED: "badge-fail",
  FAILED: "badge-fail",
  DRIFTED: "badge-fail",
  ABORTED_STALE_HASH: "badge-fail",
  PENDING_APPROVAL: "badge-medium",
  PENDING_VALIDATION: "badge-medium",
  DEPLOYING: "badge-medium",
  PENDING: "badge-medium",
  DRAFT: "badge-na",
};

// Explicit deployment-transport failure/unsupported codes (spec section
// 50) -- these get their own badge tone so they're never confused with a
// generic pass, even though the DeploymentRecord's own top-level `status`
// is just FAILED; the specific code lives inside `error`.
const EXPLICIT_CODE_TONE: Record<string, string> = {
  GNMI_DISABLED: "badge-na",
  GNMI_UNSUPPORTED: "badge-fail",
  GNMI_UNAVAILABLE: "badge-fail",
  GNMI_SCHEMA_MISMATCH: "badge-fail",
  GNMI_FAILED: "badge-fail",
  PYATS_DISABLED: "badge-na",
  PYATS_UNSUPPORTED: "badge-na",
  PYATS_UNAVAILABLE: "badge-fail",
  PYATS_FAILED: "badge-fail",
  PYATS_OK: "badge-pass",
};

function explicitCodeIn(text: string | null): string | null {
  if (!text) return null;
  const match = Object.keys(EXPLICIT_CODE_TONE).find((code) => text.includes(code));
  return match || null;
}

const TRANSPORTS = [
  { value: "ssh", label: "SSH" },
  { value: "netconf", label: "NETCONF" },
  { value: "gnmi", label: "OpenConfig / gNMI (optional)" },
];


function DeploymentCard({ d }: { d: DeploymentRecord }) {
  const code = explicitCodeIn(d.error);
  return (
    <div className="rounded-lg border border-soc-border bg-soc-bg/40 p-3 text-xs space-y-1.5">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`badge ${STATUS_TONE[d.status] || "badge-na"}`}>{d.status}</span>
        <span className="font-mono text-slate-400">transport: {d.transport || "—"}</span>
        {code && <span className={`badge ${EXPLICIT_CODE_TONE[code]}`}>{code}</span>}
        {d.started_at && (
          <span className="text-slate-500">{new Date(d.started_at).toLocaleString()}</span>
        )}
      </div>
      {d.error && <div className="text-red-400">{d.error}</div>}
      {d.transport === "gnmi" && (d.model_name || d.request_hash) && (
        <div className="text-slate-400 space-y-0.5">
          <div>model: <span className="font-mono">{d.model_name || "—"}</span> · operation: <span className="font-mono">{d.operation || "—"}</span></div>
          {d.paths && d.paths.length > 0 && (
            <div>paths: <span className="font-mono">{d.paths.join(", ")}</span></div>
          )}
          <div>request hash: <span className="font-mono">{d.request_hash || "—"}</span></div>
        </div>
      )}
      <div className="text-slate-400">
        pre-hash observed: <span className="font-mono">{(d.observed_pre_hash || "—").slice(0, 12)}</span>
        {" · "}
        post-hash: <span className="font-mono">{(d.post_config_hash || "—").slice(0, 12)}</span>
        {" · "}
        post-verification: {d.post_verification_passed === null ? "—" : d.post_verification_passed ? "passed" : "FAILED"}
      </div>
      {d.verification_engine && (
        <div className="text-slate-400">
          supplemental verification ({d.verification_engine}): {" "}
          <span className={d.verification_result === "PYATS_OK" ? "text-emerald-400" : "text-amber-400"}>
            {d.verification_result || "—"}
          </span>
          {" "}
          <span className="text-slate-600">(never authoritative — OPA/Batfish/risk decide compliance)</span>
        </div>
      )}
    </div>
  );
}

export default function ChangeRequests() {
  const [items, setItems] = useState<ChangeRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [transportById, setTransportById] = useState<Record<string, string>>({});
  const [deploymentsById, setDeploymentsById] = useState<Record<string, DeploymentRecord[]>>({});
  const [expandedId, setExpandedId] = useState<string | null>(null);

  function load() {
    setLoading(true);
    endpoints
      .changeRequests(statusFilter ? { status: statusFilter } : undefined)
      .then((r) => setItems(r.data.change_requests))
      .finally(() => setLoading(false));
  }

  useEffect(load, [statusFilter]);

  async function approve(id: string) {
    setBusyId(id);
    setError(null);
    try {
      await endpoints.approveChangeRequest(id);
      load();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Could not approve this change request.");
    } finally {
      setBusyId(null);
    }
  }

  async function reject(id: string) {
    const reason = window.prompt("Reason for rejecting this change request?");
    if (reason === null) return;
    setBusyId(id);
    setError(null);
    try {
      await endpoints.rejectChangeRequest(id, reason);
      load();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Could not reject this change request.");
    } finally {
      setBusyId(null);
    }
  }

  async function loadDeployments(id: string) {
    const r = await endpoints.changeRequestDeployments(id);
    setDeploymentsById((prev) => ({ ...prev, [id]: r.data.deployments }));
  }

  async function toggleHistory(id: string) {
    if (expandedId === id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(id);
    await loadDeployments(id);
  }

  async function deploy(id: string) {
    setBusyId(id);
    setError(null);
    try {
      const transport = transportById[id] || "ssh";
      await endpoints.deployChangeRequest(id, { transport });
      await Promise.all([load(), loadDeployments(id)]);
      setExpandedId(id);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Deployment failed to start.");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <PageHeader
        title="Change Requests"
        subtitle="Proposed configuration changes, validated through the same OPA/Batfish/risk pipeline as scans — a human always approves or rejects, AI never deploys"
        action={
          <select
            className="input-sm bg-soc-panel border border-soc-border rounded px-2 py-1 text-sm text-slate-300"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All statuses</option>
            <option value="PENDING_APPROVAL">Pending approval</option>
            <option value="APPROVED">Approved</option>
            <option value="REJECTED">Rejected</option>
            <option value="DEPLOYED">Deployed</option>
            <option value="FAILED">Failed</option>
          </select>
        }
      />
      <div className="px-8 pb-8 space-y-3">
        {error && (
          <div className="card border-red-900/60 bg-red-950/20 text-sm text-red-400">{error}</div>
        )}
        {loading && <Loading />}
        {!loading && items.length === 0 && (
          <EmptyState message="No change requests yet. Change requests are created via POST /api/change-requests (e.g. from an AI remediation suggestion or a manual proposal)." />
        )}
        {!loading &&
          items.map((cr) => (
            <div key={cr.id} className="card">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-slate-400">device {cr.device_id}</span>
                    <span className={`badge ${STATUS_TONE[cr.status] || "badge-na"}`}>{cr.status}</span>
                    {cr.source === "ai_suggestion" && <span className="badge badge-medium">AI-suggested</span>}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Created {new Date(cr.created_at).toLocaleString()}
                    {cr.created_by && ` by ${cr.created_by}`}
                  </div>
                  <div className="text-xs text-slate-400 mt-2 flex items-center gap-3 flex-wrap">
                    <span>OPA: {cr.opa_decision || "—"}</span>
                    <span>Batfish: {cr.batfish_status || "—"}</span>
                    <span>
                      Risk: {cr.risk_level || "—"} {cr.risk_score != null && `(${cr.risk_score})`}
                    </span>
                    <span className="font-semibold text-slate-300">Final: {cr.final_decision || "—"}</span>
                  </div>
                  {cr.final_reason && <div className="text-xs text-slate-500 mt-1">{cr.final_reason}</div>}
                  {cr.status === "REJECTED" && cr.rejection_reason && (
                    <div className="text-xs text-red-400 mt-1">Rejected: {cr.rejection_reason}</div>
                  )}
                  {cr.status === "APPROVED" && cr.approved_by && (
                    <div className="text-xs text-emerald-400 mt-1">
                      Approved by {cr.approved_by} at {cr.approved_at && new Date(cr.approved_at).toLocaleString()}
                    </div>
                  )}

                  {(cr.status === "APPROVED" || cr.status === "DEPLOYED" || cr.status === "FAILED") && (
                    <div className="mt-3">
                      <button
                        className="text-xs text-slate-400 hover:text-slate-200 underline decoration-dotted"
                        onClick={() => toggleHistory(cr.id)}
                      >
                        {expandedId === cr.id ? "Hide deployment history" : "Show deployment history"}
                      </button>
                      {expandedId === cr.id && (
                        <div className="mt-2 space-y-2">
                          {(deploymentsById[cr.id] || []).length === 0 && (
                            <div className="text-xs text-slate-500">No deployment attempts yet.</div>
                          )}
                          {(deploymentsById[cr.id] || []).map((d) => (
                            <DeploymentCard key={d.id} d={d} />
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
                <div className="flex flex-col gap-2 shrink-0 items-end">
                  {cr.status === "PENDING_APPROVAL" && (
                    <div className="flex gap-2">
                      <button
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-900/40 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/60 disabled:opacity-50"
                        disabled={busyId === cr.id}
                        onClick={() => approve(cr.id)}
                      >
                        Approve
                      </button>
                      <button
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-900/40 text-red-300 border border-red-800/60 hover:bg-red-900/60 disabled:opacity-50"
                        disabled={busyId === cr.id}
                        onClick={() => reject(cr.id)}
                      >
                        Reject
                      </button>
                    </div>
                  )}
                  {cr.status === "APPROVED" && (
                    <div className="flex gap-2 items-center">
                      <select
                        className="bg-soc-panel border border-soc-border rounded px-2 py-1 text-xs text-slate-300"
                        value={transportById[cr.id] || "ssh"}
                        onChange={(e) => setTransportById((prev) => ({ ...prev, [cr.id]: e.target.value }))}
                      >
                        {TRANSPORTS.map((t) => (
                          <option key={t.value} value={t.value}>{t.label}</option>
                        ))}
                      </select>
                      <button
                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-sky-900/40 text-sky-300 border border-sky-800/60 hover:bg-sky-900/60 disabled:opacity-50"
                        disabled={busyId === cr.id}
                        onClick={() => deploy(cr.id)}
                      >
                        Deploy
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}