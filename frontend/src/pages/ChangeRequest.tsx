import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { endpoints, ChangeRequest, DeploymentRecord } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";
import { useAuth } from "../context/AuthContext";
import SideBySideDiff from "../components/SideBySideDiff";

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


const SNAPSHOT_DIFF_TONE: Record<string, string> = {
  BATFISH_PASS: "badge-pass",
  BATFISH_FAIL: "badge-fail",
  BATFISH_UNSUPPORTED: "badge-na",
  BATFISH_UNAVAILABLE: "badge-na",
  BATFISH_ERROR: "badge-fail",
};

// Network Impact panel: CURRENT-vs-PROPOSED Batfish snapshot diff. Shown
// whenever a diff was actually attempted (status !== NOT_CHECKED) so a
// reviewer sees behavioral deltas -- e.g. a newly-reachable path -- before
// approving, not just OPA's single-snapshot verdict.
function SnapshotDiffPanel({ diff }: { diff: NonNullable<ChangeRequest["snapshot_diff"]> }) {
  const nodesChanged = (diff.node_delta?.added?.length || 0) + (diff.node_delta?.removed?.length || 0) > 0;
  const flowsChanged = (diff.differential_reachability?.changed_flow_count || 0) > 0;
  return (
    <div className="mt-2 rounded-lg border border-soc-border bg-soc-bg/40 p-3 text-xs space-y-1.5">
      <div className="flex items-center gap-2">
        <span className="font-semibold text-slate-300">Network Impact (CURRENT vs PROPOSED)</span>
        <span className={`badge ${SNAPSHOT_DIFF_TONE[diff.status] || "badge-na"}`}>{diff.status}</span>
      </div>
      {diff.detail && <div className="text-slate-500">{diff.detail}</div>}
      {diff.node_delta && (
        <div className={nodesChanged ? "text-amber-400" : "text-slate-500"}>
          Nodes — added: {diff.node_delta.added.length ? diff.node_delta.added.join(", ") : "none"}; removed:{" "}
          {diff.node_delta.removed.length ? diff.node_delta.removed.join(", ") : "none"}
        </div>
      )}
      {diff.route_delta && (
        <div className="text-slate-500">
          Routes — current: {diff.route_delta.current_count}, proposed: {diff.route_delta.proposed_count}
          {diff.route_delta.count_delta !== 0 && (
            <span className="text-amber-400"> ({diff.route_delta.count_delta > 0 ? "+" : ""}{diff.route_delta.count_delta})</span>
          )}
        </div>
      )}
      {diff.differential_reachability && (
        <div className={flowsChanged ? "text-red-400 font-medium" : "text-slate-500"}>
          Differential reachability: {diff.differential_reachability.status}
          {flowsChanged &&
            ` — ${diff.differential_reachability.changed_flow_count} flow(s) changed reachability (review before approving)`}
          {diff.differential_reachability.method === "TEXT_DIFF_FALLBACK" && (
            <span className="ml-1 text-slate-500">(text-diff fallback — Batfish was unavailable; not a verified reachability result)</span>
          )}
        </div>
      )}
      {diff.flow_diffs && diff.flow_diffs.length > 0 && (
        <div className="mt-1 space-y-1">
          {diff.flow_diffs.map((f) => (
            <div
              key={f.control_id}
              className={`rounded border px-2 py-1 ${
                f.result === "CRITICAL NETWORK IMPACT"
                  ? "border-red-500/50 bg-red-500/10"
                  : f.result === "NETWORK IMPACT"
                  ? "border-amber-500/50 bg-amber-500/10"
                  : "border-soc-border/60 bg-transparent"
              }`}
            >
              <div className="font-medium text-slate-300">
                {f.source_zone} &rarr; {f.destination_zone}
              </div>
              <div className="flex flex-wrap items-center gap-x-3 text-[11px] text-slate-400">
                <span>BEFORE: <span className={f.before === "REACHABLE" ? "text-red-400" : ""}>{f.before}</span></span>
                <span>AFTER: <span className={f.after === "REACHABLE" ? "text-red-400" : ""}>{f.after}</span></span>
                <span
                  className={
                    f.result === "CRITICAL NETWORK IMPACT" ? "font-semibold text-red-400"
                      : f.result === "NETWORK IMPACT" ? "font-semibold text-amber-400"
                      : "text-slate-500"
                  }
                >
                  RESULT: {f.result}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Before/After config diff, fetched lazily from GET /{id}/configs (MinIO
// blobs behind the recorded hashes) and rendered with the same SideBySideDiff
// component used elsewhere -- this is the "wow" reviewer view: red lines are
// the vulnerable config as it exists today, green lines are what the AI is
// proposing to push. Nothing here executes anything; it's read-only.
function DiffPanel({ crId }: { crId: string }) {
  const [loading, setLoading] = useState(true);
  const [configs, setConfigs] = useState<{ current_config: string | null; proposed_config: string | null } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setErr(null);
    endpoints
      .changeRequestConfigs(crId)
      .then((r) => {
        if (!cancelled) setConfigs(r.data);
      })
      .catch(() => {
        if (!cancelled) setErr("Could not load configuration text for this change request.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [crId]);

  if (loading) return <div className="text-xs text-slate-500 py-2">Loading diff…</div>;
  if (err) return <div className="text-xs text-red-400 py-2">{err}</div>;
  return (
    <div className="space-y-1.5">
      <div className="text-[11px] text-slate-500">
        Left is the device's current, vulnerable configuration. Right is the AI-proposed remediation CLI —
        it is syntax only until a human clicks Approve below.
      </div>
      <SideBySideDiff currentConfig={configs?.current_config} proposedConfig={configs?.proposed_config} />
    </div>
  );
}

function DeploymentCard({
  d,
  crId,
  canRollback,
  onChanged,
}: {
  d: DeploymentRecord;
  crId: string;
  canRollback: boolean;
  onChanged: () => void;
}) {
  const code = explicitCodeIn(d.error);
  const [rollingBack, setRollingBack] = useState(false);
  const [rollbackMsg, setRollbackMsg] = useState<string | null>(null);
  const simulated = (d.error || "").startsWith("[SIMULATED DRIFT]");
  const needsRollback = d.status === "DRIFTED" && !d.rolled_back;

  async function doRollback() {
    setRollingBack(true);
    setRollbackMsg(null);
    try {
      const r = await endpoints.rollbackDeployment(
        crId,
        d.id,
        simulated ? "Reverting a simulated drift (developer sandbox)." : undefined,
      );
      setRollbackMsg(`Rollback ${(r.data as any)?.status || "submitted"}.`);
      onChanged();
    } catch (e: any) {
      setRollbackMsg(
        e?.response?.status === 403
          ? "Your role can't roll back deployments — admin or operator is required."
          : e?.response?.data?.detail || "Rollback failed — see server logs.",
      );
    } finally {
      setRollingBack(false);
    }
  }

  return (
    <div className="rounded-lg border border-soc-border bg-soc-bg/40 p-3 text-xs space-y-1.5">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`badge ${STATUS_TONE[d.status] || "badge-na"}`}>{d.status}</span>
        {simulated && (
          <span
            className="badge border border-amber-600/50 bg-amber-950/40 text-amber-300"
            title="Injected by the developer drift simulator — no real drift occurred."
          >
            SIMULATED
          </span>
        )}
        {d.rolled_back && <span className="badge badge-pass">ROLLED BACK</span>}
        <span className="font-mono text-slate-400">transport: {d.transport || "—"}</span>
        {code && <span className={`badge ${EXPLICIT_CODE_TONE[code]}`}>{code}</span>}
        {d.started_at && (
          <span className="text-slate-500">{new Date(d.started_at).toLocaleString()}</span>
        )}
      </div>
      {d.error && <div className="text-red-400">{d.error}</div>}

      {needsRollback && (
        <div className="rounded-md border border-red-900/50 bg-red-950/20 p-2.5 space-y-2">
          <div className="text-red-300 font-medium">Rollback required</div>
          <div className="text-slate-400 leading-relaxed">
            Post-deployment verification failed, so a rollback-required alert was raised. This
            platform does not revert automatically — an operator has to initiate it.
          </div>
          {canRollback ? (
            <button
              onClick={doRollback}
              disabled={rollingBack}
              className="px-3 py-1.5 rounded-md bg-red-600/90 hover:bg-red-500 text-white
                         text-xs font-medium transition-colors disabled:opacity-40"
            >
              {rollingBack ? "Reverting…" : "Roll back to pre-change config"}
            </button>
          ) : (
            <div className="text-slate-500 italic">
              Requires the admin or operator role.
            </div>
          )}
          {rollbackMsg && <div className="text-slate-300">{rollbackMsg}</div>}
        </div>
      )}
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

/**
 * Developer sandbox: force an active deployment into DRIFTED without touching
 * a device, so the drift → alert → operator-rollback loop can be demonstrated
 * in a browser.
 *
 * Deliberately NOT labelled as an auto-rollback demo. Nothing in this platform
 * reverts on its own (RULE 4/5) — this drives the *operator-initiated* path,
 * and the copy says so, because an evaluator who walks away believing the
 * revert was automatic has been misled by the demo.
 *
 * Hides itself entirely when the backend returns 404 (ENABLE_DEV_SIMULATION
 * unset), which is the expected production state.
 */
function SimulateDriftTrigger({
  crId,
  deployments,
  onSimulated,
}: {
  crId: string;
  deployments: DeploymentRecord[];
  onSimulated: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  const driftable = deployments.find(
    (d) => (d.status === "DEPLOYED" || d.status === "VERIFIED") && !d.rolled_back,
  );

  if (unavailable || !driftable) return null;

  async function fire() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await endpoints.simulateDeploymentDrift(crId, driftable!.id);
      setMsg(
        r.data.alert_dispatched
          ? "Drift injected and a rollback-required alert was raised. Use the rollback button above to revert."
          : "Drift injected, but the alert could not be dispatched — check the server logs.",
      );
      onSimulated();
    } catch (e: any) {
      if (e?.response?.status === 404) {
        // Route is compiled out in this environment. Disappear quietly.
        setUnavailable(true);
        return;
      }
      setMsg(
        e?.response?.status === 403
          ? "Your role can't simulate drift — admin or operator is required."
          : e?.response?.data?.detail || "Could not simulate drift.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-dashed border-amber-800/50 bg-amber-950/10 p-3 text-xs space-y-2">
      <div className="flex items-center gap-2">
        <span className="badge border border-amber-600/50 bg-amber-950/40 text-amber-300">DEV</span>
        <span className="text-slate-300 font-medium">Simulate Deployment Drift</span>
      </div>
      <div className="text-slate-400 leading-relaxed">
        Forces the active deployment into <span className="font-mono">DRIFTED</span> and fires the
        real rollback-required alert — no device is contacted. Exercises the{" "}
        <span className="text-slate-300">operator-initiated</span> rollback path; the platform does
        not revert automatically.
      </div>
      <button
        onClick={fire}
        disabled={busy}
        className="px-3 py-1.5 rounded-md border border-amber-700/60 bg-amber-950/30
                   text-amber-300 hover:bg-amber-900/40 transition-colors disabled:opacity-40"
      >
        {busy ? "Injecting drift…" : "Simulate drift on latest deployment"}
      </button>
      {msg && <div className="text-slate-300">{msg}</div>}
    </div>
  );
}

function LockIcon() {
  return (
    <svg viewBox="0 0 16 16" className="w-3 h-3 shrink-0" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="3" y="7" width="10" height="7" rx="1.5" />
      <path d="M5.5 7V4.75a2.5 2.5 0 0 1 5 0V7" />
    </svg>
  );
}

export default function ChangeRequests() {
  const { hasRole } = useAuth();
  const canApprove = hasRole("security_analyst"); // true for security_analyst OR admin
  // Deploy/rollback/simulate-drift are all gated require_role("admin","operator")
  // on the backend; mirror that here so the UI disables rather than 403s.
  const canDeploy = hasRole("operator"); // true for operator OR admin
  const [items, setItems] = useState<ChangeRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [transportById, setTransportById] = useState<Record<string, string>>({});
  const [deploymentsById, setDeploymentsById] = useState<Record<string, DeploymentRecord[]>>({});
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [diffOpenId, setDiffOpenId] = useState<string | null>(null);
  const [searchParams] = useSearchParams();
  const linkedDeviceId = searchParams.get("device");
  const linkedCrId = searchParams.get("cr");
  const [didAutoOpen, setDidAutoOpen] = useState(false);

  function load() {
    setLoading(true);
    endpoints
      .changeRequests(statusFilter ? { status: statusFilter } : undefined)
      .then((r) => setItems(r.data.change_requests))
      .finally(() => setLoading(false));
  }

  useEffect(load, [statusFilter]);

  // Deep-link handoff from the scan pipeline's "Generate Remediation &
  // Review Diff" button: jump straight to the change request it just
  // created (or the one already pending for that device) with its diff
  // already open, so "review the diff" is truly one click, not a search.
  useEffect(() => {
    if (didAutoOpen || loading || (!linkedCrId && !linkedDeviceId)) return;
    const target = items.find((c) => (linkedCrId ? c.id === linkedCrId : c.device_id === linkedDeviceId));
    if (target) {
      setDiffOpenId(target.id);
      setDidAutoOpen(true);
      requestAnimationFrame(() => {
        document.getElementById(`cr-${target.id}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
      });
    }
  }, [items, loading, linkedCrId, linkedDeviceId, didAutoOpen]);

  async function approve(id: string) {
    if (!canApprove) return; // client-side guard; server enforces via require_permission regardless
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
    if (!canApprove) return;
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
        subtitle="Proposed configuration changes, validated through the same OPA/Batfish/risk pipeline as scans. AI synthesizes the syntax; it physically cannot execute until a designated Network Admin or Security Analyst clicks Approve."
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
            <div
              key={cr.id}
              id={`cr-${cr.id}`}
              className={`card ${(linkedCrId === cr.id || (!linkedCrId && linkedDeviceId === cr.device_id)) ? "ring-2 ring-cyan-500 border-cyan-700" : ""}`}
            >
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
                  {cr.snapshot_diff && cr.snapshot_diff.status !== "NOT_CHECKED" && (
                    <SnapshotDiffPanel diff={cr.snapshot_diff} />
                  )}

                  {/* Before/After CLI diff -- the side-by-side reviewer view.
                      Available regardless of status so a reviewer can see
                      exactly what's being proposed before/while deciding. */}
                  <div className="mt-3">
                    <button
                      className="text-xs text-slate-400 hover:text-slate-200 underline decoration-dotted"
                      onClick={() => setDiffOpenId(diffOpenId === cr.id ? null : cr.id)}
                    >
                      {diffOpenId === cr.id ? "Hide config diff" : "View config diff (current vs. proposed)"}
                    </button>
                    {diffOpenId === cr.id && (
                      <div className="mt-2">
                        <DiffPanel crId={cr.id} />
                      </div>
                    )}
                  </div>

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
                            <DeploymentCard
                              key={d.id}
                              d={d}
                              crId={cr.id}
                              canRollback={canDeploy}
                              onChanged={() => loadDeployments(cr.id)}
                            />
                          ))}
                          <SimulateDriftTrigger
                            crId={cr.id}
                            deployments={deploymentsById[cr.id] || []}
                            onSimulated={() => loadDeployments(cr.id)}
                          />
                        </div>
                      )}
                    </div>
                  )}
                </div>
                <div className="flex flex-col gap-2 shrink-0 items-end">
                  {cr.status === "PENDING_APPROVAL" && (
                    <div className="flex flex-col gap-1.5 items-end">
                      <div className="flex gap-2">
                        <button
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-900/40 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/60 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-emerald-900/40"
                          disabled={busyId === cr.id || !canApprove}
                          title={canApprove ? undefined : "Requires Security Analyst or Admin role"}
                          onClick={() => approve(cr.id)}
                        >
                          {!canApprove && <LockIcon />}
                          Approve
                        </button>
                        <button
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-900/40 text-red-300 border border-red-800/60 hover:bg-red-900/60 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-red-900/40"
                          disabled={busyId === cr.id || !canApprove}
                          title={canApprove ? undefined : "Requires Security Analyst or Admin role"}
                          onClick={() => reject(cr.id)}
                        >
                          {!canApprove && <LockIcon />}
                          Reject
                        </button>
                      </div>
                      <div className="text-[10px] text-slate-500 max-w-[220px] text-right leading-snug">
                        {canApprove
                          ? "AI synthesized this syntax — it cannot execute until you click Approve."
                          : "Locked: only a Security Analyst or Admin can approve or reject this change."}
                      </div>
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