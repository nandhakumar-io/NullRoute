import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { endpoints, ChangeRequest, DeploymentRecord, PushPlan, EditPreview } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";
import { useAuth } from "../context/AuthContext";
import SideBySideDiff from "../components/SideBySideDiff";
import BatfishDeltaView from "../components/BatfishDeltaView";
import { Chip, DeploymentPipelineCard, errText, verdictTone } from "../components/DeploymentPipeline";
import { ApprovalPanel, DecisionSummary, DeployDialog, ReviewTrail } from "../components/ChangeReview";

const TRANSPORTS = [
  { value: "ssh", label: "SSH" },
  { value: "netconf", label: "NETCONF" },
  { value: "gnmi", label: "OpenConfig / gNMI (optional)" },
];

const STATUS_LABEL: Record<string, string> = {
  PENDING_APPROVAL: "Pending approval", PENDING_VALIDATION: "Pending validation", ABORTED_STALE_HASH: "Aborted (stale hash)",
};
const statusText = (s: string) => STATUS_LABEL[s] || s.replace(/_/g, " ").toLowerCase().replace(/^./, (c) => c.toUpperCase());

const fmt = (v?: string | null) => (v ? new Date(v.endsWith("Z") ? v : v + "Z").toLocaleString() : "—");

/** One consistent block: small caps heading, content, hairline divider. */
function Section({ title, aside, children }: { title: string; aside?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="pt-4 mt-4 space-y-2" style={{ borderTop: "1px solid var(--border)" }}>
      <div className="flex items-center justify-between gap-3">
        <h3 className="ui-label">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  );
}

// Before/After config diff, fetched lazily from GET /{id}/configs.
function DiffPanel({ crId }: { crId: string }) {
  const [loading, setLoading] = useState(true);
  const [configs, setConfigs] = useState<{ current_config: string | null; proposed_config: string | null } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setErr(null);
    endpoints.changeRequestConfigs(crId)
      .then((r) => { if (!cancelled) setConfigs(r.data); })
      .catch(() => { if (!cancelled) setErr("Could not load configuration text for this change request."); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [crId]);

  if (loading) return <div className="text-sm ui-muted">Loading diff…</div>;
  if (err) return <div className="text-sm font-medium" style={{ color: "var(--bad-fg)" }}>{err}</div>;
  return (
    <div className="space-y-2">
      <div className="text-sm ui-muted">
        Left is the device's current configuration. Right is the proposed remediation — syntax only until a human approves it.
      </div>
      <SideBySideDiff currentConfig={configs?.current_config} proposedConfig={configs?.proposed_config} />
    </div>
  );
}

// Exactly what deployment will send to the device -- never the whole configuration.
function DeployPlanPanel({ crId, revision }: { crId: string; revision?: number }) {
  const [plan, setPlan] = useState<PushPlan | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    let cancelled = false;
    setPlan(null);
    setErr(false);
    endpoints.changeRequestDeployPlan(crId)
      .then((r) => !cancelled && setPlan(r.data))
      .catch(() => !cancelled && setErr(true));
    return () => { cancelled = true; };
  }, [crId, revision]);
  if (err) return null;
  if (!plan) return <div className="text-sm ui-muted">Working out deploy commands…</div>;
  return (
    <div className="space-y-2">
      {plan.safe ? (
        <pre className="ui-code">{plan.commands.join("\n")}</pre>
      ) : (
        <div className="ui-callout ui-tone-bad text-sm font-medium">
          No safe minimal command set could be derived — deployment will be refused. Edit the proposal below.
        </div>
      )}
      {plan.warnings.map((w, i) => (
        <div key={i} className="text-sm font-medium" style={{ color: "var(--warn-fg)" }}>{w}</div>
      ))}
    </div>
  );
}

// Admin-only fine-tuning of the proposed change.
function EditProposal({ cr, onSaved }: { cr: ChangeRequest; onSaved: () => void }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [asSnippet, setAsSnippet] = useState(true);
  const [preview, setPreview] = useState<EditPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function start() {
    setMsg(null);
    setPreview(null);
    if (cr.snippet) {
      setAsSnippet(true);
      setText(cr.snippet);
    } else {
      const r = await endpoints.changeRequestConfigs(cr.id);
      setAsSnippet(false);
      setText(r.data.proposed_config || "");
    }
    setOpen(true);
  }

  const body = () => (asSnippet ? { snippet: text } : { proposed_config: text });

  async function doPreview() {
    setBusy(true);
    setMsg(null);
    try {
      setPreview((await endpoints.previewChangeRequestEdit(cr.id, body())).data);
    } catch (e: any) {
      setMsg(errText(e, "Preview failed."));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setBusy(true);
    setMsg(null);
    try {
      await endpoints.editChangeRequest(cr.id, body());
      setOpen(false);
      onSaved();
    } catch (e: any) {
      setMsg(errText(e, "Could not save the edit."));
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return <button className="ui-btn ui-btn-neutral ui-btn-sm" onClick={start}>Edit proposed change (admin)</button>;
  }
  return (
    <div className="ui-callout ui-tone-warn space-y-2">
      <div className="font-bold">{asSnippet ? "Proposed CLI commands" : "Proposed configuration"}</div>
      <div className="text-sm ui-callout-body">
        {asSnippet
          ? "Only these commands are merged onto the device's current configuration and pushed. "
          : "Editing the full proposed configuration; deployment pushes only the difference from the device. "}
        Saving re-validates the change and requires it to be approved again.
      </div>
      <textarea className="ui-field ui-mono h-48" style={{ fontSize: "0.8125rem" }} value={text} spellCheck={false}
        onChange={(e) => { setText(e.target.value); setPreview(null); }} />
      {preview && (
        <div className="space-y-1 text-sm">
          <div className="ui-callout-body">
            Preview: {preview.commands.length} command(s) will be pushed
            {preview.diff_stats && ` · +${preview.diff_stats.added} / −${preview.diff_stats.removed} lines vs current`}
            {preview.confidence && ` · merge confidence ${preview.confidence}`}
          </div>
          <pre className="ui-code">{preview.commands.join("\n")}</pre>
          {(preview.warnings || []).map((w, i) => <div key={i} className="font-medium">{w}</div>)}
        </div>
      )}
      {msg && <div className="text-sm font-medium" style={{ color: "var(--bad-fg)" }}>{msg}</div>}
      <div className="flex gap-2 flex-wrap">
        <button className="ui-btn ui-btn-neutral" disabled={busy || !text.trim()} onClick={doPreview}>Preview</button>
        <button className="ui-btn ui-btn-deploy" disabled={busy || !text.trim()} onClick={save}>{busy ? "Working…" : "Save & re-validate"}</button>
        <button className="ui-btn ui-btn-ghost" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </div>
  );
}

/**
 * Developer sandbox: force an active deployment into DRIFTED without touching a
 * device. Hides itself when the backend returns 404 (ENABLE_DEV_SIMULATION
 * unset). Drives the *operator-initiated* rollback path -- nothing here reverts
 * automatically, and the copy says so.
 */
function SimulateDriftTrigger({ crId, deployments, onSimulated }: {
  crId: string; deployments: DeploymentRecord[]; onSimulated: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const driftable = deployments.find((d) => (d.status === "DEPLOYED" || d.status === "VERIFIED") && !d.rolled_back);
  if (unavailable || !driftable) return null;

  async function fire() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await endpoints.simulateDeploymentDrift(crId, driftable!.id);
      setMsg(r.data.alert_dispatched
        ? "Drift injected and a rollback-required alert was raised. Use the rollback control on the deployment above."
        : "Drift injected, but the alert could not be dispatched — check the server logs.");
      onSimulated();
    } catch (e: any) {
      if (e?.response?.status === 404) { setUnavailable(true); return; }
      setMsg(e?.response?.status === 403
        ? "Your role can't simulate drift — admin or operator is required."
        : errText(e, "Could not simulate drift."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="ui-callout ui-tone-idle space-y-2" style={{ borderStyle: "dashed" }}>
      <div className="flex items-center gap-2">
        <Chip tone="warn">DEV</Chip>
        <span className="font-semibold ui-text">Simulate deployment drift</span>
      </div>
      <div className="text-sm ui-muted">
        Forces the latest deployment into DRIFTED and fires the real rollback-required alert — no device is contacted.
        It exercises the operator-initiated rollback path; the platform never reverts on its own.
      </div>
      <button className="ui-btn ui-btn-neutral ui-btn-sm" onClick={fire} disabled={busy}>{busy ? "Injecting drift…" : "Simulate drift on latest deployment"}</button>
      {msg && <div className="text-sm ui-text">{msg}</div>}
    </div>
  );
}

const isLive = (d: DeploymentRecord) =>
  d.status === "PENDING" || d.status === "DEPLOYING" || d.stages.some((s) => s.status === "running");

export default function ChangeRequests() {
  const { hasRole, username } = useAuth();
  const canApprove = hasRole("security_analyst"); // security_analyst OR admin
  const canDeploy = hasRole("operator");          // operator OR admin (deploy / rollback / simulate)
  const canEdit = hasRole("admin");
  const [items, setItems] = useState<ChangeRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [deploymentsById, setDeploymentsById] = useState<Record<string, DeploymentRecord[]>>({});
  const [openPipeline, setOpenPipeline] = useState<Record<string, boolean>>({});
  const [openTrail, setOpenTrail] = useState<Record<string, boolean>>({});
  const [diffOpenId, setDiffOpenId] = useState<string | null>(null);
  const [deployTarget, setDeployTarget] = useState<ChangeRequest | null>(null);
  const [deployingId, setDeployingId] = useState<string | null>(null);
  const [searchParams] = useSearchParams();
  const linkedDeviceId = searchParams.get("device");
  const linkedCrId = searchParams.get("cr");
  const [didAutoOpen, setDidAutoOpen] = useState(false);

  const load = useCallback(() => {
    return endpoints
      .changeRequests(statusFilter ? { status: statusFilter } : undefined)
      .then((r) => setItems(r.data.change_requests))
      .finally(() => setLoading(false));
  }, [statusFilter]);

  useEffect(() => { setLoading(true); load(); }, [load]);

  const loadDeployments = useCallback(async (id: string) => {
    const r = await endpoints.changeRequestDeployments(id);
    setDeploymentsById((prev) => ({ ...prev, [id]: r.data.deployments }));
    return r.data.deployments;
  }, []);

  // Deployments already made are shown up-front: the auditor should not have to
  // click to discover that a change failed.
  const fetchedRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    items.filter((c) => ["APPROVED", "DEPLOYING", "DEPLOYED", "FAILED"].includes(c.status)).forEach((c) => {
      if (!fetchedRef.current.has(c.id)) {
        fetchedRef.current.add(c.id);
        loadDeployments(c.id).catch(() => undefined);
      }
    });
  }, [items, loadDeployments]);

  // Live progress: poll while any deployment is still running.
  useEffect(() => {
    const live = Object.entries(deploymentsById).filter(([, ds]) => ds.some(isLive)).map(([id]) => id);
    if (live.length === 0) return;
    const t = setInterval(() => { live.forEach((id) => loadDeployments(id).catch(() => undefined)); load(); }, 1500);
    return () => clearInterval(t);
  }, [deploymentsById, loadDeployments, load]);

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

  async function deploy(cr: ChangeRequest, transport: string) {
    setDeployTarget(null);
    setError(null);
    setDeployingId(cr.id);
    setOpenPipeline((p) => ({ ...p, [cr.id]: true }));
    // The POST blocks until the pipeline finishes; poll the deployment list
    // meanwhile so each stage lights up as it happens.
    const poll = setInterval(() => { loadDeployments(cr.id).catch(() => undefined); }, 1000);
    try {
      await endpoints.deployChangeRequest(cr.id, { transport });
    } catch (e: any) {
      setError(errText(e, "Deployment failed to start."));
    } finally {
      clearInterval(poll);
      await Promise.all([load(), loadDeployments(cr.id).catch(() => undefined)]);
      setDeployingId(null);
    }
  }

  const cancelDeploy = useCallback(() => setDeployTarget(null), []);

  return (
    <div>
      <PageHeader
        title="Change Requests"
        subtitle="Proposed configuration changes, validated through the same OPA / Batfish / risk pipeline as scans. AI writes the syntax; nothing is deployed until a designated reviewer approves it, and every step of the deployment is recorded."
        action={
          <select className="ui-field" style={{ width: "auto" }} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Filter by status">
            <option value="">All statuses</option>
            <option value="PENDING_APPROVAL">Pending approval</option>
            <option value="APPROVED">Approved</option>
            <option value="REJECTED">Rejected</option>
            <option value="DEPLOYED">Deployed</option>
            <option value="FAILED">Failed</option>
          </select>
        }
      />
      <div className="px-8 pb-8 space-y-4">
        {error && <div className="ui-callout ui-tone-bad font-medium" role="alert">{error}</div>}
        {loading && <Loading />}
        {!loading && items.length === 0 && (
          <EmptyState message="No change requests yet. Change requests are created via POST /api/change-requests (e.g. from an AI remediation suggestion or a manual proposal)." />
        )}
        {!loading && items.map((cr) => {
          const deployments = deploymentsById[cr.id] || [];
          const linked = linkedCrId === cr.id || (!linkedCrId && linkedDeviceId === cr.device_id);
          const preDeploy = ["PENDING_APPROVAL", "APPROVED", "DRAFT"].includes(cr.status);
          const pipelineOpen = openPipeline[cr.id] ?? true;
          const failedDeploy = deployments.find((d) => d.failed_stage);
          return (
            <article key={cr.id} id={`cr-${cr.id}`} className="card"
              style={linked ? { boxShadow: "0 0 0 2px var(--brand)" } : undefined}>
              {/* Header */}
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-base font-bold ui-text">Device <span className="ui-mono">{cr.device_id}</span></h2>
                    <Chip tone={verdictTone(cr.status)}>{statusText(cr.status)}</Chip>
                    {cr.source === "ai_suggestion" && <Chip tone="info">AI-suggested</Chip>}
                    {(cr.revision ?? 1) > 1 && <Chip tone="idle">Revision {cr.revision}</Chip>}
                    {failedDeploy && <Chip tone="bad">Failed at: {failedDeploy.stages.find((s) => s.status === "failed")?.label}</Chip>}
                  </div>
                  <div className="text-sm ui-muted">Created {fmt(cr.created_at)}{cr.created_by && ` by ${cr.created_by}`}</div>
                </div>
                {(cr.status === "APPROVED" || cr.status === "FAILED") && (
                  <button className="ui-btn ui-btn-deploy" disabled={!canDeploy || deployingId === cr.id}
                    title={canDeploy ? undefined : "Requires operator or admin role"}
                    onClick={() => setDeployTarget(cr)}>
                    {!canDeploy && "🔒 "}{deployingId === cr.id ? "Deploying…" : (cr.status === "FAILED" ? "Retry Deployment…" : "Deploy…")}
                  </button>
                )}
              </div>

              {/* Validation verdict */}
              <div className="flex items-center gap-2 flex-wrap mt-3">
                <Chip tone={verdictTone(cr.opa_decision)}>OPA {cr.opa_decision || "—"}</Chip>
                <Chip tone={verdictTone(cr.batfish_status)}>Batfish {(cr.batfish_status || "—").replace(/_/g, " ")}</Chip>
                <Chip tone={verdictTone(cr.risk_level)}>Risk {cr.risk_level || "—"}{cr.risk_score != null && ` (${cr.risk_score})`}</Chip>
                <Chip tone={verdictTone(cr.final_decision)}>Final decision {cr.final_decision || "—"}</Chip>
              </div>
              {cr.final_reason && <div className="text-sm ui-muted mt-2">{cr.final_reason}</div>}

              {cr.snapshot_diff && cr.snapshot_diff.status !== "NOT_CHECKED" && (
                <Section title="Network impact (Batfish, current → proposed)">
                  <BatfishDeltaView diff={cr.snapshot_diff} />
                </Section>
              )}

              <Section
                title="Configuration diff"
                aside={
                  <button className="ui-btn ui-btn-ghost ui-btn-sm" onClick={() => setDiffOpenId(diffOpenId === cr.id ? null : cr.id)}>
                    {diffOpenId === cr.id ? "Hide" : "Show current vs. proposed"}
                  </button>
                }
              >
                {diffOpenId === cr.id
                  ? <DiffPanel key={`${cr.id}-${cr.revision || 1}`} crId={cr.id} />
                  : <div className="text-sm ui-muted">Side-by-side view of what changes on the device.</div>}
              </Section>

              {preDeploy && (
                <Section title="Commands that will be pushed">
                  <DeployPlanPanel crId={cr.id} revision={cr.revision} />
                  {cr.edited_by && (
                    <div className="text-sm ui-muted">
                      Edited by {cr.edited_by}{cr.edited_at && ` at ${fmt(cr.edited_at)}`} (revision {cr.revision}) — approval was reset.
                    </div>
                  )}
                  {canEdit && <EditProposal cr={cr} onSaved={() => { load(); }} />}
                </Section>
              )}

              {/* Human decision */}
              <Section title={cr.status === "PENDING_APPROVAL" ? "Your decision" : "Review decision"}>
                {cr.status === "PENDING_APPROVAL" ? (
                  <ApprovalPanel cr={cr} canApprove={canApprove} currentUser={username}
                    onDone={() => { load(); }} onStale={() => { load(); }} />
                ) : (
                  <DecisionSummary cr={cr} />
                )}
                {(cr.status === "APPROVED" || cr.status === "FAILED") && !canDeploy && (
                  <div className="text-sm ui-muted">Deploying requires the operator or admin role.</div>
                )}
              </Section>

              {/* Deployment pipeline */}
              {(deployments.length > 0 || deployingId === cr.id) && (
                <Section
                  title={`Deployment pipeline (${deployments.length})`}
                  aside={
                    <button className="ui-btn ui-btn-ghost ui-btn-sm" onClick={() => setOpenPipeline((p) => ({ ...p, [cr.id]: !pipelineOpen }))}>
                      {pipelineOpen ? "Hide" : "Show"}
                    </button>
                  }
                >
                  {pipelineOpen && (
                    <div className="space-y-3">
                      {deployments.length === 0 && <div className="text-sm ui-muted">Starting deployment…</div>}
                      {deployments.map((d) => (
                        <DeploymentPipelineCard key={d.id} d={d} crId={cr.id} canRollback={canDeploy}
                          onChanged={() => { loadDeployments(cr.id); load(); }} />
                      ))}
                      <SimulateDriftTrigger crId={cr.id} deployments={deployments} onSimulated={() => loadDeployments(cr.id)} />
                    </div>
                  )}
                </Section>
              )}

              <Section
                title={`Review trail (${(cr.review_events || []).length})`}
                aside={
                  <button className="ui-btn ui-btn-ghost ui-btn-sm" onClick={() => setOpenTrail((p) => ({ ...p, [cr.id]: !p[cr.id] }))}>
                    {openTrail[cr.id] ? "Hide" : "Show"}
                  </button>
                }
              >
                {openTrail[cr.id]
                  ? <ReviewTrail events={cr.review_events} />
                  : <div className="text-sm ui-muted">Who submitted, edited, approved, rejected, deployed or rolled back this change, and why.</div>}
              </Section>
            </article>
          );
        })}
      </div>

      {deployTarget && (
        <DeployDialog cr={deployTarget} transports={TRANSPORTS} defaultTransport="ssh"
          onCancel={cancelDeploy} onConfirm={(t) => deploy(deployTarget, t)} />
      )}
    </div>
  );
}
