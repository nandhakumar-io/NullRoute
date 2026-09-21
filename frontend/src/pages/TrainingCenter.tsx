import { useEffect, useState } from "react";
import { 
  endpoints, 
  CommandMapping, 
  DatasetVersion, 
  TrainingJob, 
  ModelRegistryEntry,
  TrainingExample,
} from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";
import DatasetsPanel from "../components/training/DatasetsPanel";
import JobsPanel from "../components/training/JobsPanel";
import ModelsPanel from "../components/training/ModelsPanel";

function apiErrorMessage(e: any, fallback: string): string {
  const detail = e?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (e?.response?.status === 403) return "You don't have permission to do that (admin or security_analyst role required).";
  if (e?.response?.status === 401) return "Your session has expired — please sign in again.";
  return fallback;
}

const TABS = [
  { id: "reviews", label: "Human Review", icon: "🔍" },
  { id: "examples", label: "Training Examples", icon: "🧪" },
  { id: "datasets", label: "Datasets", icon: "📦" },
  { id: "jobs", label: "Training Jobs", icon: "⚙️" },
  { id: "models", label: "Model Registry", icon: "🏷️" },
] as const;

export default function TrainingCenter() {
  const [activeTab, setActiveTab] = useState<(typeof TABS)[number]["id"]>("reviews");

  // Reviews Tab state
  const [pending, setPending] = useState<CommandMapping[] | null>(null);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [editValues, setEditValues] = useState<Record<string, string>>({});
  const [correctionReasons, setCorrectionReasons] = useState<Record<string, string>>({});
  const [reviewError, setReviewError] = useState<Record<string, string>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);

  // Training Examples Tab state -- the second HITL gate: turns accumulated
  // approved/corrected commands into a curated, human-validated pool the
  // Datasets tab can actually pull from (validation_status PENDING -> VALIDATED).
  const [examples, setExamples] = useState<TrainingExample[] | null>(null);
  const [exampleFilter, setExampleFilter] = useState<"" | "APPROVED" | "CORRECTED" | "REJECTED">("");
  const [exampleStatus, setExampleStatus] = useState<"PENDING" | "VALIDATED" | "EXCLUDED" | "ALL">("PENDING");
  const [adminAutoValidate, setAdminAutoValidate] = useState<boolean | null>(null);
  const [exampleBusyId, setExampleBusyId] = useState<string | null>(null);
  const [exampleBulkBusy, setExampleBulkBusy] = useState(false);
  const [selectedExampleIds, setSelectedExampleIds] = useState<Set<string>>(new Set());

  // Datasets Tab state

  // Jobs Tab state

  // Models Tab state

  // Page-level error banner -- surfaces load failures (network down, no
  // permission, backend error) that would otherwise leave a tab stuck on
  // "Loading…" forever with no indication anything went wrong.
  const [loadError, setLoadError] = useState<string | null>(null);

  function load() {
    setLoadError(null);
    if (activeTab === "reviews") {
      endpoints.pendingMappings()
        .then((r) => setPending(r.data))
        .catch((e) => { setPending([]); setLoadError(apiErrorMessage(e, "Failed to load pending reviews.")); });
    } else if (activeTab === "examples") {
      endpoints.trainingExamples(exampleStatus, exampleFilter || undefined)
        .then((r) => setExamples(r.data))
        .catch((e) => { setExamples([]); setLoadError(apiErrorMessage(e, "Failed to load training examples.")); });
    }
  }

  useEffect(() => {
    load();
    // Reviews queue is where HITL self-training actually happens -- poll it
    // so a mapping another reviewer just approved (or a new unknown command
    // the AI just flagged) shows up without a manual page refresh.
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, [activeTab, exampleFilter, exampleStatus]);

  useEffect(() => {
    endpoints.trainingSettings().then((r) => setAdminAutoValidate(r.data.admin_auto_validate)).catch(() => {});
  }, []);

  // --- Reviews Tab ---
  // Categorised dropdown of all known normalized security parameters
  const SECURITY_CATEGORIES: Record<string, string[]> = {
    "Management — SSH": [
      "management.ssh.enabled", "management.ssh.version", "management.ssh.idle_timeout", "management.ssh.port",
    ],
    "Management — Telnet": ["management.telnet.enabled"],
    "Management — HTTP/HTTPS": [
      "management.http.enabled", "management.http.https_only", "management.http.port",
    ],
    "Management — General": ["management.banner_configured"],
    "Logging": [
      "logging.enabled", "logging.remote_syslog", "logging.log_level", "logging.ntp_synced",
    ],
    "AAA": [
      "aaa.enabled", "aaa.authentication_method", "aaa.accounting_enabled", "aaa.local_fallback",
    ],
    "Password Policy": [
      "password_policy.min_length", "password_policy.complexity_required", "password_policy.encrypted_storage",
    ],
    "SNMP": ["snmp.enabled", "snmp.community_strings_default"],
    "Interfaces": ["interfaces.unused_ports_disabled", "interfaces.port_security_enabled"],
    "Routing / ACLs": ["routing.ospf.enabled", "acls", "vlans"],
    "Unknown / Other": ["extra_parameters.unknown_evidence"],
  };

  async function review(id: string, action: "approve" | "correct" | "reject") {
    setReviewError((prev) => ({ ...prev, [id]: "" }));

    // A correction is only meaningful if the reviewer actually told us what
    // the AI got wrong: which parameter it maps to AND what the true value
    // is. Sending a placeholder value here would get embedded and stored as
    // permanent (wrong) ground truth for the DistilBERT retraining set, so
    // we refuse to submit a correction that's missing either field instead
    // of silently fabricating one.
    if (action === "correct") {
      if (!edits[id]) {
        setReviewError((prev) => ({ ...prev, [id]: "Pick the correct security parameter before submitting a correction." }));
        return;
      }
      if (!editValues[id]?.trim()) {
        setReviewError((prev) => ({ ...prev, [id]: "Enter the actual value observed in the config before submitting a correction." }));
        return;
      }
      if (!correctionReasons[id]?.trim()) {
        setReviewError((prev) => ({ ...prev, [id]: "A reason is required so this correction is useful as training signal." }));
        return;
      }
    }

    const normalized_facts =
      action === "correct"
        ? { facts: [{ parameter: edits[id], value: editValues[id].trim() }] }
        : undefined;

    setBusyId(id);
    try {
      await endpoints.reviewMapping(id, {
        action,
        normalized_parameter: edits[id] ? edits[id] : undefined,
        normalized_facts,
        correction_reason: correctionReasons[id],
      });
      load();
    } catch (e: any) {
      setReviewError((prev) => ({ ...prev, [id]: apiErrorMessage(e, `Failed to ${action} this mapping.`) }));
    } finally {
      setBusyId(null);
    }
  }

  async function bulkApproveHighConfidence() {
    if (!pending) return;
    const highConf = pending.filter((m) => m.confidence >= 0.85);
    setBulkBusy(true);
    setLoadError(null);
    try {
      const results = await Promise.allSettled(highConf.map((m) => endpoints.reviewMapping(m.id, { action: "approve" })));
      const failures = results.filter((r) => r.status === "rejected").length;
      if (failures > 0) {
        setLoadError(`${failures} of ${highConf.length} bulk approvals failed — the rest were applied.`);
      }
      load();
    } finally {
      setBulkBusy(false);
    }
  }

  // --- Training Examples Tab ---
  async function validateExample(id: string) {
    setExampleBusyId(id);
    setLoadError(null);
    try {
      await endpoints.validateTrainingExample(id);
      setSelectedExampleIds((prev) => { const next = new Set(prev); next.delete(id); return next; });
      load();
    } catch (e: any) {
      setLoadError(apiErrorMessage(e, "Failed to validate this training example."));
    } finally {
      setExampleBusyId(null);
    }
  }

  async function excludeExample(id: string) {
    setExampleBusyId(id);
    setLoadError(null);
    try {
      await endpoints.excludeTrainingExample(id);
      setSelectedExampleIds((prev) => { const next = new Set(prev); next.delete(id); return next; });
      load();
    } catch (e: any) {
      setLoadError(apiErrorMessage(e, "Failed to exclude this training example."));
    } finally {
      setExampleBusyId(null);
    }
  }

  function toggleExampleSelected(id: string) {
    setSelectedExampleIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  async function bulkValidateSelected() {
    if (selectedExampleIds.size === 0) return;
    setExampleBulkBusy(true);
    setLoadError(null);
    try {
      await endpoints.bulkValidateTrainingExamples(Array.from(selectedExampleIds));
      setSelectedExampleIds(new Set());
      load();
    } catch (e: any) {
      setLoadError(apiErrorMessage(e, "Bulk validation failed."));
    } finally {
      setExampleBulkBusy(false);
    }
  }

  // --- Datasets Tab ---
  return (
    <div>
      <PageHeader
        title="Training Center"
        subtitle="Manage the AI Human-in-the-Loop Feedback Architecture."
      />
      
      <div className="px-8 pb-0 border-b border-soc-border mb-6 flex gap-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-3 pb-3 pt-1 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? "text-cyan-400 border-cyan-400"
                : "text-slate-400 border-transparent hover:text-slate-200 hover:border-slate-700"
            }`}
          >
            <span className="opacity-80">{tab.icon}</span>
            {tab.label}
            {tab.id === "examples" && examples && examples.length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 text-[10px] font-semibold leading-none">
                {examples.length}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="px-8 pb-8">
        {loadError && (
          <div className="mb-4 px-4 py-3 rounded-lg border border-red-500/30 bg-red-950/20 text-sm text-red-400 flex items-center justify-between">
            <span>{loadError}</span>
            <button onClick={() => setLoadError(null)} className="text-red-400/70 hover:text-red-300 ml-4">✕</button>
          </div>
        )}

        {activeTab === "reviews" && (
          <div>
            {!pending ? (
              <Loading />
            ) : pending.length === 0 ? (
              <EmptyState message="No unknown commands awaiting review. The AI is confident about everything it has seen so far." />
            ) : (
              <div className="space-y-4">
                {/* Bulk action header */}
                <div className="flex items-center justify-between mb-2">
                  <div className="text-sm text-slate-400">
                    <span className="font-semibold text-slate-200">{pending.length}</span> commands awaiting review ·{" "}
                    <span className="text-emerald-400 font-semibold">
                      {pending.filter((m) => m.confidence >= 0.85).length}
                    </span>{" "}
                    high-confidence (≥85%)
                  </div>
                  <button
                    onClick={bulkApproveHighConfidence}
                    disabled={bulkBusy || pending.filter((m) => m.confidence >= 0.85).length === 0}
                    className="btn-primary text-xs disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {bulkBusy ? "Approving…" : "✓ Bulk Approve High-Confidence (≥85%)"}
                  </button>
                </div>

                {pending.map((m) => {
                  const confPct = Math.round(m.confidence * 100);
                  const confColor = m.confidence >= 0.85 ? "#10b981" : m.confidence >= 0.60 ? "#f59e0b" : "#ef4444";
                  return (
                    <div key={m.id} className="card">
                      <div className="flex items-start justify-between gap-6">
                        <div className="flex-1 min-w-0">
                          <div className="text-xs text-slate-500 mb-1">Unknown command · <span className="text-amber-400">{m.vendor}</span></div>
                          <pre className="bg-black/40 rounded-lg px-3 py-2 text-sm text-emerald-300 overflow-x-auto">{m.raw_command_pattern}</pre>

                          <div className="mt-3 text-xs text-slate-500">AI suggestion</div>
                          <div className="text-sm text-slate-300">{m.ai_suggested_meaning}</div>

                          {/* Confidence bar */}
                          <div className="mt-3">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-xs text-slate-500">Confidence</span>
                              <span className="text-xs font-semibold" style={{ color: confColor }}>{confPct}%</span>
                              <span className="text-xs text-slate-600">· Example value: <span className="text-slate-300">{m.example_value}</span></span>
                            </div>
                            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                              <div className="h-full rounded-full transition-all" style={{ width: `${confPct}%`, background: confColor }} />
                            </div>
                          </div>

                          {/* Categorized dropdown instead of free-text */}
                          <div className="mt-4">
                            <label className="block text-xs text-slate-500 mb-1">Map to security parameter (pick a category, then the parameter)</label>
                            <select
                              defaultValue={m.normalized_parameter}
                              onChange={(e) => setEdits((prev) => ({ ...prev, [m.id]: e.target.value }))}
                              className="w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600 font-mono"
                            >
                              {Object.entries(SECURITY_CATEGORIES).map(([group, params]) => (
                                <optgroup key={group} label={group}>
                                  {params.map((p) => (
                                    <option key={p} value={p}>{p}</option>
                                  ))}
                                </optgroup>
                              ))}
                            </select>
                          </div>
                          <div className="mt-3">
                            <label className="block text-xs text-slate-500 mb-1">Corrected value (what the config actually shows, required for corrections)</label>
                            <input
                              defaultValue={m.example_value ?? undefined}
                              onChange={(e) => setEditValues((prev) => ({ ...prev, [m.id]: e.target.value }))}
                              className="w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyan-600"
                              placeholder="e.g. enabled, 22, true — the ground-truth value for this parameter"
                            />
                          </div>
                          <div className="mt-3">
                            <label className="block text-xs text-slate-500 mb-1">Reason for correction (required for corrections)</label>
                            <input
                              onChange={(e) => setCorrectionReasons((prev) => ({ ...prev, [m.id]: e.target.value }))}
                              className="w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600"
                              placeholder="Why was the AI wrong?"
                            />
                          </div>
                          {reviewError[m.id] && (
                            <div className="mt-2 text-xs text-red-400">{reviewError[m.id]}</div>
                          )}
                        </div>

                        <div className="flex flex-col gap-2 shrink-0 w-32">
                          <button disabled={busyId === m.id} onClick={() => review(m.id, "approve")} className="btn-primary text-sm w-full disabled:opacity-40 disabled:cursor-not-allowed">
                            {busyId === m.id ? "…" : "✓ Approve"}
                          </button>
                          <button disabled={busyId === m.id} onClick={() => review(m.id, "correct")} className="btn-secondary text-sm w-full bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30 disabled:opacity-40 disabled:cursor-not-allowed">
                            {busyId === m.id ? "…" : "✎ Correct"}
                          </button>
                          <button disabled={busyId === m.id} onClick={() => review(m.id, "reject")} className="btn-secondary text-sm w-full disabled:opacity-40 disabled:cursor-not-allowed">
                            {busyId === m.id ? "…" : "✕ Reject"}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === "examples" && (
          <div>
            <div className="mb-4 flex items-center justify-between gap-4 flex-wrap">
              <p className="text-sm text-slate-400 max-w-2xl">
                Every command a reviewer approved, corrected, or rejected above lands here first.
                Validate the ones that should feed the next dataset — this is what keeps a stray
                or low-quality correction from silently becoming training data.
                {adminAutoValidate && " Approvals and corrections made by an admin are validated automatically; analyst reviews wait here."}
              </p>
              <div className="flex items-center gap-2 shrink-0">
                <select
                  value={exampleStatus}
                  onChange={(e) => setExampleStatus(e.target.value as any)}
                  className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-600"
                >
                  <option value="PENDING">Awaiting validation</option>
                  <option value="VALIDATED">Validated</option>
                  <option value="EXCLUDED">Excluded</option>
                  <option value="ALL">All statuses</option>
                </select>
                <select
                  value={exampleFilter}
                  onChange={(e) => setExampleFilter(e.target.value as any)}
                  className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-600"
                >
                  <option value="">All actions</option>
                  <option value="CORRECTED">Corrected (unknown commands)</option>
                  <option value="APPROVED">Approved</option>
                  <option value="REJECTED">Rejected</option>
                </select>
                <button
                  onClick={bulkValidateSelected}
                  disabled={exampleBulkBusy || selectedExampleIds.size === 0}
                  className="btn-primary text-xs disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {exampleBulkBusy ? "Validating…" : `✓ Validate Selected (${selectedExampleIds.size})`}
                </button>
              </div>
            </div>

            {!examples ? (
              <Loading />
            ) : examples.length === 0 ? (
              <EmptyState message="No training examples awaiting dataset-level review. Everything reviewed so far has already been validated or excluded." />
            ) : (
              <div className="space-y-3">
                {examples.map((ex) => {
                  const actionColor =
                    ex.human_action === "CORRECTED" ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
                    : ex.human_action === "APPROVED" ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                    : "text-red-400 bg-red-500/10 border-red-500/30";
                  return (
                    <div key={ex.id} className="card">
                      <div className="flex items-start gap-4">
                        <input
                          type="checkbox"
                          checked={selectedExampleIds.has(ex.id)}
                          onChange={() => toggleExampleSelected(ex.id)}
                          className="mt-1.5 accent-cyan-500"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border ${actionColor}`}>
                              {ex.human_action}
                            </span>
                            {ex.vendor && <span className="text-xs text-slate-500">{ex.vendor}</span>}
                            {ex.intent && <span className="text-xs text-slate-600 font-mono">· {ex.intent}</span>}
                            <span className="text-xs text-slate-600 ml-auto">
                              {ex.created_by} · {ex.created_at ? new Date(ex.created_at).toLocaleString() : ""}
                            </span>
                          </div>
                          <pre className="bg-black/40 rounded-lg px-3 py-2 text-sm text-emerald-300 overflow-x-auto whitespace-pre-wrap">{ex.raw_config_redacted}</pre>
                          {ex.correction_reason && (
                            <div className="mt-2 text-xs text-slate-400">
                              <span className="text-slate-500">Reason:</span> {ex.correction_reason}
                            </div>
                          )}
                        </div>
                        <div className="flex flex-col gap-2 shrink-0 w-28">
                          <button
                            disabled={exampleBusyId === ex.id}
                            onClick={() => validateExample(ex.id)}
                            className="btn-primary text-xs w-full disabled:opacity-40 disabled:cursor-not-allowed"
                          >
                            {exampleBusyId === ex.id ? "…" : "✓ Validate"}
                          </button>
                          <button
                            disabled={exampleBusyId === ex.id}
                            onClick={() => excludeExample(ex.id)}
                            className="btn-secondary text-xs w-full disabled:opacity-40 disabled:cursor-not-allowed"
                          >
                            {exampleBusyId === ex.id ? "…" : "✕ Exclude"}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === "datasets" && <DatasetsPanel onError={setLoadError} />}
        {activeTab === "jobs" && <JobsPanel onError={setLoadError} />}
        {activeTab === "models" && <ModelsPanel onError={setLoadError} />}
      </div>
    </div>
  );
}