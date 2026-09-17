import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type {
  BulkApproveResponse,
  ComplianceBaselineDetail,
  ComplianceBaselineSummary,
  Device,
  Drift,
  DriftBaseline,
  DriftFleetSummary,
  DriftScanResponse,
  DriftSeverity,
  DriftStatus,
  DriftTrendResponse,
  FlappingDevicesResponse,
  LowRiskDriftCandidate,
  WeeklyGoldenDriftReport,
} from "../lib/types";
import { useAuth } from "../context/AuthContext";
import { useToast, errorMessage } from "../lib/toast";
import { useConfirm } from "../lib/confirm";

// ─── style maps ──────────────────────────────────────────────────────────────

const SEV_PILL: Record<DriftSeverity, string> = {
  critical: "bg-red-500/20 text-red-400 border border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
  medium:   "bg-amber-500/20 text-amber-400 border border-amber-500/30",
  low:      "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
};
const SEV_DOT: Record<DriftSeverity, string> = {
  critical: "bg-red-500", high: "bg-orange-500", medium: "bg-amber-500", low: "bg-emerald-500",
};
const STATUS_PILL: Record<DriftStatus, string> = {
  open:         "bg-amber-500/20 text-amber-300 border border-amber-500/30",
  approved:     "bg-blue-500/20 text-blue-300 border border-blue-500/30",
  rolled_back:  "bg-purple-500/20 text-purple-300 border border-purple-500/30",
  dismissed:    "bg-slate-700 text-slate-400 border border-slate-600",
};
const SEV_BAR_COLOR: Record<DriftSeverity, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#10b981",
};

// ─── sub-components ──────────────────────────────────────────────────────────

function StatCard({ label, value, accent, sub }: { label: string; value: string | number; accent: string; sub?: string }) {
  return (
    <div className={`relative overflow-hidden rounded-2xl bg-slate-900 border border-slate-800 p-5 flex flex-col gap-1`}>
      <div className={`absolute inset-0 opacity-10 rounded-2xl`} style={{ background: accent }} />
      <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">{label}</p>
      <p className="text-3xl font-black text-slate-100 mt-1">{value}</p>
      {sub && <p className="text-xs text-slate-500">{sub}</p>}
    </div>
  );
}

function SeverityBar({ by_severity }: { by_severity: Record<DriftSeverity, number> }) {
  const total = Object.values(by_severity).reduce((a, b) => a + b, 0);
  if (!total) return <div className="h-3 rounded-full bg-slate-800 text-xs text-slate-500 flex items-center px-2">No open drifts</div>;
  const segs: DriftSeverity[] = ["critical", "high", "medium", "low"];
  return (
    <div className="flex h-3 rounded-full overflow-hidden gap-px">
      {segs.map(s => {
        const pct = (by_severity[s] / total) * 100;
        if (!pct) return null;
        return <div key={s} style={{ width: `${pct}%`, background: SEV_BAR_COLOR[s] }} title={`${s}: ${by_severity[s]}`} />;
      })}
    </div>
  );
}

function TrendChart({ trend }: { trend: DriftTrendResponse }) {
  const max = Math.max(1, ...trend.points.map(p => p.total));
  return (
    <div className="flex items-end gap-1 h-32 w-full">
      {trend.points.map((p, i) => (
        <div key={i} className="flex-1 flex flex-col items-center justify-end h-full group relative">
          <div className="w-full flex flex-col justify-end rounded-t overflow-hidden" style={{ height: "100%", background: "rgba(51,65,85,0.4)" }}>
            <div style={{ height: `${(p.critical / max) * 100}%`, background: "#ef4444" }} title={`${p.critical} critical`} />
            <div style={{ height: `${(p.high / max) * 100}%`, background: "#f97316" }} title={`${p.high} high`} />
            <div style={{ height: `${((p.total - p.critical - p.high) / max) * 100}%`, background: "#3b82f6" }} title={`${p.total - p.critical - p.high} other`} />
          </div>
          <div className="absolute -top-7 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity z-10 bg-slate-800 border border-slate-700 text-slate-100 text-[10px] font-semibold px-2 py-1 rounded whitespace-nowrap shadow-xl">
            {p.total} drifts
          </div>
          <span className="text-[9px] text-slate-600 mt-1">{new Date(p.bucket_start).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>
        </div>
      ))}
    </div>
  );
}

function DiffViewer({ diffText }: { diffText: string }) {
  const lines = diffText.split("\n");
  return (
    <div className="font-mono text-xs rounded-xl overflow-auto max-h-96 bg-slate-950 border border-slate-800">
      {lines.map((line, i) => {
        let cls = "text-slate-400 px-4 py-px";
        if (line.startsWith("+++") || line.startsWith("---")) cls = "text-slate-500 px-4 py-px";
        else if (line.startsWith("@@")) cls = "text-blue-400 px-4 py-px bg-blue-950/30";
        else if (line.startsWith("+")) cls = "text-emerald-400 bg-emerald-950/30 px-4 py-px block";
        else if (line.startsWith("-")) cls = "text-red-400 bg-red-950/30 px-4 py-px block";
        return (
          <div key={i} className={`flex items-start ${cls}`}>
            <span className="select-none text-slate-700 w-8 shrink-0 text-right mr-3">{i + 1}</span>
            <span className="whitespace-pre">{line || " "}</span>
          </div>
        );
      })}
    </div>
  );
}

// ─── main page ───────────────────────────────────────────────────────────────

const SEVERITY_FILTERS: { value: DriftSeverity | "all"; label: string }[] = [
  { value: "all", label: "All" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

export default function DriftPage() {
  const { hasRole } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const canReview = hasRole("admin");

  // ── core data ──
  const [summary, setSummary] = useState<DriftFleetSummary | null>(null);
  const [drifts, setDrifts] = useState<Drift[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [trend, setTrend] = useState<DriftTrendResponse | null>(null);
  const [flapping, setFlapping] = useState<FlappingDevicesResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // ── selected drift detail ──
  const [selected, setSelected] = useState<Drift | null>(null);
  const [detail, setDetail] = useState<DriftScanResponse["drift"] | null>(null);
  const [recommendation, setRecommendation] = useState<{ recommended: boolean; reason: string } | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // ── filters ──
  const [severityFilter, setSeverityFilter] = useState<DriftSeverity | "all">("all");
  const [statusFilter, setStatusFilter] = useState<DriftStatus | "all">("all");

  // ── on-demand scan ──
  const [scanDeviceId, setScanDeviceId] = useState("");
  const [scanBaseline, setScanBaseline] = useState<DriftBaseline>("previous_backup");
  const [scanning, setScanning] = useState(false);
  const [scanStage, setScanStage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [findings, setFindings] = useState<string[]>([]);

  // ── review/remediation ──
  const [reviewing, setReviewing] = useState(false);
  const [remediating, setRemediating] = useState(false);
  const [remediationNotice, setRemediationNotice] = useState<string | null>(null);
  const [remediationError, setRemediationError] = useState<string | null>(null);

  // ── weekly report ──
  const [weeklyReport, setWeeklyReport] = useState<WeeklyGoldenDriftReport | null>(null);
  const [weeklyLoading, setWeeklyLoading] = useState(false);
  const [weeklyOpen, setWeeklyOpen] = useState(false);

  // ── low-risk bulk approve ──
  const [lowRiskCandidates, setLowRiskCandidates] = useState<LowRiskDriftCandidate[] | null>(null);
  const [lowRiskLoading, setLowRiskLoading] = useState(false);
  const [lowRiskOpen, setLowRiskOpen] = useState(false);
  const [lowRiskSelected, setLowRiskSelected] = useState<Set<string>>(new Set());
  const [bulkApproving, setBulkApproving] = useState(false);

  // ── compliance role baselines ──
  const [roleBaselines, setRoleBaselines] = useState<ComplianceBaselineSummary[]>([]);
  const [rolesInUse, setRolesInUse] = useState<string[]>([]);
  const [baselinesLoading, setBaselinesLoading] = useState(false);
  const [editingRole, setEditingRole] = useState<string | null>(null);
  const [roleForm, setRoleForm] = useState({ device_role: "", config: "", description: "" });
  const [roleFormSaving, setRoleFormSaving] = useState(false);
  const [roleFormError, setRoleFormError] = useState<string | null>(null);

  const hostnameFor = useCallback(
    (deviceId: string) => devices.find(d => d.id === deviceId)?.hostname || deviceId.slice(0, 8),
    [devices]
  );

  const load = useCallback(() => {
    // Was Promise.all(...).catch(() => {}) -- if ANY one of these 5 calls
    // failed (a 4xx/5xx, a network blip), the whole .then() never ran and
    // the .catch swallowed it silently, leaving EVERY piece of state at
    // its initial empty value -- including the device list, even when
    // /api/devices itself succeeded fine. That's why "Select device..."
    // could show zero options with no visible error anywhere: one
    // unrelated endpoint (e.g. /drift/trends) failing was enough to blank
    // the whole page. Promise.allSettled applies each result on its own
    // and logs whichever ones failed, instead of an all-or-nothing swallow.
    Promise.allSettled([
      api.get<DriftFleetSummary>("/api/v1/drift/summary"),
      api.get<Drift[]>("/api/v1/drift"),
      api.get<{ items: Device[] } | Device[]>("/api/devices", { params: { limit: 500 } }),
      api.get<DriftTrendResponse>("/api/v1/drift/trends", { params: { days: 90, bucket_days: 7 } }),
      api.get<FlappingDevicesResponse>("/api/v1/drift/flapping", { params: { days: 30, min_events: 3 } }),
    ]).then(([sumRes, driftRes, devRes, trendRes, flappRes]) => {
      if (sumRes.status === "fulfilled") setSummary(sumRes.value.data);
      else console.error("Drift page: /api/v1/drift/summary failed", sumRes.reason);

      if (driftRes.status === "fulfilled") setDrifts(driftRes.value.data);
      else console.error("Drift page: /api/v1/drift failed", driftRes.reason);

      if (devRes.status === "fulfilled") {
        const items = (devRes.value.data as any).items ?? devRes.value.data;
        setDevices(Array.isArray(items) ? items : []);
      } else {
        console.error("Drift page: /api/devices failed", devRes.reason);
        setDevices([]);
      }

      if (trendRes.status === "fulfilled") setTrend(trendRes.value.data);
      else console.error("Drift page: /api/v1/drift/trends failed", trendRes.reason);

      if (flappRes.status === "fulfilled") setFlapping(flappRes.value.data);
      else console.error("Drift page: /api/v1/drift/flapping failed", flappRes.reason);
    }).finally(() => setLoading(false));
  }, []);

  const loadRoleBaselines = useCallback(() => {
    setBaselinesLoading(true);
    Promise.all([
      api.get<ComplianceBaselineSummary[]>("/api/v1/compliance-baselines"),
      api.get<string[]>("/api/v1/compliance-baselines/device-roles"),
    ]).then(([bRes, rRes]) => { setRoleBaselines(bRes.data); setRolesInUse(rRes.data); })
      .finally(() => setBaselinesLoading(false));
  }, []);

  useEffect(() => { load(); loadRoleBaselines(); }, []);

  useEffect(() => {
    if (!selected) { setDetail(null); setRecommendation(null); return; }
    setDetailLoading(true);
    setRemediationNotice(null);
    setRemediationError(null);
    Promise.all([
      api.get(`/api/v1/drift/${selected.id}`),
      api.get(`/api/v1/drift/${selected.id}/rollback-recommendation`),
    ]).then(([dRes, rRes]) => { setDetail(dRes.data); setRecommendation(rRes.data); })
      .finally(() => setDetailLoading(false));
  }, [selected?.id]);

  const filtered = useMemo(() =>
    drifts.filter(d =>
      (severityFilter === "all" || d.severity === severityFilter) &&
      (statusFilter === "all" || d.status === statusFilter)
    ), [drifts, severityFilter, statusFilter]);

  const runScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanDeviceId) return;
    setScanning(true); setScanError(null); setFindings([]);
    setScanStage("Connecting to device…");
    try {
      await new Promise(r => setTimeout(r, 400));
      setScanStage("Fetching live running config…");
      await new Promise(r => setTimeout(r, 400));
      setScanStage("Comparing against baseline…");
      const res = await api.post<DriftScanResponse>(`/api/v1/devices/${scanDeviceId}/drift/scan`, { baseline: scanBaseline });
      setScanStage("Done ✓");
      setFindings(res.data.findings);
      load();
      setSelected(res.data.drift);
      setDetail(res.data.drift);
      setRecommendation(res.data.rollback_recommendation);
      setTimeout(() => setScanStage(null), 1500);
    } catch (err: any) {
      setScanError(err?.response?.data?.detail || "Drift scan failed.");
      setScanStage(null);
    } finally { setScanning(false); }
  };

  const review = async (status: DriftStatus) => {
    if (!selected) return;
    setReviewing(true);
    try {
      await api.patch(`/api/v1/drift/${selected.id}`, { status });
      load();
      setSelected(prev => prev ? { ...prev, status } : prev);
      setDetail(prev => prev ? { ...prev, status } : prev);
    } catch (err) { toast.error(errorMessage(err, "Failed to update drift status.")); }
    finally { setReviewing(false); }
  };

  const remediate = async () => {
    if (!detail) return;
    const ok = await confirm(`Submit a change request to push the ${detail.baseline === "golden_config" ? "golden config" : "role baseline"} back to this device? It will go through the normal approval queue.`, { confirmLabel: "Submit for approval" });
    if (!ok) return;
    setRemediating(true); setRemediationError(null);
    try {
      const res = await api.post<{ message: string; change_request_id: string }>(`/api/v1/drift/${detail.id}/remediate`);
      setRemediationNotice(res.data.message);
      load();
    } catch (err: any) { setRemediationError(err?.response?.data?.detail || "Failed to submit remediation."); }
    finally { setRemediating(false); }
  };

  const loadWeekly = () => {
    setWeeklyOpen(true); setWeeklyLoading(true);
    api.get<WeeklyGoldenDriftReport>("/api/v1/drift/report/weekly-golden-config", { params: { days: 7 } })
      .then(r => setWeeklyReport(r.data))
      .catch(() => setWeeklyReport(null))
      .finally(() => setWeeklyLoading(false));
  };

  const loadLowRisk = () => {
    setLowRiskOpen(true); setLowRiskLoading(true);
    api.get<LowRiskDriftCandidate[]>("/api/v1/drift/low-risk-candidates")
      .then(r => { setLowRiskCandidates(r.data); setLowRiskSelected(new Set(r.data.map(d => d.id))); })
      .finally(() => setLowRiskLoading(false));
  };

  const runBulkApprove = async () => {
    if (!lowRiskSelected.size) return;
    setBulkApproving(true);
    try {
      const res = await api.post<BulkApproveResponse>("/api/v1/drift/bulk-approve", { drift_ids: Array.from(lowRiskSelected) });
      toast.success(`Approved ${res.data.approved_count} low-risk drift record(s).`);
      setLowRiskCandidates(prev => prev ? prev.filter(d => !res.data.approved_ids.includes(d.id)) : prev);
      setLowRiskSelected(new Set());
      load();
    } catch (err) { toast.error(errorMessage(err, "Bulk approve failed.")); }
    finally { setBulkApproving(false); }
  };

  const startEditRole = async (role: string) => {
    setRoleFormError(null);
    if (role) {
      try {
        const res = await api.get<ComplianceBaselineDetail>(`/api/v1/compliance-baselines/${encodeURIComponent(role)}`);
        setRoleForm({ device_role: role, config: res.data.config, description: res.data.description || "" });
      } catch { setRoleForm({ device_role: role, config: "", description: "" }); }
    } else { setRoleForm({ device_role: "", config: "", description: "" }); }
    setEditingRole(role || "__new__");
  };

  const saveRoleBaseline = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!roleForm.device_role.trim() || !roleForm.config.trim()) return;
    setRoleFormSaving(true); setRoleFormError(null);
    try {
      await api.put(`/api/v1/compliance-baselines/${encodeURIComponent(roleForm.device_role.trim())}`, { config: roleForm.config, description: roleForm.description || null });
      setEditingRole(null); loadRoleBaselines();
    } catch (err: any) { setRoleFormError(err?.response?.data?.detail || "Failed to save compliance baseline."); }
    finally { setRoleFormSaving(false); }
  };

  const deleteRoleBaseline = async (role: string) => {
    if (!(await confirm(`Delete the compliance baseline for role "${role}"?`, { confirmLabel: "Delete" }))) return;
    try {
      await api.delete(`/api/v1/compliance-baselines/${encodeURIComponent(role)}`);
      loadRoleBaselines(); toast.success(`Baseline for "${role}" deleted.`);
    } catch (err) { toast.error(errorMessage(err, "Failed to delete compliance baseline.")); }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-400 text-sm">Loading drift data…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950">
      {/* ── PAGE HEADER ── */}
      <div className="px-8 pt-8 pb-6 border-b border-slate-800/60 bg-slate-900">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center gap-3">
              <span className="text-2xl">📡</span> Configuration Drift
            </h1>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Detect when live device configs diverge from their golden baseline — scanned continuously and on-demand.
              Unauthorised changes surface immediately, with AI-scored risk and one-click remediation.
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            <button onClick={loadWeekly} className="text-xs font-bold uppercase tracking-wider px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors">
              📋 This Week's Drift
            </button>
            {canReview && (
              <button onClick={loadLowRisk} className="text-xs font-bold uppercase tracking-wider px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white transition-colors">
                ⚡ Bulk Approve Low-Risk
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="px-8 py-6 space-y-6">
        {/* ── STAT CARDS ── */}
        {summary && (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard label="Open Drifts" value={summary.total_open_drifts} accent="linear-gradient(135deg,#f97316,#ef4444)" />
              <StatCard label="Devices Affected" value={summary.devices_drifted} accent="linear-gradient(135deg,#6366f1,#8b5cf6)" />
              <StatCard label="Avg. Compliance" value={`${summary.average_compliance_score}/100`} accent="linear-gradient(135deg,#0ea5e9,#3b82f6)" sub={summary.average_compliance_score >= 80 ? "✓ Healthy" : summary.average_compliance_score >= 60 ? "⚠ Needs attention" : "⛔ Critical"} />
              <StatCard label="Rollback Recommended" value={summary.rollback_recommended_count} accent="linear-gradient(135deg,#ef4444,#f43f5e)" />
            </div>

            {/* severity bar */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-widest">Fleet Drift Severity Distribution</p>
                <div className="flex gap-3 text-xs text-slate-500">
                  {(["critical","high","medium","low"] as DriftSeverity[]).map(s => (
                    <span key={s} className="flex items-center gap-1">
                      <span className={`w-2 h-2 rounded-full inline-block ${SEV_DOT[s]}`} />
                      {summary.by_severity?.[s] ?? 0} {s}
                    </span>
                  ))}
                </div>
              </div>
              <SeverityBar by_severity={summary.by_severity ?? { critical: 0, high: 0, medium: 0, low: 0 }} />
            </div>
          </>
        )}

        {/* ── TREND + FLAPPING ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <p className="text-sm font-bold text-slate-100 mb-1">Drift Trend (last {trend?.days ?? 90} days)</p>
            <p className="text-xs text-slate-500 mb-4">
              Fleet-wide drift detections per {trend?.bucket_days ?? 7}-day window.
              <span className="text-red-400 ml-2">■ Critical</span>
              <span className="text-orange-400 ml-2">■ High</span>
              <span className="text-blue-400 ml-2">■ Other</span>
            </p>
            {trend && trend.points.length > 0
              ? <TrendChart trend={trend} />
              : <p className="text-xs text-slate-500 text-center py-10">No drift activity in this window.</p>}
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <p className="text-sm font-bold text-slate-100 mb-1">Flapping Devices</p>
            <p className="text-xs text-slate-500 mb-3">
              {flapping ? `≥${flapping.min_events} drift events / ${flapping.days}d` : "Repeated drifters"}
            </p>
            {!flapping || flapping.devices.length === 0
              ? <p className="text-xs text-slate-500 text-center py-8">No repeatedly-drifting devices.</p>
              : (
                <ul className="space-y-2">
                  {flapping.devices.map(d => (
                    <li key={d.device_id} className="flex items-center justify-between text-xs py-2 border-b border-slate-800 last:border-0">
                      <div>
                        <p className="font-semibold text-slate-100">{d.hostname}</p>
                        <p className="text-slate-500 text-[11px]">last {new Date(d.last_detected_at).toLocaleDateString()}</p>
                      </div>
                      <div className="text-right flex flex-col items-end gap-1">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${SEV_PILL[d.max_severity]}`}>{d.event_count}× drifts</span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
          </div>
        </div>

        {/* ── WEEKLY REPORT ── */}
        {weeklyOpen && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm font-bold text-slate-100">This Week — Drifted from Golden Config</p>
              <button onClick={() => setWeeklyOpen(false)} className="text-slate-500 hover:text-slate-300 text-lg leading-none">✕</button>
            </div>
            {weeklyLoading
              ? <p className="text-xs text-slate-400 py-4 text-center">Loading…</p>
              : !weeklyReport || weeklyReport.devices.length === 0
                ? <p className="text-xs text-slate-500 italic text-center py-4">No device has drifted from its golden config in the last 7 days.</p>
                : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm min-w-[600px]">
                      <thead>
                        <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
                          <th className="pb-2 pr-4 font-semibold">Device</th>
                          <th className="pb-2 pr-4 font-semibold">Severity</th>
                          <th className="pb-2 pr-4 font-semibold">Compliance</th>
                          <th className="pb-2 pr-4 font-semibold">Lines Changed</th>
                          <th className="pb-2 pr-4 font-semibold">Detected</th>
                          <th className="pb-2 font-semibold">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {weeklyReport.devices.map(d => (
                          <tr key={d.id} onClick={() => setSelected(d)} className="cursor-pointer hover:bg-slate-800/60 transition-colors border-b border-slate-800/50">
                            <td className="py-2 pr-4 font-medium text-slate-100">{d.hostname}</td>
                            <td className="py-2 pr-4"><span className={`px-2 py-0.5 rounded-full text-[11px] font-bold ${SEV_PILL[d.severity]}`}>{d.severity}</span></td>
                            <td className="py-2 pr-4 text-slate-300">{d.compliance_score}/100</td>
                            <td className="py-2 pr-4 font-mono text-xs text-slate-300">+{d.added_lines}/-{d.removed_lines}</td>
                            <td className="py-2 pr-4 text-slate-500 text-xs">{new Date(d.detected_at).toLocaleString()}</td>
                            <td className="py-2"><span className={`px-2 py-0.5 rounded-full text-[11px] font-bold ${STATUS_PILL[d.status]}`}>{d.status.replace(/_/g," ")}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
          </div>
        )}

        {/* ── BULK LOW-RISK ── */}
        {lowRiskOpen && (
          <div className="bg-slate-900 border border-amber-800/40 rounded-2xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <p className="text-sm font-bold text-slate-100">Bulk Approve — Low-Risk Cosmetic Drifts</p>
                <p className="text-xs text-slate-500 mt-0.5">Only description/remark edits — no behavior changes.</p>
              </div>
              <button onClick={() => setLowRiskOpen(false)} className="text-slate-500 hover:text-slate-300 text-lg">✕</button>
            </div>
            {lowRiskLoading
              ? <p className="text-xs text-slate-400">Loading…</p>
              : !lowRiskCandidates || lowRiskCandidates.length === 0
                ? <p className="text-xs text-slate-500 italic">No low-risk candidates right now.</p>
                : (
                  <>
                    <div className="space-y-2 max-h-48 overflow-y-auto mb-4">
                      {lowRiskCandidates.map(d => (
                        <label key={d.id} className="flex items-center gap-3 text-xs cursor-pointer hover:bg-slate-800/40 rounded-lg px-2 py-1.5">
                          <input type="checkbox" checked={lowRiskSelected.has(d.id)} onChange={() => setLowRiskSelected(prev => { const s = new Set(prev); s.has(d.id) ? s.delete(d.id) : s.add(d.id); return s; })} className="accent-cyan-500" />
                          <span className="text-slate-100 font-medium">{d.hostname}</span>
                          <span className="text-slate-500">+{d.added_lines}/-{d.removed_lines} lines</span>
                        </label>
                      ))}
                    </div>
                    <button onClick={runBulkApprove} disabled={bulkApproving || !lowRiskSelected.size} className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold uppercase tracking-wider px-4 py-2 rounded-xl disabled:opacity-50 transition-colors">
                      {bulkApproving ? "Approving…" : `Approve ${lowRiskSelected.size} selected`}
                    </button>
                  </>
                )}
          </div>
        )}

        {/* ── ON-DEMAND SCAN ── */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
          <p className="text-sm font-bold text-slate-100 mb-1">On-Demand Drift Scan</p>
          <p className="text-xs text-slate-500 mb-4">Collect the live running config from a device and compare it against a baseline right now.</p>
          <form onSubmit={runScan} className="flex flex-wrap items-end gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Device</label>
              <select className="bg-slate-800 border border-slate-700 text-slate-100 text-sm rounded-xl px-3 py-2 min-w-[220px] focus:outline-none focus:ring-2 focus:ring-cyan-500"
                value={scanDeviceId} onChange={e => setScanDeviceId(e.target.value)} required>
                <option value="">Select device…</option>
                {devices.map(d => <option key={d.id} value={d.id}>{d.hostname} ({d.ip_address})</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Baseline</label>
              <select className="bg-slate-800 border border-slate-700 text-slate-100 text-sm rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                value={scanBaseline} onChange={e => setScanBaseline(e.target.value as DriftBaseline)}>
                <option value="previous_backup">Previous Backup</option>
                <option value="golden_config">Golden Config</option>
                <option value="role_baseline">Role Baseline</option>
              </select>
            </div>
            <button type="submit" disabled={scanning || !scanDeviceId}
              className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-bold px-5 py-2 rounded-xl disabled:opacity-50 transition-colors flex items-center gap-2">
              {scanning ? <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin inline-block" /> : "⚡"}
              {scanning ? (scanStage || "Scanning…") : "Run Drift Scan"}
            </button>
            {scanStage && !scanning && (
              <span className="text-emerald-400 text-xs font-semibold">{scanStage}</span>
            )}
          </form>
          {scanError && <p className="text-red-400 text-sm mt-3">{scanError}</p>}
          {findings.length > 0 && (
            <div className="mt-4 bg-slate-800/40 rounded-xl p-3">
              <p className="text-xs font-semibold text-slate-400 uppercase mb-2">Scan Findings</p>
              <ul className="space-y-1">
                {findings.map((f, i) => <li key={i} className="text-xs text-slate-300">• {f}</li>)}
              </ul>
            </div>
          )}
        </div>

        {/* ── DRIFT FEED + DETAIL PANEL ── */}
        <div>
          {/* filter bar */}
          <div className="flex flex-wrap gap-2 mb-3">
            <div className="flex gap-1 border border-slate-800 rounded-xl p-1 bg-slate-900">
              {SEVERITY_FILTERS.map(f => (
                <button key={f.value} onClick={() => setSeverityFilter(f.value)}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors ${severityFilter === f.value ? "bg-slate-700 text-white" : "text-slate-500 hover:text-slate-300"}`}>
                  {f.label}
                </button>
              ))}
            </div>
            <div className="flex gap-1 border border-slate-800 rounded-xl p-1 bg-slate-900">
              {(["all","open","approved","dismissed","rolled_back"] as (DriftStatus|"all")[]).map(s => (
                <button key={s} onClick={() => setStatusFilter(s)}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold capitalize transition-colors ${statusFilter === s ? "bg-slate-700 text-white" : "text-slate-500 hover:text-slate-300"}`}>
                  {s.replace(/_/g," ")}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-5 gap-5">
            {/* drift list */}
            <div className="xl:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                <p className="text-sm font-bold text-slate-100">Drift Records</p>
                <span className="text-xs text-slate-500">{filtered.length} results</span>
              </div>
              <div className="overflow-y-auto max-h-[600px]">
                {filtered.length === 0
                  ? <p className="text-xs text-slate-500 text-center py-12">{drifts.length === 0 ? "No drift detected yet — run a scan above." : "No records match the current filter."}</p>
                  : filtered.map(d => (
                    <button key={d.id} onClick={() => setSelected(d)} className={`w-full text-left px-4 py-3 border-b border-slate-800/50 hover:bg-slate-800/60 transition-colors ${selected?.id === d.id ? "bg-slate-800 border-l-2 border-l-cyan-500" : ""}`}>
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="font-semibold text-slate-100 text-sm truncate">{hostnameFor(d.device_id)}</p>
                          <p className="text-[11px] text-slate-500 mt-0.5">{d.baseline.replace(/_/g," ")} · {new Date(d.detected_at).toLocaleDateString()}</p>
                        </div>
                        <div className="flex flex-col items-end gap-1 shrink-0">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${SEV_PILL[d.severity]}`}>{d.severity}</span>
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${STATUS_PILL[d.status]}`}>{d.status.replace(/_/g," ")}</span>
                        </div>
                      </div>
                      <div className="mt-2 flex gap-3 text-[11px] text-slate-500">
                        <span>+{d.added_lines} / -{d.removed_lines} lines</span>
                        <span>score: {d.compliance_score}/100</span>
                        {d.maintenance_window_id && <span className="text-slate-600">maintenance</span>}
                      </div>
                    </button>
                  ))}
              </div>
            </div>

            {/* detail panel */}
            <div className="xl:col-span-3 bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden flex flex-col">
              {!selected
                ? (
                  <div className="flex flex-col items-center justify-center h-full py-20 text-center px-6">
                    <div className="text-5xl mb-4 opacity-30">📄</div>
                    <p className="text-slate-400 text-sm">Select a drift record to view the full config diff, risk assessment, and remediation actions.</p>
                  </div>
                )
                : detailLoading || !detail
                  ? <div className="flex items-center justify-center h-64"><div className="w-8 h-8 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" /></div>
                  : (
                    <div className="flex flex-col gap-0 overflow-y-auto">
                      {/* device header */}
                      <div className="px-5 py-4 border-b border-slate-800 bg-slate-800/40">
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <p className="font-black text-slate-100 text-lg">{hostnameFor(detail.device_id)}</p>
                            <p className="text-xs text-slate-400 mt-0.5">
                              Baseline: <span className="text-slate-300">{detail.baseline.replace(/_/g," ")}</span>
                              {" · "}Detected: <span className="text-slate-300">{new Date(detail.detected_at).toLocaleString()}</span>
                            </p>
                          </div>
                          <span className={`px-3 py-1 rounded-full text-xs font-bold capitalize ${SEV_PILL[detail.severity]}`}>{detail.severity}</span>
                        </div>
                      </div>

                      {/* metrics row */}
                      <div className="grid grid-cols-3 gap-px bg-slate-800 border-b border-slate-800">
                        {[
                          { label: "Compliance", value: `${detail.compliance_score}/100`, color: detail.compliance_score >= 80 ? "text-emerald-400" : detail.compliance_score >= 60 ? "text-amber-400" : "text-red-400" },
                          { label: "Risk Score", value: detail.risk_score, color: detail.risk_score >= 70 ? "text-red-400" : detail.risk_score >= 40 ? "text-amber-400" : "text-emerald-400" },
                          { label: "Lines Changed", value: `+${detail.added_lines}/-${detail.removed_lines}`, color: "text-slate-300" },
                        ].map(m => (
                          <div key={m.label} className="bg-slate-900 px-4 py-3 text-center">
                            <p className={`text-xl font-black ${m.color}`}>{m.value}</p>
                            <p className="text-[10px] text-slate-500 uppercase mt-0.5">{m.label}</p>
                          </div>
                        ))}
                      </div>

                      <div className="p-5 space-y-4">
                        {/* AI summary */}
                        {detail.ai_summary && (
                          <div className="bg-blue-950/30 border border-blue-800/40 rounded-xl p-4">
                            <p className="text-[11px] font-bold text-blue-400 uppercase tracking-wider mb-1">🤖 AI Analysis</p>
                            <p className="text-sm text-slate-200">{detail.ai_summary}</p>
                          </div>
                        )}

                        {/* rollback recommendation */}
                        {recommendation && (
                          <div className={`rounded-xl p-4 border ${recommendation.recommended ? "bg-red-950/30 border-red-800/40" : "bg-emerald-950/30 border-emerald-800/40"}`}>
                            <p className={`text-[11px] font-bold uppercase tracking-wider mb-1 ${recommendation.recommended ? "text-red-400" : "text-emerald-400"}`}>
                              {recommendation.recommended ? "⚠ Rollback Recommended" : "✓ No Rollback Needed"}
                            </p>
                            <p className="text-xs text-slate-300">{recommendation.reason}</p>
                            {recommendation.recommended && (detail.baseline === "golden_config" || detail.baseline === "role_baseline") && canReview && detail.status === "open" && (
                              <button onClick={remediate} disabled={remediating}
                                className="mt-3 bg-red-600 hover:bg-red-500 text-white text-xs font-bold uppercase tracking-wider px-4 py-2 rounded-lg disabled:opacity-50 transition-colors">
                                {remediating ? "Submitting…" : `⚡ Push ${detail.baseline === "golden_config" ? "Golden Config" : "Role Baseline"} to Fix`}
                              </button>
                            )}
                            {remediationNotice && <p className="mt-2 text-emerald-400 text-xs font-medium">{remediationNotice}</p>}
                            {remediationError && <p className="mt-2 text-red-400 text-xs">{remediationError}</p>}
                          </div>
                        )}

                        {/* CLI diff */}
                        {detail.cli_diff && (
                          <div>
                            <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2">📟 CLI Commands (What Changed)</p>
                            <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono overflow-x-auto leading-relaxed max-h-48">
                              {detail.cli_diff.split("\n").map((line, i) => {
                                let cls = "text-slate-300";
                                if (line.startsWith("interface ") || line.startsWith("router ")) cls = "text-indigo-400 font-semibold";
                                else if (line.trimStart().startsWith("no ")) cls = "text-red-400";
                                else if (line.startsWith("  ")) cls = "text-emerald-400";
                                return <span key={i} className={`block ${cls}`}>{line || " "}</span>;
                              })}
                            </pre>
                          </div>
                        )}

                        {/* raw diff */}
                        <details>
                          <summary className="text-[11px] font-bold text-slate-500 uppercase tracking-wider cursor-pointer hover:text-cyan-400 select-none mb-2">
                            📄 {detail.cli_diff ? "Raw Unified Diff ▸" : "Configuration Diff ▸"}
                          </summary>
                          <DiffViewer diffText={detail.diff_text} />
                        </details>

                        {/* action buttons */}
                        {detail.status === "open" && (
                          canReview
                            ? (
                              <div className="flex gap-2 pt-2">
                                <button onClick={() => review("approved")} disabled={reviewing}
                                  className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold px-4 py-2 rounded-xl disabled:opacity-50 transition-colors">
                                  ✓ Approve as New Baseline
                                </button>
                                <button onClick={() => review("dismissed")} disabled={reviewing}
                                  className="bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm font-bold px-4 py-2 rounded-xl disabled:opacity-50 transition-colors">
                                  Dismiss
                                </button>
                              </div>
                            )
                            : <p className="text-xs text-slate-500 italic pt-2">Only a Network Administrator can approve or dismiss drift.</p>
                        )}
                      </div>
                    </div>
                  )}
            </div>
          </div>
        </div>

        {/* ── COMPLIANCE ROLE BASELINES ── */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
            <div>
              <p className="text-sm font-bold text-slate-100">Compliance Baselines by Role</p>
              <p className="text-xs text-slate-500 mt-0.5">Shared golden-config templates per device_role — scan with "Role Baseline" above to compare against these.</p>
            </div>
            {canReview && (
              <button onClick={() => startEditRole("")}
                className="text-xs font-bold uppercase tracking-wider text-cyan-400 border border-cyan-800/60 bg-cyan-950/30 px-3 py-1.5 rounded-xl hover:bg-cyan-950/60">
                + Add Baseline
              </button>
            )}
          </div>

          {editingRole && (
            <form onSubmit={saveRoleBaseline} className="mb-4 border border-slate-700 rounded-xl p-4 bg-slate-800/40 flex flex-col gap-3">
              <div className="flex flex-wrap gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Device Role</label>
                  {editingRole === "__new__"
                    ? <input list="roles-in-use" className="bg-slate-800 border border-slate-700 text-slate-100 text-sm rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500" placeholder="e.g. core, access, edge-firewall" value={roleForm.device_role} onChange={e => setRoleForm({ ...roleForm, device_role: e.target.value })} required />
                    : <input className="bg-slate-800 border border-slate-700 text-slate-100 text-sm rounded-xl px-3 py-2 opacity-70" value={roleForm.device_role} disabled />}
                  <datalist id="roles-in-use">{rolesInUse.map(r => <option key={r} value={r} />)}</datalist>
                </div>
                <div className="flex-1 min-w-[220px]">
                  <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Description (optional)</label>
                  <input className="w-full bg-slate-800 border border-slate-700 text-slate-100 text-sm rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500" placeholder="e.g. Standard core switch baseline" value={roleForm.description} onChange={e => setRoleForm({ ...roleForm, description: e.target.value })} />
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Baseline Config</label>
                <textarea className="w-full bg-slate-800 border border-slate-700 text-slate-100 text-sm rounded-xl px-3 py-2 font-mono h-36 focus:outline-none focus:ring-2 focus:ring-cyan-500" placeholder="Paste the approved config template for this role…" value={roleForm.config} onChange={e => setRoleForm({ ...roleForm, config: e.target.value })} required />
              </div>
              {roleFormError && <p className="text-red-400 text-sm">{roleFormError}</p>}
              <div className="flex gap-2">
                <button type="submit" disabled={roleFormSaving} className="bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-bold px-4 py-2 rounded-xl disabled:opacity-50 transition-colors">
                  {roleFormSaving ? "Saving…" : "Save Baseline"}
                </button>
                <button type="button" onClick={() => setEditingRole(null)} className="bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm font-bold px-4 py-2 rounded-xl transition-colors">
                  Cancel
                </button>
              </div>
            </form>
          )}

          {baselinesLoading
            ? <p className="text-xs text-slate-500">Loading…</p>
            : roleBaselines.length === 0
              ? <p className="text-xs text-slate-500 italic">No role baselines set yet. Add one above.</p>
              : (
                <div className="divide-y divide-slate-800">
                  {roleBaselines.map(b => (
                    <div key={b.device_role} className="py-3 flex items-center justify-between gap-3 flex-wrap">
                      <div>
                        <span className="text-sm font-bold text-slate-100">{b.device_role}</span>
                        <span className="ml-2 text-xs text-slate-500">{b.device_count} device(s) · checksum {b.checksum.slice(0, 10)}</span>
                        {b.description && <p className="text-xs text-slate-500 mt-0.5">{b.description}</p>}
                      </div>
                      {canReview && (
                        <div className="flex gap-2 shrink-0">
                          <button onClick={() => startEditRole(b.device_role)} className="text-xs font-bold uppercase tracking-wider text-slate-400 border border-slate-700 px-2.5 py-1 rounded-lg hover:bg-slate-800 transition-colors">Edit</button>
                          <button onClick={() => deleteRoleBaseline(b.device_role)} className="text-xs font-bold uppercase tracking-wider text-red-400 border border-red-800/60 px-2.5 py-1 rounded-lg hover:bg-red-950/40 transition-colors">Delete</button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
        </div>
      </div>
    </div>
  );
}