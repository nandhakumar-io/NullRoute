import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { BulkApproveResponse, ComplianceBaselineDetail, ComplianceBaselineSummary, Device, Drift, DriftBaseline, DriftFleetSummary, DriftScanResponse, DriftSeverity, DriftStatus, DriftTrendResponse, FlappingDevicesResponse, LowRiskDriftCandidate, WeeklyGoldenDriftReport } from "../lib/types";
import ConfigDiff from "../components/ConfigDiff";
import { ImpactClassificationBadge } from "../components/ImpactClassificationBadge";
import StatCard from "../components/StatCard";
import { useAuth } from "../context/AuthContext";
import { useToast, errorMessage } from "../lib/toast";
import { useConfirm } from "../lib/confirm";
import { PageHeader, Loading } from "../components/ui";

const severityStyle: Record<DriftSeverity, string> = {
  low: "bg-emerald-950/40 text-emerald-400",
  medium: "bg-amber-950/40 text-amber-400",
  high: "bg-orange-950/50 text-orange-400",
  critical: "bg-red-950/40 text-red-400",
};

const statusStyle: Record<DriftStatus, string> = {
  open: "bg-amber-950/60 text-amber-300",
  approved: "bg-blue-950/60 text-blue-300",
  rolled_back: "bg-purple-950/60 text-purple-300",
  dismissed: "bg-slate-800 text-slate-400",
};

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

  const [summary, setSummary] = useState<DriftFleetSummary | null>(null);
  const [drifts, setDrifts] = useState<Drift[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<Drift | null>(null);
  const [detail, setDetail] = useState<DriftScanResponse["drift"] | null>(null);
  const [findings, setFindings] = useState<string[]>([]);
  const [recommendation, setRecommendation] = useState<{ recommended: boolean; reason: string } | null>(null);

  const [initialLoading, setInitialLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<DriftSeverity | "all">("all");

  const [scanDeviceId, setScanDeviceId] = useState("");
  const [scanBaseline, setScanBaseline] = useState<DriftBaseline>("previous_backup");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const [reviewing, setReviewing] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [remediating, setRemediating] = useState(false);
  const [remediationError, setRemediationError] = useState<string | null>(null);
  const [remediationNotice, setRemediationNotice] = useState<string | null>(null);

  // "Who's drifted from golden config this week" one-click report -- a
  // deduplicated (one row per device) view scoped to a time window,
  // distinct from the raw per-scan `drifts` feed above.
  const [weeklyReport, setWeeklyReport] = useState<WeeklyGoldenDriftReport | null>(null);
  const [weeklyLoading, setWeeklyLoading] = useState(false);
  const [weeklyError, setWeeklyError] = useState<string | null>(null);
  const [weeklyOpen, setWeeklyOpen] = useState(false);

  // "Bulk-approve low-risk drift" -- one-click approval for OPEN, LOW
  // severity drift where every changed line is a cosmetic
  // description/remark edit (see drift_service.is_low_risk_bulk_approvable).
  const [lowRiskCandidates, setLowRiskCandidates] = useState<LowRiskDriftCandidate[] | null>(null);
  const [lowRiskLoading, setLowRiskLoading] = useState(false);
  const [lowRiskError, setLowRiskError] = useState<string | null>(null);
  const [lowRiskOpen, setLowRiskOpen] = useState(false);
  const [lowRiskSelected, setLowRiskSelected] = useState<Set<string>>(new Set());
  const [bulkApproving, setBulkApproving] = useState(false);
  const [bulkApproveNotice, setBulkApproveNotice] = useState<string | null>(null);

  const loadLowRiskCandidates = () => {
    setLowRiskOpen(true);
    setLowRiskLoading(true);
    setLowRiskError(null);
    setBulkApproveNotice(null);
    api
      .get<LowRiskDriftCandidate[]>("/drift/low-risk-candidates")
      .then((res) => {
        setLowRiskCandidates(res.data);
        setLowRiskSelected(new Set(res.data.map((d) => d.id)));
      })
      .catch((err) => setLowRiskError(errorMessage(err, "Failed to load low-risk drift candidates.")))
      .finally(() => setLowRiskLoading(false));
  };

  const toggleLowRiskSelected = (id: string) => {
    setLowRiskSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const runBulkApprove = async () => {
    if (lowRiskSelected.size === 0) return;
    setBulkApproving(true);
    setLowRiskError(null);
    try {
      const res = await api.post<BulkApproveResponse>("/api/v1/drift/bulk-approve", {
        drift_ids: Array.from(lowRiskSelected),
      });
      setBulkApproveNotice(`Approved ${res.data.approved_count} low-risk drift record(s).`);
      setLowRiskCandidates((prev) => (prev ? prev.filter((d) => !res.data.approved_ids.includes(d.id)) : prev));
      setLowRiskSelected(new Set());
      load();
    } catch (err) {
      setLowRiskError(errorMessage(err, "Bulk approve failed."));
    } finally {
      setBulkApproving(false);
    }
  };

  // Drift trending / flapping-device detection.
  const [trend, setTrend] = useState<DriftTrendResponse | null>(null);
  const [flapping, setFlapping] = useState<FlappingDevicesResponse | null>(null);

  const runWeeklyReport = () => {
    setWeeklyOpen(true);
    setWeeklyLoading(true);
    setWeeklyError(null);
    api
      .get<WeeklyGoldenDriftReport>("/drift/report/weekly-golden-config", { params: { days: 7 } })
      .then((res) => setWeeklyReport(res.data))
      .catch((err) => setWeeklyError(err?.response?.data?.detail || "Failed to load weekly drift report."))
      .finally(() => setWeeklyLoading(false));
  };


  // Compliance Baselines by role -- shared golden-config-style template
  // per device_role (core/access/edge/...) rather than one-per-device, so
  // scanning with baseline="role_baseline" above has something to compare
  // against. See DriftBaseline.ROLE_BASELINE / ComplianceBaseline.
  const [roleBaselines, setRoleBaselines] = useState<ComplianceBaselineSummary[]>([]);
  const [rolesInUse, setRolesInUse] = useState<string[]>([]);
  const [baselinesLoading, setBaselinesLoading] = useState(false);
  const [editingRole, setEditingRole] = useState<string | null>(null);
  const [roleForm, setRoleForm] = useState({ device_role: "", config: "", description: "" });
  const [roleFormSaving, setRoleFormSaving] = useState(false);
  const [roleFormError, setRoleFormError] = useState<string | null>(null);

  const loadRoleBaselines = () => {
    setBaselinesLoading(true);
    Promise.all([
      api.get<ComplianceBaselineSummary[]>("/api/v1/compliance-baselines"),
      api.get<string[]>("/api/v1/compliance-baselines/device-roles"),
    ])
      .then(([baselinesRes, rolesRes]) => {
        setRoleBaselines(baselinesRes.data);
        setRolesInUse(rolesRes.data);
      })
      .finally(() => setBaselinesLoading(false));
  };

  useEffect(loadRoleBaselines, []);

  const startEditRole = async (role: string) => {
    setRoleFormError(null);
    if (role) {
      try {
        const res = await api.get<ComplianceBaselineDetail>(`/api/v1/compliance-baselines/${encodeURIComponent(role)}`);
        setRoleForm({ device_role: role, config: res.data.config, description: res.data.description || "" });
      } catch {
        setRoleForm({ device_role: role, config: "", description: "" });
      }
    } else {
      setRoleForm({ device_role: "", config: "", description: "" });
    }
    setEditingRole(role || "__new__");
  };

  const saveRoleBaseline = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!roleForm.device_role.trim() || !roleForm.config.trim()) return;
    setRoleFormSaving(true);
    setRoleFormError(null);
    try {
      await api.put(`/api/v1/compliance-baselines/${encodeURIComponent(roleForm.device_role.trim())}`, {
        config: roleForm.config,
        description: roleForm.description || null,
      });
      setEditingRole(null);
      loadRoleBaselines();
    } catch (err: any) {
      setRoleFormError(err?.response?.data?.detail || "Failed to save compliance baseline.");
    } finally {
      setRoleFormSaving(false);
    }
  };

  const deleteRoleBaseline = async (role: string) => {
    if (!(await confirm(`Delete the compliance baseline for role "${role}"? Devices with this role will fall back to golden config / previous backup for drift scans.`, { confirmLabel: "Delete" }))) return;
    try {
      await api.delete(`/api/v1/compliance-baselines/${encodeURIComponent(role)}`);
      loadRoleBaselines();
      toast.success(`Baseline for "${role}" deleted.`);
    } catch (err) {
      toast.error(errorMessage(err, "Failed to delete compliance baseline."));
    }
  };

  const load = () => {
    Promise.all([
      api.get<DriftFleetSummary>("/api/v1/drift/summary"),
      api.get<Drift[]>("/api/v1/drift"),
      api.get<{ items: Device[] } | Device[]>("/api/devices", { params: { limit: 500 } }),
      api.get<DriftTrendResponse>("/api/v1/drift/trends", { params: { days: 90, bucket_days: 7 } }),
      api.get<FlappingDevicesResponse>("/api/v1/drift/flapping", { params: { days: 30, min_events: 3 } }),
    ])
      .then(([summaryRes, driftRes, devRes, trendRes, flappingRes]) => {
        setSummary(summaryRes.data);
        setDrifts(driftRes.data);
        const deviceItems = (devRes.data as any).items ?? devRes.data;
        setDevices(Array.isArray(deviceItems) ? deviceItems : []);
        setTrend(trendRes.data);
        setFlapping(flappingRes.data);
      })
      .finally(() => setInitialLoading(false));
  };

  useEffect(load, []);

  useEffect(() => {
    if (!selected) {
      setDetail(null);
      setFindings([]);
      setRecommendation(null);
      return;
    }
    setDetailLoading(true);
    setRemediationError(null);
    setRemediationNotice(null);
    Promise.all([
      api.get(`/api/v1/drift/${selected.id}`),
      api.get(`/api/v1/drift/${selected.id}/rollback-recommendation`),
    ])
      .then(([detailRes, recRes]) => {
        setDetail(detailRes.data);
        setRecommendation(recRes.data);
        setFindings([]);
      })
      .finally(() => setDetailLoading(false));
  }, [selected?.id]);

  const hostnameFor = (deviceId: string) => devices.find((d) => d.id === deviceId)?.hostname || deviceId.slice(0, 8);

  const filtered = useMemo(
    () => (severityFilter === "all" ? drifts : drifts.filter((d) => d.severity === severityFilter)),
    [drifts, severityFilter]
  );

  const runScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanDeviceId) return;
    setScanning(true);
    setScanError(null);
    try {
      const res = await api.post<DriftScanResponse>(`/api/v1/devices/${scanDeviceId}/drift/scan`, {
        baseline: scanBaseline,
      });
      setFindings(res.data.findings);
      load();
      const newDrift = res.data.drift;
      setSelected(newDrift);
      setDetail(newDrift);
      setRecommendation(res.data.rollback_recommendation);
    } catch (err: any) {
      setScanError(err?.response?.data?.detail || "Drift scan failed.");
    } finally {
      setScanning(false);
    }
  };

  const review = async (status: DriftStatus) => {
    if (!selected) return;
    setReviewing(true);
    setReviewError(null);
    try {
      await api.patch(`/api/v1/drift/${selected.id}`, { status });
      load();
      setSelected((prev) => (prev ? { ...prev, status } : prev));
      setDetail((prev) => (prev ? { ...prev, status } : prev));
    } catch (err: any) {
      setReviewError(err?.response?.data?.detail || "Failed to update drift status.");
    } finally {
      setReviewing(false);
    }
  };

  if (initialLoading) return <Loading />;

  return (
    <div>
      <PageHeader
        title="Configuration Drift"
        subtitle="Detects when a device's live configuration has diverged from its golden config or last known-good backup — scanned nightly, or on demand below."
      />

      <div className="px-8 pb-8 space-y-6">
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Open Drifts" value={summary.total_open_drifts} indigo-500="amber" />
          <StatCard label="Devices Drifted" value={summary.devices_drifted} indigo-500="red" />
          <StatCard label="Avg. Compliance Score" value={`${summary.average_compliance_score}/100`} indigo-500="blue" />
          <StatCard label="Rollback Recommended" value={summary.rollback_recommended_count} indigo-500="red" />
        </div>
      )}

      {/* Drift trend + flapping devices */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 card">
          <h2 className="text-sm font-bold text-slate-100">Drift Trend (last {trend?.days ?? 90} days)</h2>
          <p className="text-xs text-slate-500 mt-1 mb-4">
            Fleet-wide drift detections per {trend?.bucket_days ?? 7}-day bucket — a rising trend means devices are drifting more often, not just that more scans ran.
          </p>
          {!trend || trend.points.length === 0 ? (
            <p className="text-xs text-slate-400 py-8 text-center">No drift activity in this window.</p>
          ) : (
            (() => {
              const max = Math.max(1, ...trend.points.map((p) => p.total));
              return (
                <div className="flex items-end gap-1.5 h-40">
                  {trend.points.map((p) => (
                    <div key={p.bucket_start} className="flex-1 flex flex-col items-center justify-end h-full group relative">
                      <div className="w-full flex flex-col justify-end h-full rounded-t overflow-hidden bg-slate-800" style={{ height: "100%" }}>
                        <div
                          className="w-full bg-red-500"
                          style={{ height: `${(p.critical / max) * 100}%` }}
                          title={`${p.critical} critical`}
                        />
                        <div
                          className="w-full bg-orange-400"
                          style={{ height: `${(p.high / max) * 100}%` }}
                          title={`${p.high} high`}
                        />
                        <div
                          className="w-full bg-cyan-600"
                          style={{ height: `${((p.total - p.critical - p.high) / max) * 100}%` }}
                          title={`${p.total - p.critical - p.high} other`}
                        />
                      </div>
                      <div className="absolute -top-6 opacity-0 group-hover:opacity-100 transition-opacity text-[10px] font-bold bg-slate-800 text-white px-1.5 py-0.5 rounded whitespace-nowrap">
                        {p.total} on {new Date(p.bucket_start).toLocaleDateString()}
                      </div>
                      <span className="text-[9px] text-slate-400 mt-1 rotate-0">{new Date(p.bucket_start).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>
                    </div>
                  ))}
                </div>
              );
            })()
          )}
        </div>

        <div className="card">
          <h2 className="text-sm font-bold text-slate-100">Flapping Devices</h2>
          <p className="text-xs text-slate-500 mt-1 mb-3">
            {flapping ? `≥${flapping.min_events} drift events in the last ${flapping.days} days` : "Devices drifting repeatedly"} — a sign of unmanaged hand-edits, not a one-off change.
          </p>
          {!flapping || flapping.devices.length === 0 ? (
            <p className="text-xs text-slate-400 py-6 text-center">No repeatedly-drifting devices right now.</p>
          ) : (
            <ul className="space-y-2">
              {flapping.devices.map((d) => (
                <li key={d.device_id} className="flex items-center justify-between text-xs border-b border-soc-border/60 pb-2 last:border-0 last:pb-0">
                  <div>
                    <p className="font-semibold text-slate-100">{d.hostname}</p>
                    <p className="text-slate-400">last drift {new Date(d.last_detected_at).toLocaleDateString()}</p>
                  </div>
                  <div className="text-right">
                    <span className={`inline-block px-2 py-0.5 rounded-full font-bold ${severityStyle[d.max_severity]}`}>{d.event_count}x</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="mt-6 card">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100">Drifted From Golden Config This Week</h2>
            <p className="text-xs text-slate-500 mt-1">
              One-click fleet view: every device whose live config has diverged from its golden config in the
              last 7 days, one row per device (not one row per scan).
            </p>
          </div>
          <button
            onClick={runWeeklyReport}
            disabled={weeklyLoading}
            className="text-xs font-bold uppercase tracking-wider text-white bg-cyan-600 hover:bg-cyan-500 px-4 py-2 rounded-lg shadow-sm disabled:opacity-50 shrink-0"
          >
            {weeklyLoading ? "Loading…" : "Show This Week's Drift"}
          </button>
        </div>

        {weeklyOpen && (
          <div className="mt-4">
            {weeklyLoading ? (
              <p className="text-xs text-slate-400">Loading…</p>
            ) : weeklyError ? (
              <p className="text-xs text-red-400">{weeklyError}</p>
            ) : weeklyReport && weeklyReport.devices.length === 0 ? (
              <p className="text-xs text-slate-400 italic">
                No device has drifted from its golden config in the last {weeklyReport.days} days.
              </p>
            ) : weeklyReport ? (
              <div className="overflow-x-auto border border-soc-border rounded-lg">
                <table className="w-full text-sm min-w-[560px]">
                  <thead className="bg-slate-800/40">
                    <tr>
                      <th className="text-left px-4 py-2 font-semibold text-slate-500 text-xs uppercase">Device</th>
                      <th className="text-left px-4 py-2 font-semibold text-slate-500 text-xs uppercase">Severity</th>
                      <th className="text-left px-4 py-2 font-semibold text-slate-500 text-xs uppercase">Compliance</th>
                      <th className="text-left px-4 py-2 font-semibold text-slate-500 text-xs uppercase">Lines Changed</th>
                      <th className="text-left px-4 py-2 font-semibold text-slate-500 text-xs uppercase">Detected</th>
                      <th className="text-left px-4 py-2 font-semibold text-slate-500 text-xs uppercase">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-soc-border/60">
                    {weeklyReport.devices.map((d, i) => (
                      <tr
                        key={d.id}
                        onClick={() => setSelected(d)}
                        className={`cursor-pointer hover:bg-slate-800/60 ${i % 2 ? "bg-slate-800/40" : "bg-soc-panel"}`}
                      >
                        <td className="px-4 py-2.5 font-medium text-slate-100">{d.hostname}</td>
                        <td className="px-4 py-2.5">
                          <span className={`px-2 py-1 rounded-full text-xs font-semibold capitalize ${severityStyle[d.severity]}`}>
                            {d.severity}
                          </span>
                        </td>
                        <td className="px-4 py-2.5">{d.compliance_score}/100</td>
                        <td className="px-4 py-2.5 font-mono text-xs">
                          +{d.added_lines}/-{d.removed_lines}
                        </td>
                        <td className="px-4 py-2.5 text-slate-500 text-xs">{new Date(d.detected_at).toLocaleString()}</td>
                        <td className="px-4 py-2.5">
                          <span className={`px-2 py-1 rounded-full text-xs font-semibold capitalize ${statusStyle[d.status]}`}>
                            {d.status.replace(/_/g, " ")}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="text-[11px] text-slate-400 px-4 py-2 bg-slate-800/40 border-t border-soc-border">
                  Click a row to open that drift's full detail below.
                </p>
              </div>
            ) : null}
          </div>
        )}
      </div>

      <form onSubmit={runScan} className="mt-6 card flex flex-wrap items-end gap-3">
        <div>
          <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Device</label>
          <select
            className="input min-w-[220px]"
            value={scanDeviceId}
            onChange={(e) => setScanDeviceId(e.target.value)}
            required
          >
            <option value="">Select device…</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.hostname} ({d.ip_address})
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Baseline</label>
          <select
            className="input"
            value={scanBaseline}
            onChange={(e) => setScanBaseline(e.target.value as DriftBaseline)}
          >
            <option value="previous_backup">Previous backup</option>
            <option value="golden_config">Golden config</option>
            <option value="role_baseline">Role baseline (by device_role)</option>
          </select>
        </div>
        <button
          type="submit"
          disabled={scanning || !devices.length}
          className="bg-cyan-600 text-white rounded-lg px-4 py-2 text-sm font-semibold hover:bg-cyan-500 transition-colors disabled:opacity-50"
        >
          {scanning ? "Scanning…" : "Run Drift Scan"}
        </button>
        {scanError && <p className="text-red-400 text-sm w-full">{scanError}</p>}
      </form>

      <div className="mt-6 card">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h2 className="text-sm font-bold text-slate-100">Compliance Baselines by Role</h2>
            <p className="text-xs text-slate-500 mt-1">
              One shared baseline template per device_role (e.g. "core", "access") -- so a core switch and an
              access switch are judged against different expected configs instead of sharing one golden config,
              or having no baseline at all. Set a device's role via Devices → Edit, then scan with
              baseline "Role baseline" above.
            </p>
          </div>
          {canReview && (
            <button
              onClick={() => startEditRole("")}
              className="text-xs font-bold uppercase tracking-wider text-cyan-400 border border-cyan-800/60 bg-cyan-950/30 px-3 py-1.5 rounded-lg hover:bg-cyan-950/60 shrink-0"
            >
              + Add Baseline
            </button>
          )}
        </div>

        {editingRole && (
          <form onSubmit={saveRoleBaseline} className="mt-4 border border-soc-border rounded-lg p-4 bg-slate-800/40 flex flex-col gap-3">
            <div className="flex flex-wrap gap-3">
              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Device Role</label>
                {editingRole === "__new__" ? (
                  <input
                    list="roles-in-use"
                    className="input"
                    placeholder="e.g. core, access, edge-firewall"
                    value={roleForm.device_role}
                    onChange={(e) => setRoleForm({ ...roleForm, device_role: e.target.value })}
                    required
                  />
                ) : (
                  <input className="input" value={roleForm.device_role} disabled />
                )}
                <datalist id="roles-in-use">
                  {rolesInUse.map((r) => (
                    <option key={r} value={r} />
                  ))}
                </datalist>
              </div>
              <div className="flex-1 min-w-[220px]">
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Description (optional)</label>
                <input
                  className="w-full input"
                  placeholder="e.g. Standard core switch baseline (BGP + OSPF uplinks)"
                  value={roleForm.description}
                  onChange={(e) => setRoleForm({ ...roleForm, description: e.target.value })}
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Baseline Config</label>
              <textarea
                className="w-full input font-mono h-40"
                placeholder="Paste the approved config template for this role..."
                value={roleForm.config}
                onChange={(e) => setRoleForm({ ...roleForm, config: e.target.value })}
                required
              />
            </div>
            {roleFormError && <p className="text-red-400 text-sm">{roleFormError}</p>}
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={roleFormSaving}
                className="bg-cyan-600 text-white rounded-lg px-4 py-2 text-sm font-semibold hover:bg-cyan-500 transition-colors disabled:opacity-50"
              >
                {roleFormSaving ? "Saving…" : "Save Baseline"}
              </button>
              <button
                type="button"
                onClick={() => setEditingRole(null)}
                className="btn-secondary"
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        {baselinesLoading ? (
          <p className="text-xs text-slate-400 mt-4">Loading…</p>
        ) : roleBaselines.length === 0 ? (
          <p className="text-xs text-slate-400 italic mt-4">No role baselines set yet.</p>
        ) : (
          <div className="mt-4 divide-y divide-soc-border/60">
            {roleBaselines.map((b) => (
              <div key={b.device_role} className="py-3 flex items-center justify-between gap-3 flex-wrap">
                <div>
                  <span className="text-sm font-bold text-slate-100">{b.device_role}</span>
                  <span className="ml-2 text-xs text-slate-400">
                    {b.device_count} device{b.device_count === 1 ? "" : "s"} · checksum {b.checksum.slice(0, 10)}
                  </span>
                  {b.description && <p className="text-xs text-slate-500 mt-0.5">{b.description}</p>}
                </div>
                {canReview && (
                  <div className="flex gap-2 shrink-0">
                    <button
                      onClick={() => startEditRole(b.device_role)}
                      className="text-xs font-bold uppercase tracking-wider text-slate-400 border border-soc-border bg-soc-panel px-2.5 py-1 rounded-lg hover:bg-slate-800"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => deleteRoleBaseline(b.device_role)}
                      className="text-xs font-bold uppercase tracking-wider text-red-400 border border-red-800/60 bg-soc-panel px-2.5 py-1 rounded-lg hover:bg-red-950/40"
                    >
                      Delete
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mt-6 mb-3">
        {SEVERITY_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setSeverityFilter(f.value)}
            className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-colors ${
              severityFilter === f.value
                ? "bg-slate-800 text-white border-slate-700"
                : "bg-soc-panel text-slate-500 border-soc-border hover:border-slate-600"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-soc-panel border border-soc-border rounded-xl overflow-x-auto self-start">
          <table className="w-full text-sm min-w-[560px]">
            <thead className="bg-slate-800 text-white">
              <tr>
                <th className="text-left px-4 py-3 font-semibold">Device</th>
                <th className="text-left px-4 py-3 font-semibold">Severity</th>
                <th className="text-left px-4 py-3 font-semibold">Compliance</th>
                <th className="text-left px-4 py-3 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {initialLoading && (
                <tr>
                  <td colSpan={4} className="text-center text-slate-400 py-8">
                    Loading…
                  </td>
                </tr>
              )}
              {!initialLoading && filtered.length === 0 && (
                <tr>
                  <td colSpan={4} className="text-center text-slate-400 py-8">
                    {drifts.length === 0 ? "No drift detected yet. Run a scan above." : "No drifts match this filter."}
                  </td>
                </tr>
              )}
              {filtered.map((d, i) => (
                <tr
                  key={d.id}
                  onClick={() => setSelected(d)}
                  className={`cursor-pointer hover:bg-slate-800/60 ${i % 2 ? "bg-slate-800/40" : "bg-soc-panel"} ${
                    selected?.id === d.id ? "ring-2 ring-inset ring-cyan-500" : ""
                  }`}
                >
                  <td className="px-4 py-3 font-medium text-slate-100">{hostnameFor(d.device_id)}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold capitalize ${severityStyle[d.severity]}`}>
                      {d.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">{d.compliance_score}/100</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold capitalize ${statusStyle[d.status]}`}>
                      {d.status.replace(/_/g, " ")}
                    </span>
                    {d.maintenance_window_id && (
                      <span
                        title="Device was in an active maintenance window when this was detected"
                        className="ml-1 px-2 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-500"
                      >
                        Expected — maintenance
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          {!selected ? (
            <p className="text-sm text-slate-400 italic">Select a drift record to view details.</p>
          ) : detailLoading || !detail ? (
            <p className="text-sm text-slate-400 italic">Loading…</p>
          ) : (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="font-semibold text-slate-100">{hostnameFor(detail.device_id)}</h3>
                  <p className="text-xs text-slate-500 mt-1">
                    Baseline: {detail.baseline.replace(/_/g, " ")} · Detected{" "}
                    {new Date(detail.detected_at).toLocaleString()}
                  </p>
                </div>
                <div className="shrink-0 flex flex-col items-end gap-1">
                  <span className={`px-2 py-1 rounded-full text-xs font-semibold capitalize ${severityStyle[detail.severity]}`}>
                    {detail.severity}
                  </span>
                  {detail.maintenance_window_id && (
                    <span className="px-2 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-500 whitespace-nowrap">
                      Expected — maintenance
                    </span>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="bg-slate-800/40 rounded-lg p-2">
                  <p className="text-lg font-bold text-slate-100">{detail.compliance_score}</p>
                  <p className="text-[10px] text-slate-500 uppercase">Compliance</p>
                </div>
                <div className="bg-slate-800/40 rounded-lg p-2">
                  <p className="text-lg font-bold text-slate-100">{detail.risk_score}</p>
                  <p className="text-[10px] text-slate-500 uppercase">Risk Score</p>
                </div>
                <div className="bg-slate-800/40 rounded-lg p-2">
                  <p className="text-lg font-bold text-slate-100">
                    +{detail.added_lines}/-{detail.removed_lines}
                  </p>
                  <p className="text-[10px] text-slate-500 uppercase">Lines Changed</p>
                </div>
              </div>

              {detail.ai_summary && (
                <div>
                  <p className="text-xs font-semibold text-slate-500 uppercase mb-1">AI Summary</p>
                  <p className="text-sm text-slate-300">{detail.ai_summary}</p>
                </div>
              )}

              {findings.length > 0 && (
                <ul className="text-xs text-slate-400 list-disc list-inside space-y-0.5">
                  {findings.map((f, i) => (
                    <li key={i}>{f}</li>
                  ))}
                </ul>
              )}

              {recommendation && (
                <div
                  className={`rounded-lg p-3 text-xs ${
                    recommendation.recommended ? "bg-red-950/40 text-red-400" : "bg-emerald-950/40 text-emerald-400"
                  }`}
                >
                  <p className="font-semibold mb-0.5">
                    {recommendation.recommended ? "Rollback recommended" : "No rollback needed"}
                  </p>
                  <p>{recommendation.reason}</p>
                  {recommendation.recommended && (
                    <>
                      {detail.baseline === "golden_config" || detail.baseline === "role_baseline" ? (
                        <>
                          <p className="mt-1 text-slate-500">
                            This drift was detected against an approved {detail.baseline === "golden_config" ? "golden config" : "role baseline"} --
                            it can be auto-remediated by pushing that config straight back to the device, or you
                            can roll back manually via a specific snapshot on the Devices page instead.
                          </p>
                          <div className="mt-1.5">
                            <ImpactClassificationBadge
                              classification={detail.risk_score >= 70 ? "danger" : detail.risk_score >= 40 ? "caution" : "safe"}
                              label={
                                detail.risk_score >= 70
                                  ? `⛔ High risk score (${detail.risk_score}) -- review before pushing`
                                  : detail.risk_score >= 40
                                  ? `⚠ Moderate risk score (${detail.risk_score})`
                                  : `✓ Low risk score (${detail.risk_score})`
                              }
                            />
                          </div>
                          {canReview && detail.status === "open" && (
                            <button
                              onClick={async () => {
                                if (
                                  !(await confirm(
                                    `Submit a change request to push the ${detail.baseline === "golden_config" ? "golden config" : "role baseline"} to this device? This only submits it for approval -- it still needs a NETWORK_ADMIN to approve (a second, different one if it's Critical Risk) before anything deploys.`,
                                    { danger: false, confirmLabel: "Submit for approval" }
                                  ))
                                )
                                  return;
                                setRemediating(true);
                                setRemediationError(null);
                                try {
                                  const res = await api.post<{ message: string; change_request_id: string; requires_dual_approval: boolean }>(
                                    `/api/v1/drift/${detail.id}/remediate`
                                  );
                                  setRemediationNotice(res.data.message);
                                  const [detailRes, recRes] = await Promise.all([
                                    api.get(`/api/v1/drift/${detail.id}`),
                                    api.get(`/api/v1/drift/${detail.id}/rollback-recommendation`),
                                  ]);
                                  setDetail(detailRes.data);
                                  setRecommendation(recRes.data);
                                  load();
                                } catch (err: any) {
                                  setRemediationError(err?.response?.data?.detail || "Failed to submit auto-remediation.");
                                } finally {
                                  setRemediating(false);
                                }
                              }}
                              disabled={remediating}
                              className="mt-2 bg-red-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold uppercase tracking-wider hover:bg-red-700 disabled:opacity-50"
                            >
                              {remediating
                                ? "Submitting…"
                                : `⚡ Push ${detail.baseline === "golden_config" ? "Golden Config" : "Role Baseline"} to Fix Drift`}
                            </button>
                          )}
                        </>
                      ) : (
                        <p className="mt-1 text-slate-500">
                          To roll back, go to the <span className="font-medium text-slate-100">Devices</span> page and select a
                          snapshot to restore.
                        </p>
                      )}
                      {remediationError && <p className="mt-1 text-red-400">{remediationError}</p>}
                      {remediationNotice && <p className="mt-1 text-emerald-400 font-medium">{remediationNotice}</p>}
                    </>
                  )}
                </div>
              )}

              {detail.cli_diff && (
                <div>
                  <p className="text-xs font-semibold text-slate-500 uppercase mb-1">CLI Commands (What Changed)</p>
                  <pre className="bg-slate-900 text-xs rounded-lg p-4 overflow-x-auto leading-relaxed">
                    {detail.cli_diff.split("\n").map((line, i) => {
                      let cls = "text-slate-300";
                      if (line.startsWith("interface ") || line.startsWith("router ")) cls = "text-indigo-500 font-semibold block";
                      else if (line.trimStart().startsWith("no ")) cls = "text-red-400 bg-red-950/40 block";
                      else if (line.startsWith("  ")) cls = "text-emerald-400 bg-green-950/40 block";
                      return (
                        <span key={i} className={cls}>
                          {line || " "}
                          {"\n"}
                        </span>
                      );
                    })}
                  </pre>
                </div>
              )}

              <details className="group">
                <summary className="text-xs font-semibold text-slate-500 uppercase mb-1 cursor-pointer hover:text-cyan-400 select-none">
                  {detail.cli_diff ? "Raw Configuration Diff ▸" : "Configuration Diff"}
                </summary>
                <div className="mt-1">
                  <ConfigDiff diffText={detail.diff_text} />
                </div>
              </details>

              {reviewError && <p className="text-red-400 text-xs">{reviewError}</p>}
              {detail.status === "open" &&
                (canReview ? (
                  <div className="flex gap-2 pt-2">
                    <button
                      onClick={() => review("approved")}
                      disabled={reviewing}
                      className="bg-cyan-600 text-white rounded-lg px-4 py-2 text-sm font-semibold hover:bg-cyan-500 transition-colors disabled:opacity-50"
                    >
                      Approve as New Baseline
                    </button>
                    <button
                      onClick={() => review("dismissed")}
                      disabled={reviewing}
                      className="bg-slate-700 text-slate-300 rounded-lg px-4 py-2 text-sm font-semibold hover:bg-slate-700 transition-colors disabled:opacity-50"
                    >
                      Dismiss
                    </button>
                  </div>
                ) : (
                  <p className="text-xs text-slate-400 italic pt-2">
                    Only a Network Administrator can approve or dismiss a drift record.
                  </p>
                ))}
            </div>
          )}
        </div>
      </div>
      </div>
    </div>
  );
}