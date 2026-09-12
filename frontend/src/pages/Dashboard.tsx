import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, DashboardStats, DashboardMetrics, DashboardRange, Device, Finding, BackupFleetSummary } from "../api";
import { PageHeader, StatCard, Loading, StatusBadge, ScoreRing } from "../components/ui";
import {
  BarChart, Bar, LineChart, Line, AreaChart, Area, XAxis, YAxis, Tooltip, Legend,
  ResponsiveContainer, CartesianGrid,
} from "recharts";

const RANGES: { value: DashboardRange; label: string }[] = [
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
  { value: "90d", label: "90d" },
];

function formatBucketLabel(iso: string, range: DashboardRange) {
  const d = new Date(iso);
  return range === "24h"
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function ScoreBar({ score }: { score: number | null }) {
  const v = score ?? 0;
  const color = v >= 80 ? "#34d399" : v >= 50 ? "#fbbf24" : "#f87171";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${v}%`, background: color }} />
      </div>
      <span className="text-xs font-semibold w-8 text-right" style={{ color }}>{Math.round(v)}%</span>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [range, setRange] = useState<DashboardRange>("7d");
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [criticalFindings, setCriticalFindings] = useState<Finding[]>([]);
  const [backupSummary, setBackupSummary] = useState<BackupFleetSummary | null>(null);
  const [openAlertCount, setOpenAlertCount] = useState<number | null>(null);

  useEffect(() => {
    endpoints.dashboard().then((r) => setStats(r.data)).catch(() => setStats(null));
    endpoints.backupSummary().then((r) => setBackupSummary(r.data)).catch(() => setBackupSummary(null));
    endpoints.alerts({ status: "OPEN" }).then((r) => setOpenAlertCount(r.data.count)).catch(() => setOpenAlertCount(null));
    endpoints.devices({ limit: 50, sort_by: "last_compliance_score", sort_dir: "asc" })
      .then((r) => {
        const items = (r.data as any).items ?? r.data;
        setDevices(Array.isArray(items) ? items : []);
      })
      .catch(() => {});
    endpoints.findings({ severity: "CRITICAL", result: "FAIL" })
      .then((r) => setCriticalFindings(Array.isArray(r.data) ? (r.data as Finding[]).slice(0, 8) : []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    setMetricsLoading(true);
    endpoints
      .dashboardMetrics(range)
      .then((r) => setMetrics(r.data))
      .catch(() => setMetrics(null))
      .finally(() => setMetricsLoading(false));
  }, [range]);

  if (!stats) return <Loading />;

  const fwData = Object.entries(stats.framework_scores).map(([framework, score]) => ({ framework, score }));
  const trendData = (metrics?.timeseries || []).map((p) => ({
    label: formatBucketLabel(p.bucket, range),
    compliance: p.compliance_score,
    critical: p.critical_findings,
    high: p.high_findings,
    medium: p.medium_findings,
    low: p.low_findings,
  }));

  const attentionDevices = [...devices]
    .sort((a, b) => {
      if (a.last_compliance_score == null) return -1;
      if (b.last_compliance_score == null) return 1;
      return (a.last_compliance_score ?? 0) - (b.last_compliance_score ?? 0);
    })
    .slice(0, 8);

  return (
    <div>
      <PageHeader title="SOC Dashboard" subtitle="AI-driven multi-vendor network security compliance overview" />

      <div className="px-8 flex items-center justify-between mb-3">
        <div className="font-semibold text-slate-200">Compliance Trends</div>
        <div className="flex gap-1 bg-slate-900/60 border border-soc-border rounded-lg p-1">
          {RANGES.map((r) => (
            <button
              key={r.value}
              onClick={() => setRange(r.value)}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors ${
                range === r.value ? "bg-cyan-600 text-white" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="px-8 grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="card flex flex-col items-center justify-center">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">
            Compliance % ({range})
          </div>
          <ScoreRing score={metrics ? Math.round(metrics.compliance_score) : 0} />
        </div>
        <StatCard label="Open Findings" value={metrics?.open_findings ?? "—"} tone="high" />
        <StatCard label="Resolved Findings" value={metrics?.resolved_findings ?? "—"} tone="good" />
        <StatCard
          label={`Critical / High (${range})`}
          value={metrics ? `${metrics.critical_findings} / ${metrics.high_findings}` : "—"}
          tone="critical"
        />
      </div>

      <div className="px-8 mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Compliance Score Over Time</div>
          {metricsLoading || !metrics ? (
            <div className="text-slate-500 text-sm h-[220px] flex items-center justify-center">Loading…</div>
          ) : trendData.length === 0 ? (
            <div className="text-slate-500 text-sm">No scans in this window yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
                <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={12} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: "#111a2e", border: "1px solid #1e2a44" }} />
                <Line type="monotone" dataKey="compliance" stroke="#22d3ee" strokeWidth={2} dot={false} connectNulls />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Findings by Severity Over Time</div>
          {metricsLoading || !metrics ? (
            <div className="text-slate-500 text-sm h-[220px] flex items-center justify-center">Loading…</div>
          ) : trendData.length === 0 ? (
            <div className="text-slate-500 text-sm">No findings in this window yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
                <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111a2e", border: "1px solid #1e2a44" }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" name="Critical" />
                <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" name="High" />
                <Area type="monotone" dataKey="medium" stackId="1" stroke="#f59e0b" fill="#f59e0b" name="Medium" />
                <Area type="monotone" dataKey="low" stackId="1" stroke="#10b981" fill="#10b981" name="Low" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* KPI rows */}
      <div className="px-8 grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
        <StatCard label="Total Devices" value={stats.total_devices} />
        <StatCard label="Devices Scanned" value={stats.devices_scanned} />
        <StatCard label="Overall Compliance" value={`${stats.overall_compliance_score}%`} tone="good" />
        <StatCard label="Pending AI Reviews" value={stats.pending_ai_mappings} tone="medium" />
      </div>
      <div className="px-8 mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Critical Findings" value={stats.critical_findings} tone="critical" />
        <StatCard label="High Findings" value={stats.high_findings} tone="high" />
        <StatCard label="Medium Findings" value={stats.medium_findings} tone="medium" />
        <StatCard label="Low Findings" value={stats.low_findings} tone="low" />
      </div>
      <div className="px-8 mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="OPA Violations" value={stats.opa_violations} tone="critical" />
        <StatCard label="Batfish Violations" value={stats.batfish_violations} tone="high" />
        <StatCard label="High-Risk Devices" value={stats.high_risk_devices} tone="high" />
        <StatCard label="Unknown Configurations" value={stats.unknown_configurations} tone="medium" />
      </div>
      <div className="px-8 mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Evidence Anchors" value={stats.evidence_anchors} tone="good" />
        <StatCard label="Fabric Failures" value={stats.fabric_failures} tone={stats.fabric_failures > 0 ? "critical" : "default"} />
        <StatCard label="Integrity Failures" value={stats.integrity_failures} tone={stats.integrity_failures > 0 ? "critical" : "good"} />
      </div>

      {/* Operational Health: NCO backup coverage + alerting */}
      <div className="px-8 mt-6">
        <div className="font-semibold text-slate-200 mb-3">Operational Health</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Link to="/backups" className="card hover:border-cyan-800 transition-colors block">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Snapshot Coverage</div>
            <div className="text-2xl font-bold mt-2 text-slate-100">
              {backupSummary ? `${backupSummary.devices_with_snapshot}/${backupSummary.total_devices}` : "—"}
            </div>
          </Link>
          <Link to="/backups" className="card hover:border-cyan-800 transition-colors block">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">DR Destinations Healthy</div>
            <div
              className="text-2xl font-bold mt-2"
              style={{ color: backupSummary && backupSummary.destinations_failing > 0 ? "#f87171" : "#34d399" }}
            >
              {backupSummary ? `${backupSummary.destinations_healthy}/${backupSummary.destination_count}` : "—"}
            </div>
          </Link>
          <Link to="/alerts" className="card hover:border-cyan-800 transition-colors block">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Open Alerts</div>
            <div className="text-2xl font-bold mt-2" style={{ color: openAlertCount ? "#f87171" : "#34d399" }}>
              {openAlertCount ?? "—"}
            </div>
          </Link>
          <Link to="/backups" className="card hover:border-cyan-800 transition-colors block">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Recent Export Success</div>
            <div className="text-2xl font-bold mt-2 text-slate-100">
              {backupSummary && backupSummary.recent_jobs_evaluated > 0
                ? `${Math.round((backupSummary.recent_jobs_success / backupSummary.recent_jobs_evaluated) * 100)}%`
                : "—"}
            </div>
          </Link>
        </div>
      </div>

      {/* Devices Requiring Attention + Top Critical Findings */}
      <div className="px-8 mt-6 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="font-semibold text-slate-200">Devices Requiring Attention</div>
            <Link to="/devices" className="text-xs text-cyan-400 hover:underline">View all →</Link>
          </div>
          {attentionDevices.length === 0 ? (
            <div className="text-slate-500 text-sm">No devices in inventory yet.</div>
          ) : (
            <div className="space-y-2">
              {attentionDevices.map((d) => (
                <Link
                  key={d.id}
                  to={`/devices/${d.id}`}
                  className="flex flex-col gap-1 px-3 py-2 rounded-lg hover:bg-slate-800/50 border border-transparent hover:border-soc-border transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-slate-200 text-sm font-medium">{d.hostname || d.name || d.management_address || d.id.slice(0, 10)}</span>
                    <div className="flex gap-1">
                      {d.vendor && <span className="badge bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">{d.vendor}</span>}
                      {d.last_compliance_score == null && <span className="badge bg-amber-950 text-amber-400 border border-amber-800 text-[10px]">Never scanned</span>}
                    </div>
                  </div>
                  <ScoreBar score={d.last_compliance_score} />
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="font-semibold text-slate-200">Top Critical Findings</div>
            <Link to="/compliance" className="text-xs text-cyan-400 hover:underline">View all →</Link>
          </div>
          {criticalFindings.length === 0 ? (
            <div className="text-slate-500 text-sm">No critical findings. ✓</div>
          ) : (
            <div className="space-y-2">
              {criticalFindings.map((f) => (
                <div key={f.id} className="px-3 py-2 rounded-lg bg-red-950/20 border border-red-900/40">
                  <div className="flex items-center gap-2">
                    <span className="text-red-300 text-xs font-semibold">{f.control_id}</span>
                    <span className="badge bg-red-950 text-red-300 border border-red-800 text-[10px]">{f.framework}</span>
                  </div>
                  <div className="text-slate-300 text-sm mt-0.5 truncate" title={f.title}>{f.title}</div>
                  {f.remediation && (
                    <div className="text-slate-500 text-xs mt-0.5 truncate" title={f.remediation}>{f.remediation}</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Framework + Risk + Recent Scans */}
      <div className="px-8 mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Framework Compliance</div>
          {fwData.length === 0 ? (
            <div className="text-slate-500 text-sm">No scans yet — upload a configuration to get started.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={fwData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
                <XAxis dataKey="framework" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: "#111a2e", border: "1px solid #1e2a44" }} />
                <Bar dataKey="score" fill="#22d3ee" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Risk Distribution</div>
          {Object.keys(stats.risk_distribution).length === 0 ? (
            <div className="text-slate-500 text-sm">No risk-scored scans yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={Object.entries(stats.risk_distribution).map(([level, count]) => ({ level, count }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
                <XAxis dataKey="level" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111a2e", border: "1px solid #1e2a44" }} />
                <Bar dataKey="count" fill="#ef4444" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Recent Scans</div>
          <div className="space-y-1.5">
            {stats.recent_scans.length === 0 && <div className="text-slate-500 text-sm">No scans yet.</div>}
            {stats.recent_scans.map((s) => (
              <Link
                key={s.id}
                to={`/scans/${s.id}`}
                className="flex items-center justify-between px-3 py-2 rounded-lg hover:bg-slate-800/50 border border-transparent hover:border-soc-border text-sm transition-colors"
              >
                <span className="text-slate-300 font-mono text-xs">{s.id.slice(0, 8)}</span>
                <span className="text-slate-500 text-xs">{s.framework}</span>
                <StatusBadge status={s.status} />
                <span className="text-slate-400 font-semibold text-sm">{s.compliance_score != null ? `${s.compliance_score}%` : "—"}</span>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}