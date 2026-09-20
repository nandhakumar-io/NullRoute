import { useEffect, useState, ReactNode } from "react";
import { Link } from "react-router-dom";
import { endpoints, DashboardStats, DashboardMetrics, DashboardRange, Device, Finding, BackupFleetSummary, ComplianceMatrix } from "../api";
import { PageHeader, StatCard, Loading, StatusBadge, ScoreRing, CollapsibleCard } from "../components/ui";
import RagChatPanel from "../components/RagChatPanel";
import { useTheme } from "../theme";
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
  const color = v >= 80 ? "#10b981" : v >= 50 ? "#f59e0b" : "#ef4444";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${v}%`, background: color }} />
      </div>
      <span className="text-xs font-semibold w-8 text-right" style={{ color }}>{Math.round(v)}%</span>
    </div>
  );
}

function LiveClock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div
      className="flex flex-col items-end px-3 py-1 rounded-lg border border-soc-border bg-slate-900/60 leading-tight"
      title="Local time"
    >
      <span className="text-sm font-semibold text-slate-200 tabular-nums">
        {now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
      </span>
      <span className="text-[11px] text-slate-500">
        {now.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" })}
      </span>
    </div>
  );
}

/** Small chip used for the top-of-page "posture" summary row. */
function PostureChip({ label, value, tone }: { label: string; value: ReactNode; tone: "critical" | "high" | "medium" | "good" | "neutral" }) {
  const toneStyles: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/30",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/30",
    medium: "bg-amber-500/10 text-amber-600 border-amber-500/30",
    good: "bg-emerald-500/10 text-emerald-600 border-emerald-500/30",
    neutral: "bg-slate-500/10 text-slate-500 border-slate-500/30",
  };
  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium ${toneStyles[tone]}`}>
      <span className="font-bold">{value}</span>
      <span className="opacity-80 text-xs">{label}</span>
    </div>
  );
}

/** Cross-vendor compliance heatmap: rows are controls, columns are
 * vendors, cell shade is PASS rate. This is the single visual that proves
 * the "unified, not vendor-siloed" pitch -- the exact same control row is
 * evaluated against every vendor's own native syntax and lands in the
 * same table. Blank cells mean that control simply wasn't applicable /
 * evaluated for that vendor yet, not a failure. */
function heatColor(pct: number | null, isLight: boolean): string {
  if (pct == null) return isLight ? "#f1f5f9" : "#1e2a44";
  if (pct >= 90) return isLight ? "#bbf7d0" : "#065f46";
  if (pct >= 75) return isLight ? "#d9f99d" : "#3f6212";
  if (pct >= 50) return isLight ? "#fef08a" : "#854d0e";
  if (pct >= 25) return isLight ? "#fed7aa" : "#9a3412";
  return isLight ? "#fecaca" : "#7f1d1d";
}

function ComplianceMatrixHeatmap({ matrix, isLight }: { matrix: ComplianceMatrix; isLight: boolean }) {
  if (matrix.rows.length === 0) {
    return <div className="text-slate-500 text-sm">No cross-vendor findings yet — scan devices from at least two vendors to populate this matrix.</div>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs border-collapse">
        <thead>
          <tr>
            <th className="text-left px-2 py-1.5 text-slate-500 font-semibold uppercase tracking-wide sticky left-0 bg-inherit">Control</th>
            {matrix.vendors.map((v) => (
              <th key={v} className="px-2 py-1.5 text-slate-500 font-semibold uppercase tracking-wide text-center whitespace-nowrap">{v}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.rows.map((row) => (
            <tr key={row.control_id}>
              <td className="px-2 py-1 font-mono text-slate-300 whitespace-nowrap" title={row.title}>
                {row.control_id}
              </td>
              {matrix.vendors.map((v) => {
                const val = row.vendors[v];
                return (
                  <td key={v} className="px-1 py-1 text-center">
                    <div
                      className="rounded px-2 py-1 font-semibold"
                      style={{ background: heatColor(val, isLight), color: val == null ? "#64748b" : isLight ? "#0f172a" : "#e2e8f0" }}
                      title={`${row.control_id} on ${v}: ${val == null ? "not evaluated" : `${val}% pass`}`}
                    >
                      {val == null ? "—" : `${val}%`}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex items-center gap-3 mt-3 text-[10px] text-slate-500">
        <span>Same control, evaluated natively per vendor syntax:</span>
        {[["≥90%", 92], ["75-89%", 80], ["50-74%", 60], ["25-49%", 35], ["<25%", 10]].map(([label, v]) => (
          <span key={label as string} className="flex items-center gap-1">
            <span className="w-3 h-3 rounded-sm inline-block" style={{ background: heatColor(v as number, isLight) }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { theme } = useTheme();
  const isLight = theme === "light";
  // recharts needs literal color values, not Tailwind classes, so the two
  // small palettes below are the one place chart colors are picked
  // per-theme; everything else in this file rides the app-wide CSS
  // `html.light` remap in index.css.
  const chartAxis = "#64748b";
  const chartGrid = isLight ? "#e2e8f0" : "#1e2a44";
  const tooltipStyle = isLight
    ? { background: "#ffffff", border: "1px solid #e2e8f0", color: "#0f172a", borderRadius: 8 }
    : { background: "#111a2e", border: "1px solid #1e2a44", borderRadius: 8 };

  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [range, setRange] = useState<DashboardRange>("7d");
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [criticalFindings, setCriticalFindings] = useState<Finding[]>([]);
  const [backupSummary, setBackupSummary] = useState<BackupFleetSummary | null>(null);
  const [openAlertCount, setOpenAlertCount] = useState<number | null>(null);
  const [matrix, setMatrix] = useState<ComplianceMatrix | null>(null);

  useEffect(() => {
    endpoints.dashboard().then((r) => setStats(r.data)).catch(() => setStats(null));
    endpoints.complianceMatrix().then((r) => setMatrix(r.data)).catch(() => setMatrix(null));
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

  const neverScanned = devices.filter((d) => d.last_compliance_score == null).length;
  // The fleet-wide `overall_compliance_score` is the always-on source of
  // truth for "current posture" — it's derived from each device's latest
  // scan regardless of when that scan happened. `metrics.compliance_score`
  // is scoped to the selected time window and legitimately reads 0 when no
  // scan ran in that window, which used to make the dashboard show "0%
  // overall compliance" even on a fleet that's actually 93.9% compliant.
  // Only prefer the windowed score once the window actually has scan
  // activity to report.
  const overallScore =
    metrics && trendData.length > 0
      ? Math.round(metrics.compliance_score)
      : Math.round(stats.overall_compliance_score);

  // Same fallback: the windowed metrics endpoint legitimately reports 0
  // open/critical/high findings when nothing happened in the selected
  // range, but the fleet still has real open findings from before that
  // window — those live on `stats` and are what "Findings Breakdown"
  // below is built from, so use them whenever the window itself is empty.
  const hasWindowActivity = !!metrics && trendData.length > 0;
  const openFindingsTotal = hasWindowActivity
    ? metrics!.open_findings
    : stats.critical_findings + stats.high_findings + stats.medium_findings + stats.low_findings;
  const criticalCount = hasWindowActivity ? metrics!.critical_findings : stats.critical_findings;
  const highCount = hasWindowActivity ? metrics!.high_findings : stats.high_findings;
  const postureTone: "critical" | "high" | "medium" | "good" = overallScore >= 80 ? "good" : overallScore >= 60 ? "medium" : overallScore >= 40 ? "high" : "critical";

  return (
    <div className="pb-24">
      <PageHeader
        title="Security Operations Dashboard"
        subtitle="Multi-vendor network compliance, risk, and drift posture at a glance"
        action={
          <div className="flex items-center gap-3">
            <LiveClock />
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
        }
      />

      {/* At-a-glance posture strip -- the "so what do I need to know right now" row */}
      <div className="px-8 flex flex-wrap gap-2 mb-6">
        <PostureChip label="global network compliance" value={`${overallScore}%`} tone={postureTone} />
        <PostureChip
          label="devices out of baseline"
          value={`${stats.devices_out_of_baseline} Critical`}
          tone={stats.devices_out_of_baseline > 0 ? "critical" : "good"}
        />
        <PostureChip
          label="MTTR"
          value={
            stats.mttr_hours == null
              ? "—"
              : `${stats.mttr_hours < 1 ? `${Math.round(stats.mttr_hours * 60)}m` : `${stats.mttr_hours.toFixed(1)}h`}${
                  stats.mttr_improvement_pct != null
                    ? ` (${stats.mttr_improvement_pct > 0 ? "↓" : "↑"}${Math.abs(stats.mttr_improvement_pct)}%)`
                    : ""
                }`
          }
          tone={stats.mttr_improvement_pct != null && stats.mttr_improvement_pct > 0 ? "good" : "neutral"}
        />
        <PostureChip label="open critical" value={stats.critical_findings} tone={stats.critical_findings > 0 ? "critical" : "good"} />
        <PostureChip label="open high" value={stats.high_findings} tone={stats.high_findings > 0 ? "high" : "good"} />
        <PostureChip label="devices never scanned" value={neverScanned} tone={neverScanned > 0 ? "medium" : "good"} />
        <PostureChip label="open alerts" value={openAlertCount ?? "—"} tone={(openAlertCount ?? 0) > 0 ? "high" : "good"} />
        <PostureChip label="batfish violations" value={stats.batfish_violations} tone={stats.batfish_violations > 0 ? "high" : "good"} />
        <PostureChip label="evidence integrity failures" value={stats.integrity_failures} tone={stats.integrity_failures > 0 ? "critical" : "good"} />
      </div>

      <div className="px-8 grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="card flex flex-col items-center justify-center">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">
            Compliance % ({range})
          </div>
          <ScoreRing score={overallScore} />
        </div>
        <StatCard label="Open Findings" value={openFindingsTotal} tone="high" />
        <StatCard label="Resolved Findings" value={metrics?.resolved_findings ?? "—"} tone="good" />
        <StatCard
          label={`Critical / High (${range})`}
          value={`${criticalCount} / ${highCount}`}
          tone="critical"
        />
      </div>

      {/* Cross-Vendor Compliance Matrix -- the "unified, not siloed" proof:
          same control row, evaluated natively against every vendor's own
          config syntax, side by side. */}
      <div className="px-8 mt-4">
        <CollapsibleCard
          title="Cross-Vendor Compliance Matrix"
          subtitle="Same control catalog evaluated natively across every vendor's syntax — one normalized model, not vendor silos"
          storageKey="crossVendorMatrix"
        >
          {!matrix ? (
            <div className="text-slate-500 text-sm h-[80px] flex items-center justify-center">Loading…</div>
          ) : (
            <ComplianceMatrixHeatmap matrix={matrix} isLight={isLight} />
          )}
        </CollapsibleCard>
      </div>

      <div className="px-8 mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <CollapsibleCard title="Compliance Score Over Time" subtitle={`Trend across the last ${range}`} storageKey="complianceTrend">
          {metricsLoading || !metrics ? (
            <div className="text-slate-500 text-sm h-[220px] flex items-center justify-center">Loading…</div>
          ) : trendData.length === 0 ? (
            <div className="text-slate-500 text-sm">No scans in this window yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke={chartGrid} />
                <XAxis dataKey="label" stroke={chartAxis} fontSize={11} />
                <YAxis stroke={chartAxis} fontSize={12} domain={[0, 100]} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line type="monotone" dataKey="compliance" stroke="#0891b2" strokeWidth={2} dot={false} connectNulls />
              </LineChart>
            </ResponsiveContainer>
          )}
        </CollapsibleCard>

        <CollapsibleCard title="Findings by Severity Over Time" subtitle="New findings introduced per period" storageKey="findingsTrend">
          {metricsLoading || !metrics ? (
            <div className="text-slate-500 text-sm h-[220px] flex items-center justify-center">Loading…</div>
          ) : trendData.length === 0 ? (
            <div className="text-slate-500 text-sm">No findings in this window yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke={chartGrid} />
                <XAxis dataKey="label" stroke={chartAxis} fontSize={11} />
                <YAxis stroke={chartAxis} fontSize={12} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.75} name="Critical" />
                <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.75} name="High" />
                <Area type="monotone" dataKey="medium" stackId="1" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.75} name="Medium" />
                <Area type="monotone" dataKey="low" stackId="1" stroke="#10b981" fill="#10b981" fillOpacity={0.75} name="Low" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </CollapsibleCard>
      </div>

      {/* Findings breakdown -- most-referenced numbers for a netsec auditor */}
      <div className="px-8 mt-6">
        <CollapsibleCard title="Findings Breakdown" subtitle="Current open findings by severity and check engine" storageKey="findingsBreakdown">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Critical Findings" value={stats.critical_findings} tone="critical" />
            <StatCard label="High Findings" value={stats.high_findings} tone="high" />
            <StatCard label="Medium Findings" value={stats.medium_findings} tone="medium" />
            <StatCard label="Low Findings" value={stats.low_findings} tone="low" />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
            <StatCard label="OPA Policy Violations" value={stats.opa_violations} tone="critical" />
            <StatCard label="Batfish Violations" value={stats.batfish_violations} tone="high" />
            <StatCard label="High-Risk Devices" value={stats.high_risk_devices} tone="high" />
            <StatCard label="Unknown Configurations" value={stats.unknown_configurations} tone="medium" />
          </div>
        </CollapsibleCard>
      </div>

      {/* Fleet + assurance -- inventory & evidence-chain health */}
      <div className="px-8 mt-4">
        <CollapsibleCard title="Fleet & Assurance" subtitle="Inventory coverage and tamper-evidence integrity" storageKey="fleetAssurance">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Total Devices" value={stats.total_devices} />
            <StatCard label="Devices Scanned" value={stats.devices_scanned} />
            <StatCard label="Pending AI Reviews" value={stats.pending_ai_mappings} tone="medium" />
            <StatCard label="Evidence Anchors" value={stats.evidence_anchors} tone="good" />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
            <StatCard label="Fabric Failures" value={stats.fabric_failures} tone={stats.fabric_failures > 0 ? "critical" : "default"} />
            <StatCard label="Integrity Failures" value={stats.integrity_failures} tone={stats.integrity_failures > 0 ? "critical" : "good"} />
            <StatCard label="Overall Compliance" value={`${stats.overall_compliance_score}%`} tone="good" />
            <StatCard label="Devices Never Scanned" value={neverScanned} tone={neverScanned > 0 ? "medium" : "good"} />
          </div>
        </CollapsibleCard>
      </div>

      {/* Operational Health: NCO backup coverage + alerting */}
      <div className="px-8 mt-6">
        <CollapsibleCard title="Operational Health" subtitle="Backup coverage, DR readiness, and alert volume" storageKey="operationalHealth">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Link to="/backups" className="card hover:border-cyan-700 transition-colors block">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Snapshot Coverage</div>
              <div className="text-2xl font-bold mt-2 text-slate-100">
                {backupSummary ? `${backupSummary.devices_with_snapshot}/${backupSummary.total_devices}` : "—"}
              </div>
            </Link>
            <Link to="/backups" className="card hover:border-cyan-700 transition-colors block">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">DR Destinations Healthy</div>
              <div
                className="text-2xl font-bold mt-2"
                style={{ color: backupSummary && backupSummary.destinations_failing > 0 ? "#ef4444" : "#10b981" }}
              >
                {backupSummary ? `${backupSummary.destinations_healthy}/${backupSummary.destination_count}` : "—"}
              </div>
            </Link>
            <Link to="/alerts" className="card hover:border-cyan-700 transition-colors block">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Open Alerts</div>
              <div className="text-2xl font-bold mt-2" style={{ color: openAlertCount ? "#ef4444" : "#10b981" }}>
                {openAlertCount ?? "—"}
              </div>
            </Link>
            <Link to="/backups" className="card hover:border-cyan-700 transition-colors block">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Recent Export Success</div>
              <div className="text-2xl font-bold mt-2 text-slate-100">
                {backupSummary && backupSummary.recent_jobs_evaluated > 0
                  ? `${Math.round((backupSummary.recent_jobs_success / backupSummary.recent_jobs_evaluated) * 100)}%`
                  : "—"}
              </div>
            </Link>
          </div>
        </CollapsibleCard>
      </div>

      {/* Devices Requiring Attention + Top Critical Findings */}
      <div className="px-8 mt-6 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <CollapsibleCard
          title="Devices Requiring Attention"
          subtitle="Lowest compliance score first"
          storageKey="devicesAttention"
          action={<Link to="/devices" className="text-xs text-cyan-500 hover:underline" onClick={(e) => e.stopPropagation()}>View all →</Link>}
        >
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
        </CollapsibleCard>

        <CollapsibleCard
          title="Top Critical Findings"
          subtitle="Currently failing, highest severity"
          storageKey="topCriticalFindings"
          action={<Link to="/compliance" className="text-xs text-cyan-500 hover:underline" onClick={(e) => e.stopPropagation()}>View all →</Link>}
        >
          {criticalFindings.length === 0 ? (
            <div className="text-slate-500 text-sm">No critical findings. ✓</div>
          ) : (
            <div className="space-y-2">
              {criticalFindings.map((f) => (
                <div key={f.id} className="px-3 py-2 rounded-lg bg-red-500/5 border border-red-500/20">
                  <div className="flex items-center gap-2">
                    <span className="text-red-500 text-xs font-semibold">{f.control_id}</span>
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
        </CollapsibleCard>
      </div>

      {/* Framework + Risk + Recent Scans */}
      <div className="px-8 mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
        <CollapsibleCard title="Framework Compliance" subtitle="Score by regulatory/security framework" storageKey="frameworkCompliance">
          {fwData.length === 0 ? (
            <div className="text-slate-500 text-sm">No scans yet — upload a configuration to get started.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={fwData}>
                <CartesianGrid strokeDasharray="3 3" stroke={chartGrid} />
                <XAxis dataKey="framework" stroke={chartAxis} fontSize={12} />
                <YAxis stroke={chartAxis} fontSize={12} domain={[0, 100]} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="score" fill="#0891b2" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </CollapsibleCard>

        <CollapsibleCard title="Risk Distribution" subtitle="Devices by computed risk level" storageKey="riskDistribution">
          {Object.keys(stats.risk_distribution).length === 0 ? (
            <div className="text-slate-500 text-sm">No risk-scored scans yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={Object.entries(stats.risk_distribution).map(([level, count]) => ({ level, count }))}>
                <CartesianGrid strokeDasharray="3 3" stroke={chartGrid} />
                <XAxis dataKey="level" stroke={chartAxis} fontSize={12} />
                <YAxis stroke={chartAxis} fontSize={12} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" fill="#ef4444" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </CollapsibleCard>

        <CollapsibleCard title="Recent Scans" subtitle="Latest compliance runs" storageKey="recentScans">
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
        </CollapsibleCard>
      </div>

      {/* Floating, shrinkable RAG chat dock -- see components/RagChatPanel.tsx */}
      <RagChatPanel />
    </div>
  );
}