import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, DashboardStats } from "../api";
import { PageHeader, StatCard, Loading, StatusBadge } from "../components/ui";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    endpoints.dashboard().then((r) => setStats(r.data)).catch(() => setStats(null));
  }, []);

  if (!stats) return <Loading />;

  const fwData = Object.entries(stats.framework_scores).map(([framework, score]) => ({ framework, score }));

  return (
    <div>
      <PageHeader title="SOC Dashboard" subtitle="AI-driven multi-vendor network security compliance overview" />
      <div className="px-8 grid grid-cols-2 md:grid-cols-4 gap-4">
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

      <div className="px-8 mt-6 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Framework Compliance</div>
          {fwData.length === 0 ? (
            <div className="text-slate-500 text-sm">No scans yet — upload a configuration to get started.</div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
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
          <div className="font-semibold text-slate-200 mb-3">Recent Scans</div>
          <div className="space-y-2">
            {stats.recent_scans.length === 0 && <div className="text-slate-500 text-sm">No scans yet.</div>}
            {stats.recent_scans.map((s) => (
              <Link
                key={s.id}
                to={`/scans/${s.id}`}
                className="flex items-center justify-between px-3 py-2 rounded-lg hover:bg-slate-800/50 border border-transparent hover:border-soc-border text-sm"
              >
                <span className="text-slate-300 font-mono text-xs">{s.id.slice(0, 8)}</span>
                <span className="text-slate-500">{s.framework}</span>
                <StatusBadge status={s.status} />
                <span className="text-slate-400 font-semibold">{s.compliance_score ?? "—"}%</span>
              </Link>
            ))}
          </div>
        </div>
      </div>

      <div className="px-8 mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">OPA vs Batfish Violations</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={Object.entries(stats.opa_vs_batfish).map(([k, v]) => ({ name: k.replace("_violations", ""), count: v }))}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#111a2e", border: "1px solid #1e2a44" }} />
              <Bar dataKey="count" fill="#f97316" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Risk Distribution</div>
          {Object.keys(stats.risk_distribution).length === 0 ? (
            <div className="text-slate-500 text-sm">No risk-scored scans yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
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
          <div className="font-semibold text-slate-200 mb-3">Evidence Anchoring Status</div>
          {Object.keys(stats.evidence_anchoring_status).length === 0 ? (
            <div className="text-slate-500 text-sm">No evidence generated yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={Object.entries(stats.evidence_anchoring_status).map(([status, count]) => ({ status, count }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
                <XAxis dataKey="status" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111a2e", border: "1px solid #1e2a44" }} />
                <Bar dataKey="count" fill="#22c55e" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
