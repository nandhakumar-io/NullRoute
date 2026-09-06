import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { endpoints, NetworkScanJob } from "../api";
import { PageHeader, Loading } from "../components/ui";

const STAGES = [
  "discovery",
  "device_identification",
  "configuration",
  "normalization",
  "compliance",
  "risk_analysis",
  "report",
] as const;

type StageStatus = "PENDING" | "RUNNING" | "DONE" | "SKIPPED" | "FAILED";

function StageRow({ name, stage }: { name: string; stage: { status: StageStatus; detail?: string } | undefined }) {
  const status = stage?.status ?? "PENDING";
  const icons: Record<string, string> = {
    PENDING: "○",
    RUNNING: "⟳",
    DONE: "✓",
    SKIPPED: "–",
    FAILED: "✗",
  };
  const colors: Record<string, string> = {
    PENDING: "text-slate-600",
    RUNNING: "text-cyan-400 animate-spin",
    DONE: "text-emerald-400",
    SKIPPED: "text-slate-500",
    FAILED: "text-red-400",
  };
  const barColors: Record<string, string> = {
    PENDING: "bg-slate-800",
    RUNNING: "bg-cyan-600 animate-pulse",
    DONE: "bg-emerald-600",
    SKIPPED: "bg-slate-700",
    FAILED: "bg-red-700",
  };
  return (
    <div className="flex items-start gap-4 py-3">
      <div className={`text-xl font-mono w-6 shrink-0 mt-0.5 ${colors[status]}`}>{icons[status]}</div>
      <div className="flex-1">
        <div className={`flex items-center gap-2`}>
          <span className={`text-sm font-semibold capitalize ${status === "RUNNING" ? "text-cyan-300" : status === "DONE" ? "text-emerald-300" : status === "FAILED" ? "text-red-300" : "text-slate-400"}`}>
            {name.replace(/_/g, " ")}
          </span>
          <span className={`badge text-[10px] ${
            status === "RUNNING" ? "bg-cyan-950 text-cyan-300 border border-cyan-800"
            : status === "DONE" ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
            : status === "FAILED" ? "bg-red-950 text-red-300 border border-red-800"
            : status === "SKIPPED" ? "bg-slate-800 text-slate-500 border border-slate-700"
            : "bg-slate-900 text-slate-600 border border-slate-800"
          }`}>
            {status === "RUNNING" ? "in progress" : status.toLowerCase()}
          </span>
        </div>
        <div className="mt-1.5 h-1.5 bg-slate-900 rounded-full overflow-hidden w-full max-w-md">
          <div className={`h-full rounded-full ${barColors[status]}`} style={{ width: status === "PENDING" ? "0%" : status === "SKIPPED" ? "100%" : "100%" }} />
        </div>
        {stage?.detail && (
          <div className="text-xs text-slate-500 mt-1">{stage.detail}</div>
        )}
      </div>
    </div>
  );
}

function DeviceResultRow({ r }: { r: any }) {
  const decision = r.final_decision as string | undefined;
  return (
    <tr className="border-b border-soc-border/50 hover:bg-slate-800/30 transition-colors">
      <td className="px-4 py-3">
        <Link to={`/devices/${r.device_id}`} className="text-cyan-400 hover:underline font-mono text-xs">
          {r.hostname || r.device_id?.slice(0, 12)}
        </Link>
      </td>
      <td className="px-4 py-3">
        {r.success ? (
          <span className="badge bg-emerald-950 text-emerald-300 border border-emerald-800">Success</span>
        ) : (
          <span className="badge bg-red-950 text-red-300 border border-red-800">Failed</span>
        )}
      </td>
      <td className="px-4 py-3">
        {r.scan_id ? (
          <Link to={`/scans/${r.scan_id}`} className="text-cyan-400 hover:underline font-mono text-xs">
            {r.scan_id.slice(0, 8)}
          </Link>
        ) : "—"}
      </td>
      <td className="px-4 py-3">
        {decision ? (
          <span className={`badge ${decision === "PASS" ? "badge-pass" : decision === "BLOCK" ? "badge-critical" : "badge-medium"}`}>
            {decision}
          </span>
        ) : "—"}
      </td>
      <td className="px-4 py-3 text-slate-400">
        {r.compliance_score != null ? `${Math.round(r.compliance_score)}%` : "—"}
      </td>
      <td className="px-4 py-3">
        {r.risk_level ? (
          <span className={`badge ${r.risk_level === "HIGH" || r.risk_level === "CRITICAL" ? "badge-high" : r.risk_level === "MEDIUM" ? "badge-medium" : "badge-low"}`}>
            {r.risk_level}
          </span>
        ) : "—"}
      </td>
      <td className="px-4 py-3 text-red-400 text-xs max-w-[200px] truncate" title={r.error ?? ""}>
        {r.error ?? ""}
      </td>
    </tr>
  );
}

export default function NetworkScanDetail() {
  const { scanJobId } = useParams<{ scanJobId: string }>();
  const [job, setJob] = useState<NetworkScanJob | null>(null);
  const [loading, setLoading] = useState(true);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchJob = async () => {
    if (!scanJobId) return;
    try {
      const r = await endpoints.getNetworkScan(scanJobId);
      setJob(r.data);
      if (r.data.status !== "RUNNING" && r.data.status !== "PENDING") {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    } catch {
      if (pollRef.current) clearInterval(pollRef.current);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchJob();
    pollRef.current = setInterval(fetchJob, 3000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [scanJobId]);

  if (loading) return <Loading />;
  if (!job) return (
    <div className="px-8 py-10 text-slate-500">Network scan job not found.</div>
  );

  const stages = job.stages as Record<string, { status: StageStatus; detail?: string }> || {};
  const deviceResults: any[] = job.device_results ?? [];
  const discoveredHosts: any[] = job.discovered_hosts ?? [];
  const resolvedIds: string[] = job.resolved_device_ids ?? [];

  return (
    <div>
      <PageHeader
        title={job.name || `Scan Job ${job.id.slice(0, 8)}`}
        subtitle={`Network scan · ${job.framework} · ${job.include_batfish ? "Batfish enabled" : "No Batfish"}`}
      />

      {/* Top metadata */}
      <div className="px-8 grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Status", value: job.status },
          { label: "Target CIDR", value: job.target_cidr ?? (job.run_discovery ? "—" : "Devices only") },
          { label: "Discovered Hosts", value: discoveredHosts.length || "—" },
          { label: "Resolved Devices", value: resolvedIds.length || "—" },
        ].map(({ label, value }) => (
          <div key={label} className="card py-3 px-4">
            <div className="text-xs text-slate-500 font-semibold uppercase tracking-wide mb-1">{label}</div>
            <div className="font-semibold text-slate-200">{value}</div>
          </div>
        ))}
      </div>

      <div className="px-8 grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Stage progress */}
        <div className="card">
          <div className="font-semibold text-slate-200 mb-2">Pipeline Stages</div>
          <div className="divide-y divide-soc-border/50">
            {STAGES.map((stage) => (
              <StageRow key={stage} name={stage} stage={stages[stage]} />
            ))}
          </div>
          {(job.status === "RUNNING" || job.status === "PENDING") && (
            <div className="text-xs text-slate-500 mt-3 animate-pulse">Polling for updates…</div>
          )}
        </div>

        {/* Timestamps + discovered hosts */}
        <div className="flex flex-col gap-4">
          <div className="card">
            <div className="font-semibold text-slate-200 mb-3">Timeline</div>
            <div className="space-y-2 text-sm">
              {[
                { label: "Created", value: job.created_at },
                { label: "Started", value: job.started_at },
                { label: "Completed", value: job.completed_at },
              ].map(({ label, value }) => (
                <div key={label} className="flex justify-between">
                  <span className="text-slate-500">{label}</span>
                  <span className="text-slate-300">{value ? new Date(value).toLocaleString() : "—"}</span>
                </div>
              ))}
              {job.created_by && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Created by</span>
                  <span className="text-slate-300">{job.created_by}</span>
                </div>
              )}
            </div>
          </div>

          {job.error && (
            <div className="card border-red-800 bg-red-950/20">
              <div className="text-xs font-semibold text-red-400 uppercase tracking-wide mb-1">Error</div>
              <div className="text-red-300 text-sm">{job.error}</div>
            </div>
          )}

          {discoveredHosts.length > 0 && (
            <div className="card">
              <div className="font-semibold text-slate-200 mb-2">Discovered Hosts ({discoveredHosts.length})</div>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {discoveredHosts.map((h: any) => (
                  <div key={h.ip} className="flex items-center gap-2 text-xs text-slate-400">
                    <span className="font-mono text-cyan-400">{h.ip}</span>
                    {h.hostname && <span>· {h.hostname}</span>}
                    {h.vendor_guess && <span className="badge bg-slate-800 text-slate-400 border border-slate-700">{h.vendor_guess}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Per-device results */}
      {deviceResults.length > 0 && (
        <div className="px-8 mb-8">
          <div className="font-semibold text-slate-200 mb-3">Device Results ({deviceResults.length})</div>
          <div className="card p-0 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-soc-border text-slate-500 text-xs uppercase tracking-wide">
                  <th className="px-4 py-3 text-left">Device</th>
                  <th className="px-4 py-3 text-left">Outcome</th>
                  <th className="px-4 py-3 text-left">Scan</th>
                  <th className="px-4 py-3 text-left">Decision</th>
                  <th className="px-4 py-3 text-left">Compliance</th>
                  <th className="px-4 py-3 text-left">Risk</th>
                  <th className="px-4 py-3 text-left">Error</th>
                </tr>
              </thead>
              <tbody>
                {deviceResults.map((r: any, i: number) => (
                  <DeviceResultRow key={r.device_id ?? i} r={r} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
