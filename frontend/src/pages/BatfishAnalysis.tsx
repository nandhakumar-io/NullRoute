import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { endpoints, BatfishAnalysis as BatfishAnalysisType, BatfishReachabilityCheck, SnapshotDiff } from "../api";
import { PageHeader, Loading, EmptyState, SeverityBadge } from "../components/ui";

const STATUS_TONE: Record<string, string> = {
  BATFISH_PASS: "badge-pass",
  BATFISH_FAIL: "badge-fail",
  BATFISH_UNSUPPORTED: "badge-medium",
  BATFISH_UNAVAILABLE: "badge-na",
  BATFISH_ERROR: "badge-fail",
  NOT_INTEGRATED: "badge-na",
};

function StatusPill({ status }: { status: string }) {
  return <span className={`badge ${STATUS_TONE[status] || "badge-na"}`}>{status.replace(/_/g, " ")}</span>;
}

function ReachabilityRow({ check }: { check: BatfishReachabilityCheck }) {
  const fail = check.batfish_status === "BATFISH_FAIL";
  const unresolved = ["BATFISH_UNSUPPORTED", "BATFISH_UNAVAILABLE", "BATFISH_ERROR"].includes(check.batfish_status);
  return (
    <div className={`border rounded-lg p-3 ${fail ? "border-red-800/60 bg-red-950/20" : "border-soc-border"}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="font-mono text-xs text-slate-400">{check.control_id}</span>
        <div className="flex gap-2 items-center">
          {!unresolved && <SeverityBadge severity={check.severity} />}
          <StatusPill status={check.batfish_status} />
        </div>
      </div>
      <div className="text-sm text-slate-300">{check.title}</div>
      <div className="text-xs text-slate-500 mt-1 flex items-center gap-2">
        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">{check.source_zone}</span>
        <span>→</span>
        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">{check.destination_zone}</span>
        <span className="ml-2">
          reachable: <span className="text-slate-300">{check.reachable === null ? "n/a" : String(check.reachable)}</span>
          {" · "}expected: <span className="text-slate-300">{String(check.expected_reachable)}</span>
        </span>
      </div>
      {check.detail && <div className="text-xs font-mono text-cyan-400/80 mt-1">{check.detail}</div>}
    </div>
  );
}

export default function BatfishAnalysis() {
  const { scanId } = useParams();
  const [analysis, setAnalysis] = useState<BatfishAnalysisType | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    endpoints
      .batfishAnalysis(scanId)
      .then((r) => setAnalysis(r.data))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return <Loading />;
  if (!analysis) return <EmptyState message="No Batfish analysis found for this scan." />;

  const checks = analysis.reachability_checks || [];
  const violations = checks.filter((c) => c.batfish_status === "BATFISH_FAIL");
  const unsupported = (analysis.init_issues || []).filter((i) => i.status === "BATFISH_UNSUPPORTED");

  return (
    <div>
      <PageHeader
        title="Batfish Analysis"
        subtitle={
          <>
            Scan <span className="font-mono">{analysis.scan_id}</span> ·{" "}
            <Link className="text-cyan-400 hover:underline" to={`/scans/${analysis.scan_id}`}>
              back to scan
            </Link>
          </>
        }
        action={<StatusPill status={analysis.status} />}
      />

      {analysis.status === "NOT_INTEGRATED" && (
        <div className="px-8">
          <EmptyState message="Batfish behavioral analysis has not run for this scan (BATFISH_ENABLED=false)." />
        </div>
      )}

      {analysis.status !== "NOT_INTEGRATED" && (
        <>
          <div className="px-8 grid grid-cols-1 lg:grid-cols-4 gap-4 mb-6">
            <div className="card">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Network</div>
              <div className="text-sm font-mono text-slate-200 mt-2 truncate">{analysis.network_name || "—"}</div>
            </div>
            <div className="card">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Candidate Snapshot</div>
              <div className="text-sm font-mono text-slate-200 mt-2 truncate">{analysis.snapshot_name || "—"}</div>
            </div>
            <div className="card">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Nodes Parsed</div>
              <div className="text-2xl font-bold text-slate-100 mt-1">{(analysis.nodes || []).length}</div>
            </div>
            <div className="card">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Critical Violation</div>
              <div className={`text-2xl font-bold mt-1 ${analysis.critical_violation ? "text-red-400" : "text-emerald-400"}`}>
                {analysis.critical_violation ? "YES" : "NO"}
              </div>
            </div>
          </div>

          <div className="px-8 grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="card">
              <div className="font-semibold text-slate-200 mb-3">
                Reachability &amp; Behavioral Checks ({checks.length}
                {violations.length > 0 && <span className="text-red-400"> · {violations.length} violation(s)</span>})
              </div>
              <div className="space-y-2 max-h-[32rem] overflow-auto">
                {checks.length === 0 ? (
                  <EmptyState message="No behavioral checks were evaluated for this snapshot." />
                ) : (
                  checks.map((c) => <ReachabilityRow key={c.control_id} check={c} />)
                )}
              </div>
            </div>

            <div className="card">
              <div className="font-semibold text-slate-200 mb-3">
                Initialization Issues ({unsupported.length})
              </div>
              <div className="text-xs text-slate-500 mb-2">
                Parser warnings and unsupported syntax are always surfaced here — never silently treated as
                compliant (RULE 13).
              </div>
              <div className="space-y-2 max-h-[26rem] overflow-auto">
                {(analysis.init_issues || []).length === 0 ? (
                  <EmptyState message="No initialization issues reported." />
                ) : (
                  (analysis.init_issues || []).map((issue, i) => (
                    <div key={i} className="border border-soc-border rounded-lg p-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono text-xs text-slate-400">{issue.device || "—"}</span>
                        <StatusPill status={issue.status} />
                      </div>
                      {issue.line && <div className="text-xs font-mono text-slate-400 mt-1 truncate">{issue.line}</div>}
                      <div className="text-xs text-slate-300 mt-1">{issue.detail}</div>
                    </div>
                  ))
                )}
              </div>

              <div className="font-semibold text-slate-200 mt-6 mb-3">Nodes</div>
              <div className="flex flex-wrap gap-2">
                {(analysis.nodes || []).map((n) => (
                  <span key={n} className="px-2 py-1 rounded bg-slate-800 text-xs font-mono text-slate-300">
                    {n}
                  </span>
                ))}
                {(analysis.nodes || []).length === 0 && <span className="text-xs text-slate-500">No nodes parsed.</span>}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}