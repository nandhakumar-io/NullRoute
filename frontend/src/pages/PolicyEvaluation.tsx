import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { endpoints, OpaAnalysis } from "../api";
import { PageHeader, Loading, EmptyState, ResultBadge, SeverityBadge } from "../components/ui";

type Finding = Record<string, any>;

const RESULT_OPTIONS = ["ALL", "PASS", "FAIL", "NOT_APPLICABLE", "REVIEW"];
const SEVERITY_OPTIONS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function PolicyEvaluation() {
  const { scanId } = useParams();
  const [analysis, setAnalysis] = useState<OpaAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [frameworkFilter, setFrameworkFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [resultFilter, setResultFilter] = useState("ALL");

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    endpoints
      .opaAnalysis(scanId)
      .then((r) => setAnalysis(r.data))
      .finally(() => setLoading(false));
  }, [scanId]);

  const findings: Finding[] = analysis?.findings || [];

  const frameworks = useMemo(
    () => ["ALL", ...Array.from(new Set(findings.map((f) => f.framework).filter(Boolean)))],
    [findings]
  );

  const filtered = findings.filter((f) => {
    if (frameworkFilter !== "ALL" && f.framework !== frameworkFilter) return false;
    if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
    if (resultFilter !== "ALL" && f.result !== resultFilter) return false;
    return true;
  });

  if (loading) return <Loading />;
  if (!analysis || analysis.decision === undefined) {
    return <EmptyState message="No OPA policy evaluation found for this scan yet." />;
  }

  const passed = findings.filter((f) => f.result === "PASS").length;
  const failed = findings.filter((f) => f.result === "FAIL").length;
  const notApplicable = findings.filter((f) => f.result === "NOT_APPLICABLE").length;
  const review = findings.filter((f) => f.result === "REVIEW").length;

  return (
    <div>
      <PageHeader
        title="Policy Evaluation"
        subtitle={
          <>
            OPA is the authoritative deterministic policy engine — decision{" "}
            <span className="text-slate-300 font-mono">{analysis.decision}</span>
            {" · "}policy {analysis.policy_version}
            {" · "}decision ID <span className="font-mono">{analysis.decision_id}</span>
          </>
        }
      />
      <div className="px-8 pb-8 space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="card">
            <div className="text-xs uppercase text-slate-500 font-semibold">Passed</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">{passed}</div>
          </div>
          <div className="card">
            <div className="text-xs uppercase text-slate-500 font-semibold">Failed</div>
            <div className="text-2xl font-bold text-red-400 mt-1">{failed}</div>
          </div>
          <div className="card">
            <div className="text-xs uppercase text-slate-500 font-semibold">Not Applicable</div>
            <div className="text-2xl font-bold text-slate-400 mt-1">{notApplicable}</div>
          </div>
          <div className="card">
            <div className="text-xs uppercase text-slate-500 font-semibold">Review</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">{review}</div>
          </div>
        </div>

        <div className="flex gap-3 flex-wrap items-center">
          <select className="select" value={frameworkFilter} onChange={(e) => setFrameworkFilter(e.target.value)}>
            {frameworks.map((f) => (
              <option key={f} value={f}>
                {f === "ALL" ? "All frameworks" : f}
              </option>
            ))}
          </select>
          <select className="select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s === "ALL" ? "All severities" : s}
              </option>
            ))}
          </select>
          <select className="select" value={resultFilter} onChange={(e) => setResultFilter(e.target.value)}>
            {RESULT_OPTIONS.map((r) => (
              <option key={r} value={r}>
                {r === "ALL" ? "All results" : r.replace("_", " ")}
              </option>
            ))}
          </select>
          <span className="text-xs text-slate-500">
            {filtered.length} of {findings.length} controls
          </span>
        </div>

        {filtered.length === 0 && <EmptyState message="No controls match the current filters." />}

        {filtered.map((f, i) => (
          <div
            key={f.control_id || i}
            className={`border rounded-lg p-3 ${
              f.result === "FAIL" ? "border-red-800/60 bg-red-950/20" : "border-soc-border"
            }`}
          >
            <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
              <span className="font-mono text-xs text-slate-400">{f.control_id}</span>
              <div className="flex gap-2 items-center">
                {f.severity && <SeverityBadge severity={f.severity} />}
                <ResultBadge result={f.result} />
              </div>
            </div>
            <div className="text-sm text-slate-300">{f.title}</div>
            {f.parameter && (
              <div className="text-xs text-slate-500 mt-1">
                {f.parameter} — expected <span className="text-slate-300">{String(f.expected)}</span>, actual{" "}
                <span className="text-slate-300">{String(f.actual)}</span>
              </div>
            )}
            {f.reason && <div className="text-xs text-slate-500 mt-1">{f.reason}</div>}
            {f.remediation && <div className="text-xs font-mono text-cyan-400/80 mt-1">{f.remediation}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}
