import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, Finding } from "../api";
import { PageHeader, Loading, EmptyState, SeverityBadge, ResultBadge } from "../components/ui";

export default function Compliance() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [severity, setSeverity] = useState("");
  const [result, setResult] = useState("");

  useEffect(() => {
    endpoints.findings({ severity: severity || undefined, result: result || undefined }).then((r) => setFindings(r.data));
  }, [severity, result]);

  return (
    <div>
      <PageHeader title="Compliance" subtitle="Findings across all frameworks: CIS, NIST SP 800-53, DISA STIG, ISO/IEC 27001" />
      <div className="px-8 flex gap-3 mb-4">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm">
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select value={result} onChange={(e) => setResult(e.target.value)} className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm">
          <option value="">All results</option>
          <option value="PASS">Pass</option>
          <option value="FAIL">Fail</option>
          <option value="NOT_APPLICABLE">Not applicable</option>
        </select>
      </div>

      <div className="px-8 pb-8">
        {!findings ? (
          <Loading />
        ) : findings.length === 0 ? (
          <EmptyState message="No findings match the current filters." />
        ) : (
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border">
                  <th className="py-2 pr-4">Framework</th>
                  <th className="py-2 pr-4">Control</th>
                  <th className="py-2 pr-4">Title</th>
                  <th className="py-2 pr-4">Severity</th>
                  <th className="py-2 pr-4">Result</th>
                  <th className="py-2 pr-4">Expected</th>
                  <th className="py-2 pr-4">Actual</th>
                  <th className="py-2 pr-4">Scan</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f: any) => (
                  <tr key={f.id} className="border-b border-soc-border/50 hover:bg-slate-800/30">
                    <td className="py-2 pr-4">{f.framework}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{f.control_id}</td>
                    <td className="py-2 pr-4">{f.title}</td>
                    <td className="py-2 pr-4"><SeverityBadge severity={f.severity} /></td>
                    <td className="py-2 pr-4"><ResultBadge result={f.result} /></td>
                    <td className="py-2 pr-4 text-slate-400">{f.expected_value}</td>
                    <td className="py-2 pr-4 text-slate-400">{f.actual_value}</td>
                    <td className="py-2 pr-4">
                      {f.scan_id && <Link className="text-cyan-400 hover:underline text-xs" to={`/scans/${f.scan_id}`}>view</Link>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
