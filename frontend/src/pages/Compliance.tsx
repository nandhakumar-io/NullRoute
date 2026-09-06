import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, Finding, Device } from "../api";
import { PageHeader, Loading, EmptyState, SeverityBadge, ResultBadge } from "../components/ui";

const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const RESULTS = ["", "FAIL", "PASS", "NOT_APPLICABLE"];
const FRAMEWORKS = ["", "CIS", "NIST", "DISA_STIG", "ISO_27001", "ALL"];

function ExpandedRow({ finding }: { finding: any }) {
  return (
    <tr className="bg-slate-900/50 border-b border-soc-border/50">
      <td colSpan={9} className="px-6 py-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <div className="text-xs font-semibold text-slate-500 uppercase mb-1">Expected Value</div>
            <div className="font-mono text-xs text-slate-300 bg-slate-800/60 rounded px-2 py-1 whitespace-pre-wrap break-all">
              {finding.expected_value ?? "—"}
            </div>
          </div>
          <div>
            <div className="text-xs font-semibold text-slate-500 uppercase mb-1">Actual Value</div>
            <div className={`font-mono text-xs rounded px-2 py-1 whitespace-pre-wrap break-all ${
              finding.result === "FAIL" ? "bg-red-950/40 text-red-300" : "bg-slate-800/60 text-slate-300"
            }`}>
              {finding.actual_value ?? "—"}
            </div>
          </div>
          {finding.evidence_line && (
            <div className="md:col-span-2">
              <div className="text-xs font-semibold text-slate-500 uppercase mb-1">Evidence</div>
              <div className="font-mono text-xs text-slate-400 bg-slate-800/60 rounded px-2 py-1 whitespace-pre-wrap break-all">{finding.evidence_line}</div>
            </div>
          )}
          {finding.remediation && (
            <div className="md:col-span-2">
              <div className="text-xs font-semibold text-slate-500 uppercase mb-1">Remediation</div>
              <div className="text-slate-300 text-sm">{finding.remediation}</div>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}

export default function Compliance() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [severity, setSeverity] = useState("");
  const [result, setResult] = useState("FAIL");
  const [framework, setFramework] = useState("");
  const [scanId, setScanId] = useState("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState("");

  useEffect(() => {
    endpoints.devices({ limit: 500 })
      .then((r) => {
        const items = (r.data as any).items ?? r.data;
        setDevices(Array.isArray(items) ? items : []);
      })
      .catch(() => {});
  }, []);

  const load = useCallback(() => {
    setFindings(null);
    endpoints.findings({
      severity: severity || undefined,
      result: result || undefined,
      scan_id: scanId || undefined,
    }).then((r) => {
      let data = Array.isArray(r.data) ? r.data as Finding[] : [];
      // Client-side: filter by framework + device (scan-level)
      if (framework) data = data.filter((f: any) => f.framework === framework);
      if (search.trim()) {
        const q = search.trim().toLowerCase();
        data = data.filter((f: any) =>
          f.title?.toLowerCase().includes(q) ||
          f.control_id?.toLowerCase().includes(q) ||
          f.parameter?.toLowerCase().includes(q) ||
          f.remediation?.toLowerCase().includes(q)
        );
      }
      setFindings(data);
    }).catch(() => setFindings([]));
  }, [severity, result, framework, scanId, search]);

  useEffect(() => {
    load();
  }, [load]);

  const toggleExpand = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const critCount = findings?.filter((f: any) => f.severity === "CRITICAL" && f.result === "FAIL").length ?? 0;
  const highCount = findings?.filter((f: any) => f.severity === "HIGH" && f.result === "FAIL").length ?? 0;
  const passCount = findings?.filter((f: any) => f.result === "PASS").length ?? 0;
  const totalCount = findings?.length ?? 0;

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle="Cross-framework compliance findings from OPA, Batfish, and AI analysis"
      />

      {/* Quick stats */}
      {findings && findings.length > 0 && (
        <div className="px-8 mb-4 flex gap-3 flex-wrap">
          <div className="card py-2 px-4 flex items-center gap-2">
            <span className="text-xs text-slate-500 font-semibold uppercase">Total</span>
            <span className="font-bold text-slate-200">{totalCount}</span>
          </div>
          <div className="card py-2 px-4 flex items-center gap-2">
            <span className="text-xs text-red-500 font-semibold uppercase">Critical Fails</span>
            <span className="font-bold text-red-400">{critCount}</span>
          </div>
          <div className="card py-2 px-4 flex items-center gap-2">
            <span className="text-xs text-orange-500 font-semibold uppercase">High Fails</span>
            <span className="font-bold text-orange-400">{highCount}</span>
          </div>
          <div className="card py-2 px-4 flex items-center gap-2">
            <span className="text-xs text-emerald-500 font-semibold uppercase">Passed</span>
            <span className="font-bold text-emerald-400">{passCount}</span>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="px-8 flex flex-wrap gap-2 mb-4">
        <input
          className="input text-sm w-48"
          placeholder="Search title, control, param…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select className="select text-sm" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {SEVERITIES.filter(Boolean).map((s) => <option key={s} value={s}>{s.charAt(0) + s.slice(1).toLowerCase()}</option>)}
        </select>
        <select className="select text-sm" value={result} onChange={(e) => setResult(e.target.value)}>
          <option value="">All results</option>
          {RESULTS.filter(Boolean).map((r) => <option key={r} value={r}>{r === "NOT_APPLICABLE" ? "N/A" : r.charAt(0) + r.slice(1).toLowerCase()}</option>)}
        </select>
        <select className="select text-sm" value={framework} onChange={(e) => setFramework(e.target.value)}>
          <option value="">All frameworks</option>
          {FRAMEWORKS.filter(Boolean).map((f) => <option key={f} value={f}>{f}</option>)}
        </select>
        <input
          className="input text-sm w-56 font-mono"
          placeholder="Scan ID (optional)"
          value={scanId}
          onChange={(e) => setScanId(e.target.value)}
        />
        {(severity || result || framework || scanId || search) && (
          <button
            className="btn-secondary text-sm"
            onClick={() => { setSeverity(""); setResult("FAIL"); setFramework(""); setScanId(""); setSearch(""); }}
          >
            Reset
          </button>
        )}
      </div>

      <div className="px-8 pb-8">
        {!findings ? (
          <Loading />
        ) : findings.length === 0 ? (
          <EmptyState message="No findings match the current filters." />
        ) : (
          <div className="card p-0 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border text-xs uppercase tracking-wide">
                  <th className="px-4 py-3 w-6"></th>
                  <th className="px-4 py-3">Framework</th>
                  <th className="px-4 py-3">Control</th>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Result</th>
                  <th className="px-4 py-3">Parameter</th>
                  <th className="px-4 py-3">Scan</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f: any) => (
                  <>
                    <tr
                      key={f.id}
                      onClick={() => toggleExpand(f.id)}
                      className={`border-b border-soc-border/50 cursor-pointer transition-colors ${
                        expanded.has(f.id) ? "bg-slate-800/40" : "hover:bg-slate-800/20"
                      } ${f.severity === "CRITICAL" && f.result === "FAIL" ? "border-l-2 border-red-700" : ""}`}
                    >
                      <td className="px-4 py-3 text-slate-500 text-center">
                        <span className="text-xs">{expanded.has(f.id) ? "▾" : "▸"}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="badge bg-slate-800 text-slate-300 border border-slate-700">{f.framework}</span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-cyan-400">{f.control_id}</td>
                      <td className="px-4 py-3 max-w-[240px] truncate text-slate-200" title={f.title}>{f.title}</td>
                      <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                      <td className="px-4 py-3"><ResultBadge result={f.presentation_result || f.result} /></td>
                      <td className="px-4 py-3 max-w-[160px] truncate text-slate-400 text-xs" title={f.parameter}>{f.parameter}</td>
                      <td className="px-4 py-3">
                        {f.scan_id && (
                          <Link
                            className="text-cyan-400 hover:underline text-xs font-mono"
                            to={`/scans/${f.scan_id}`}
                            onClick={(e) => e.stopPropagation()}
                          >
                            {f.scan_id.slice(0, 8)}
                          </Link>
                        )}
                      </td>
                    </tr>
                    {expanded.has(f.id) && <ExpandedRow key={`${f.id}-exp`} finding={f} />}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
