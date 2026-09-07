import { useEffect, useState } from "react";
import { endpoints, AuditLogEntry } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

const RESULT_TONE: Record<string, string> = {
  SUCCESS: "text-emerald-400",
  FAILURE: "text-red-400",
  DENIED: "text-amber-400",
};

export default function AuditLogPage() {
  const [rows, setRows] = useState<AuditLogEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({ action: "", object_type: "", result: "", since: "", until: "" });
  const [exporting, setExporting] = useState(false);

  const getCleanParams = () => ({
    action: filters.action || undefined,
    object_type: filters.object_type || undefined,
    result: filters.result || undefined,
    since: filters.since ? new Date(filters.since).toISOString() : undefined,
    until: filters.until ? new Date(filters.until).toISOString() : undefined,
    limit: 200,
  });

  const load = () => {
    setRows(null);
    setError(null);
    endpoints
      .auditLog(getCleanParams())
      .then((r) => setRows(r.data))
      .catch((e) => {
        if (e?.response?.status === 403) {
          setError("You don't have permission to view the audit log (requires the Auditor, Tenant Admin, or Super Admin role).");
        } else {
          setError("Failed to load the audit log.");
        }
        setRows([]);
      });
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleExport = async (format: "csv" | "json") => {
    if (exporting) return;
    setExporting(true);
    try {
      const res = await endpoints.exportAuditLog(format, getCleanParams());
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `audit-log-${new Date().toISOString().replace(/[:.]/g, "-")}.${format}`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (e: any) {
      setError("Failed to export Audit Log.");
    } finally {
      setExporting(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="Audit Log"
        subtitle="Who did what, when, from where — every config upload, scan, compliance change, AI mapping approval, remediation approval, credential operation, and report download."
        action={
          <div className="flex gap-2">
            <button onClick={() => handleExport("csv")} className="btn-secondary" disabled={exporting}>
              Export CSV
            </button>
            <button onClick={() => handleExport("json")} className="btn-secondary" disabled={exporting}>
              Export JSON
            </button>
          </div>
        }
      />

      <div className="px-8 flex flex-wrap gap-3 mb-4">
        <input
          className="input"
          placeholder="Filter by action (e.g. scan.upload)"
          value={filters.action}
          onChange={(e) => setFilters((f) => ({ ...f, action: e.target.value }))}
        />
        <input
          className="input"
          placeholder="Filter by object type (e.g. credential)"
          value={filters.object_type}
          onChange={(e) => setFilters((f) => ({ ...f, object_type: e.target.value }))}
        />
        <select
          className="select"
          value={filters.result}
          onChange={(e) => setFilters((f) => ({ ...f, result: e.target.value }))}
        >
          <option value="">Any result</option>
          <option value="SUCCESS">Success</option>
          <option value="FAILURE">Failure</option>
          <option value="DENIED">Denied</option>
        </select>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 font-semibold uppercase">Since</span>
          <input type="datetime-local" className="input text-sm" value={filters.since} onChange={(e) => setFilters((f) => ({ ...f, since: e.target.value }))} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 font-semibold uppercase">Until</span>
          <input type="datetime-local" className="input text-sm" value={filters.until} onChange={(e) => setFilters((f) => ({ ...f, until: e.target.value }))} />
        </div>
        <button className="btn-primary" onClick={load}>
          Apply filters
        </button>
      </div>

      <div className="px-8 pb-8">
        {rows === null ? (
          <Loading />
        ) : error ? (
          <EmptyState message={error} />
        ) : rows.length === 0 ? (
          <EmptyState message="No audit events match these filters yet." />
        ) : (
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 uppercase text-xs tracking-wide border-b border-soc-border">
                  <th className="py-2 pr-4">When</th>
                  <th className="py-2 pr-4">Who</th>
                  <th className="py-2 pr-4">Action</th>
                  <th className="py-2 pr-4">Object</th>
                  <th className="py-2 pr-4">Source IP</th>
                  <th className="py-2 pr-4">Result</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id} className="border-b border-soc-border/50 hover:bg-slate-800/30">
                    <td className="py-2 pr-4 text-slate-400 font-mono text-xs whitespace-nowrap">
                      {new Date(row.created_at).toLocaleString()}
                    </td>
                    <td className="py-2 pr-4 text-slate-300">{row.username || "—"}</td>
                    <td className="py-2 pr-4 text-cyan-300 font-mono text-xs">{row.action}</td>
                    <td className="py-2 pr-4 text-slate-400 font-mono text-xs">
                      {row.object_type ? `${row.object_type}${row.object_id ? ` / ${row.object_id.slice(0, 8)}` : ""}` : "—"}
                    </td>
                    <td className="py-2 pr-4 text-slate-500 font-mono text-xs">{row.source_ip || "—"}</td>
                    <td className={`py-2 pr-4 font-semibold ${RESULT_TONE[row.result || ""] || "text-slate-400"}`}>
                      {row.result || "—"}
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