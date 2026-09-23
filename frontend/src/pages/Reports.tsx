import { useEffect, useState } from "react";
import { endpoints, Scan } from "../api";
import { PageHeader, Loading, EmptyState, StatusBadge } from "../components/ui";

export default function Reports() {
  const [scans, setScans] = useState<Scan[] | null>(null);

  useEffect(() => {
    endpoints.scans().then((r) => setScans(r.data));
  }, []);

  return (
    <div>
      <PageHeader title="Reports" subtitle="Generate PDF, JSON, or CSV compliance reports for any completed scan" />
      <div className="px-8 pb-8">
        {!scans ? (
          <Loading />
        ) : scans.length === 0 ? (
          <EmptyState message="No scans yet." />
        ) : (
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border">
                  <th className="py-2 pr-4">Scan</th>
                  <th className="py-2 pr-4">Framework</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Score</th>
                  <th className="py-2 pr-4">Date</th>
                  <th className="py-2 pr-4">Reports</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id} className="border-b border-soc-border/50 hover:bg-slate-800/30">
                    <td className="py-2 pr-4 font-mono text-xs">{s.id.slice(0, 8)}</td>
                    <td className="py-2 pr-4">{s.framework}</td>
                    <td className="py-2 pr-4"><StatusBadge status={s.status} /></td>
                    <td className="py-2 pr-4 font-semibold">{s.compliance_score ?? "—"}%</td>
                    <td className="py-2 pr-4 text-slate-500">{new Date(s.created_at).toLocaleString()}</td>
                    <td className="py-2 pr-4 space-x-3">
                      {s.compliance_score != null || s.status === "completed" ? (
                        <>
                          <button className="text-cyan-400 hover:underline bg-transparent border-none p-0 cursor-pointer text-sm" onClick={() => endpoints.downloadReport(s.id, "pdf")}>PDF</button>
                          <button className="text-cyan-400 hover:underline bg-transparent border-none p-0 cursor-pointer text-sm" onClick={() => endpoints.downloadReport(s.id, "json")}>JSON</button>
                          <button className="text-cyan-400 hover:underline bg-transparent border-none p-0 cursor-pointer text-sm" onClick={() => endpoints.downloadReport(s.id, "csv")}>CSV</button>
                        </>
                      ) : (
                        <>
                          <span className="text-slate-500 cursor-not-allowed" title="Not available until scan completes">PDF</span>
                          <span className="text-slate-500 cursor-not-allowed" title="Not available until scan completes">JSON</span>
                          <span className="text-slate-500 cursor-not-allowed" title="Not available until scan completes">CSV</span>
                        </>
                      )}
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
