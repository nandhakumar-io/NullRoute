import { useEffect, useState } from "react";
import { endpoints, CommandMapping } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

export default function KnowledgeBase() {
  const [mappings, setMappings] = useState<CommandMapping[] | null>(null);

  useEffect(() => {
    endpoints.approvedMappings().then((r) => setMappings(r.data));
  }, []);

  return (
    <div>
      <PageHeader
        title="Knowledge Base"
        subtitle="Human-validated command mappings, retrievable via pgvector similarity search for future normalization"
      />
      <div className="px-8 pb-8">
        {!mappings ? (
          <Loading />
        ) : mappings.length === 0 ? (
          <EmptyState message="No approved mappings yet. Approve items in the Training Center to populate the knowledge base." />
        ) : (
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border">
                  <th className="py-2 pr-4">Vendor</th>
                  <th className="py-2 pr-4">Raw pattern</th>
                  <th className="py-2 pr-4">Normalized parameter</th>
                  <th className="py-2 pr-4">Example value</th>
                  <th className="py-2 pr-4">Confidence</th>
                  <th className="py-2 pr-4">Status</th>
                </tr>
              </thead>
              <tbody>
                {mappings.map((m) => (
                  <tr key={m.id} className="border-b border-soc-border/50 hover:bg-slate-800/30">
                    <td className="py-2 pr-4">{m.vendor}</td>
                    <td className="py-2 pr-4 font-mono text-xs max-w-xs truncate">{m.raw_command_pattern}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-cyan-400">{m.normalized_parameter}</td>
                    <td className="py-2 pr-4">{m.example_value}</td>
                    <td className="py-2 pr-4">{Math.round(m.confidence * 100)}%</td>
                    <td className="py-2 pr-4"><span className="badge badge-pass">{m.status}</span></td>
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
