import { useEffect, useState } from "react";
import { endpoints, CommandMapping } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

export default function TrainingCenter() {
  const [pending, setPending] = useState<CommandMapping[] | null>(null);
  const [edits, setEdits] = useState<Record<string, string>>({});

  function load() {
    endpoints.pendingMappings().then((r) => setPending(r.data));
  }

  useEffect(load, []);

  async function review(id: string, action: "approve" | "reject") {
    await endpoints.reviewMapping(id, action, edits[id]);
    load();
  }

  return (
    <div>
      <PageHeader
        title="Training Center"
        subtitle="Review AI-suggested interpretations of unknown configuration syntax below the confidence threshold"
      />
      <div className="px-8 pb-8">
        {!pending ? (
          <Loading />
        ) : pending.length === 0 ? (
          <EmptyState message="No unknown commands awaiting review. The AI is confident about everything it has seen so far." />
        ) : (
          <div className="space-y-4">
            {pending.map((m) => (
              <div key={m.id} className="card">
                <div className="flex items-start justify-between gap-6">
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-slate-500 mb-1">Unknown command · {m.vendor}</div>
                    <pre className="bg-black/40 rounded-lg px-3 py-2 text-sm text-amber-300 overflow-x-auto">{m.raw_command_pattern}</pre>

                    <div className="mt-3 text-xs text-slate-500">AI suggestion</div>
                    <div className="text-sm text-slate-300">{m.ai_suggested_meaning}</div>

                    <div className="mt-3 flex items-center gap-4 text-xs text-slate-500">
                      <span>Confidence: <span className="text-amber-400 font-semibold">{Math.round(m.confidence * 100)}%</span></span>
                      <span>Example value: <span className="text-slate-300">{m.example_value}</span></span>
                    </div>

                    <div className="mt-3">
                      <label className="block text-xs text-slate-500 mb-1">Mapped security parameter</label>
                      <input
                        defaultValue={m.normalized_parameter}
                        onChange={(e) => setEdits((prev) => ({ ...prev, [m.id]: e.target.value }))}
                        className="w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-600 font-mono"
                      />
                    </div>
                  </div>

                  <div className="flex flex-col gap-2 shrink-0">
                    <button onClick={() => review(m.id, "approve")} className="btn-primary text-sm">✓ Approve</button>
                    <button onClick={() => review(m.id, "reject")} className="btn-secondary text-sm">✕ Reject</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
