import { useEffect, useState } from "react";
import { endpoints, ModelRegistryEntry } from "../../api";
import { Loading, EmptyState } from "../ui";
import { apiErrorMessage, statusClass } from "./shared";

export default function ModelsPanel({ onError }: { onError: (m: string | null) => void }) {
  const [models, setModels] = useState<ModelRegistryEntry[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => endpoints.registryModels().then((r) => setModels(r.data)).catch((e) => { setModels([]); onError(apiErrorMessage(e, "Failed to load model registry.")); });
  useEffect(() => { load(); }, []); // eslint-disable-line

  async function act(id: string, action: "approve" | "reject" | "promote" | "rollback") {
    setBusy(id);
    onError(null);
    try {
      if (action === "approve") await endpoints.approveModel(id);
      else if (action === "reject") await endpoints.rejectModel(id);
      else if (action === "promote") await endpoints.promoteModel(id);
      else await endpoints.rollbackModel(id);
    } catch (e) {
      onError(apiErrorMessage(e, `Failed to ${action} model.`));
    } finally {
      setBusy(null);
      load(); // a failed approve can still flip the model to REJECTED (regression gate)
    }
  }

  if (!models) return <Loading />;
  if (models.length === 0) return <EmptyState message="No models in registry yet — a completed training job registers a candidate here." />;

  return (
    <div className="overflow-hidden rounded-lg border border-soc-border">
      <table className="w-full text-left text-sm text-slate-400">
        <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
          <tr>
            <th className="px-4 py-3">Model</th><th className="px-4 py-3">Dataset</th><th className="px-4 py-3">Metrics</th>
            <th className="px-4 py-3">Intent coverage</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-soc-border">
          {models.map((m) => {
            const total = m.known_intents_total ?? 13;
            const covered = m.known_intents_covered;
            return (
              <tr key={m.id} className="hover:bg-soc-panel align-top">
                <td className="px-4 py-3"><div className="font-mono text-slate-200">{m.model_name}</div><div className="text-xs">{m.model_type}</div></td>
                <td className="px-4 py-3 font-mono">{m.dataset_version}</td>
                <td className="px-4 py-3 text-xs">macro F1 {m.metrics?.macro_f1 ?? "—"}<br />unknown F1 {m.metrics?.unknown_f1 ?? "—"}</td>
                <td className="px-4 py-3 text-xs">
                  {covered == null ? "—" : (
                    <>
                      <span className={covered < total ? "text-amber-400" : "text-emerald-400"}>{covered}/{total} known intents</span>
                      {m.known_intents_missing && m.known_intents_missing.length > 0 && (
                        <div title={m.known_intents_missing.join(", ")} className="text-slate-400 cursor-help">
                          missing: {m.known_intents_missing.slice(0, 3).join(", ")}{m.known_intents_missing.length > 3 ? ` +${m.known_intents_missing.length - 3}` : ""}
                        </div>
                      )}
                    </>
                  )}
                </td>
                <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs ${statusClass(m.status)}`}>{m.status}</span></td>
                <td className="px-4 py-3 flex gap-3">
                  {busy === m.id ? <span className="text-slate-500 text-xs">Working…</span> : (
                    <>
                      {m.status === "CANDIDATE" && (<>
                        <button onClick={() => act(m.id, "approve")} className="text-emerald-400 hover:underline">Approve</button>
                        <button onClick={() => act(m.id, "reject")} className="text-red-400 hover:underline">Reject</button>
                      </>)}
                      {m.status === "APPROVED" && <button onClick={() => act(m.id, "promote")} className="text-cyan-400 font-bold hover:underline">Promote to Prod</button>}
                      {/* Rollback means "make THIS earlier model production again", so it lives on ARCHIVED rows, never on the current PRODUCTION row. */}
                      {m.status === "ARCHIVED" && (
                        <button onClick={() => { if (window.confirm(`Roll back to ${m.model_name}? It replaces the current production model.`)) act(m.id, "rollback"); }}
                          className="text-amber-400 hover:underline">Roll back to this</button>
                      )}
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
