import { useEffect, useState } from "react";
import { endpoints, DatasetVersion, TrainingJob } from "../../api";
import { Loading, EmptyState } from "../ui";
import { apiErrorMessage, statusClass } from "./shared";

export default function JobsPanel({ onError }: { onError: (m: string | null) => void }) {
  const [jobs, setJobs] = useState<TrainingJob[] | null>(null);
  const [datasets, setDatasets] = useState<DatasetVersion[]>([]);
  const [datasetId, setDatasetId] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => {
    endpoints.trainingJobs().then((r) => setJobs(r.data)).catch((e) => { setJobs([]); onError(apiErrorMessage(e, "Failed to load training jobs.")); });
    endpoints.datasets().then((r) => setDatasets(r.data.filter((d) => d.status === "FINALIZED"))).catch(() => {});
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []); // eslint-disable-line

  const label = (id: string) => datasets.find((d) => d.id === id)?.version || id.split("-")[0];

  async function act(key: string, fn: () => Promise<any>, fail: string) {
    setBusy(key);
    onError(null);
    try { await fn(); load(); } catch (e) { onError(apiErrorMessage(e, fail)); } finally { setBusy(null); }
  }

  return (
    <div>
      <p className="text-sm text-slate-400 mb-4 max-w-3xl">
        Jobs run on the training worker, not in your browser — a queued job starts on its own. Only finalized datasets can be trained on.
      </p>
      <div className="mb-6 flex gap-4">
        <select value={datasetId} onChange={(e) => setDatasetId(e.target.value)}
          className="flex-1 bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200">
          <option value="">{datasets.length ? "Select a finalized dataset…" : "No finalized datasets — finalize one first"}</option>
          {datasets.map((d) => <option key={d.id} value={d.id}>{d.version} ({d.example_count} examples)</option>)}
        </select>
        <button disabled={!datasetId || busy === "create"} className="btn-primary disabled:opacity-40 disabled:cursor-not-allowed"
          onClick={() => act("create", async () => { await endpoints.createTrainingJob(datasetId); setDatasetId(""); }, "Failed to create training job.")}>
          {busy === "create" ? "Creating…" : "Queue Training Job"}
        </button>
      </div>

      {!jobs ? <Loading /> : jobs.length === 0 ? <EmptyState message="No training jobs yet." /> : (
        <div className="overflow-hidden rounded-lg border border-soc-border">
          <table className="w-full text-left text-sm text-slate-400">
            <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
              <tr><th className="px-4 py-3">Job</th><th className="px-4 py-3">Dataset</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Result</th><th className="px-4 py-3">Actions</th></tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {jobs.map((j) => (
                <tr key={j.id} className="hover:bg-soc-panel align-top">
                  <td className="px-4 py-3 font-mono">{j.id.split("-")[0]}</td>
                  <td className="px-4 py-3 font-mono">{label(j.dataset_version_id)}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs ${statusClass(j.status)}`}>{j.status}</span></td>
                  <td className="px-4 py-3 text-xs">
                    {j.status === "COMPLETED" && j.metrics && (
                      <>macro F1 {j.metrics.macro_f1} · {j.metrics.known_intents_covered ?? "?"}/{j.metrics.known_intents_total ?? 13} known intents</>
                    )}
                    {j.status === "FAILED" && <span className="text-red-400 break-words">{j.error}</span>}
                    {j.status === "RUNNING" && "Training in progress…"}
                    {j.status === "QUEUED" && "Waiting for the training worker"}
                  </td>
                  <td className="px-4 py-3 flex gap-3">
                    {j.status === "QUEUED" && <button className="text-amber-400 hover:underline" disabled={!!busy} onClick={() => act(j.id, () => endpoints.cancelTrainingJob(j.id), "Failed to cancel job.")}>Cancel</button>}
                    {(j.status === "FAILED" || j.status === "CANCELLED") && <button className="text-cyan-400 hover:underline" disabled={!!busy} onClick={() => act(j.id, () => endpoints.retryTrainingJob(j.id), "Failed to retry job.")}>Retry</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
