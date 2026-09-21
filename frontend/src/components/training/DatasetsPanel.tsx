import { useEffect, useState } from "react";
import { endpoints, DatasetVersion, TrainingExample } from "../../api";
import { Loading, EmptyState } from "../ui";
import { apiErrorMessage, statusClass } from "./shared";

/** Dataset versions: DRAFTs are edited in place; Finalize freezes one (so
 *  trained models stay traceable) and Clone starts a new draft from it. */
export default function DatasetsPanel({ onError, onChanged }: { onError: (m: string | null) => void; onChanged?: () => void }) {
  const [datasets, setDatasets] = useState<DatasetVersion[] | null>(null);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [members, setMembers] = useState<TrainingExample[] | null>(null);
  const [available, setAvailable] = useState<TrainingExample[] | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());

  const open = datasets?.find((d) => d.id === openId) || null;
  const editable = open?.status === "DRAFT";

  const loadList = () =>
    endpoints.datasets().then((r) => setDatasets(r.data)).catch((e) => { setDatasets([]); onError(apiErrorMessage(e, "Failed to load datasets.")); });

  const loadEditor = async (id: string, draft: boolean) => {
    setMembers(null);
    setAvailable(null);
    setPicked(new Set());
    try {
      const m = await endpoints.datasetExamples(id);
      setMembers(m.data);
      if (draft) {
        const v = await endpoints.trainingExamples("VALIDATED");
        const inSet = new Set(m.data.map((x) => x.id));
        setAvailable(v.data.filter((x) => !inSet.has(x.id)));
      } else setAvailable([]);
    } catch (e) {
      setMembers([]);
      setAvailable([]);
      onError(apiErrorMessage(e, "Failed to load dataset examples."));
    }
  };

  useEffect(() => { loadList(); }, []);
  useEffect(() => { if (openId && open) loadEditor(openId, open.status === "DRAFT"); }, [openId]); // eslint-disable-line

  async function run(key: string, fn: () => Promise<any>, failMsg: string, after?: () => void) {
    setBusy(key);
    onError(null);
    try {
      await fn();
      await loadList();
      after?.();
      onChanged?.();
    } catch (e) {
      onError(apiErrorMessage(e, failMsg));
    } finally {
      setBusy(null);
    }
  }

  const createDraft = () =>
    run("create", async () => {
      const r = await endpoints.createDatasetDraft(label.trim());
      setLabel("");
      setOpenId(r.data.id);
    }, "Failed to create draft.");

  const refreshEditor = () => { if (openId && open) loadEditor(openId, open.status === "DRAFT"); };

  return (
    <div>
      <p className="text-sm text-slate-400 mb-4 max-w-3xl">
        Build a dataset as a <b>draft</b>, add validated examples, then <b>finalize</b> it. Finalized versions are frozen so every
        trained model stays traceable to exactly the data it saw; to change one, <b>clone</b> it into a new draft.
      </p>
      <div className="mb-6 flex gap-4">
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="New draft label (e.g. v2-network-rules)"
          className="flex-1 bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm font-mono text-slate-200" />
        <button onClick={createDraft} disabled={busy === "create" || !label.trim()} className="btn-primary disabled:opacity-40 disabled:cursor-not-allowed">
          {busy === "create" ? "Creating…" : "New Draft"}
        </button>
      </div>

      {!datasets ? <Loading /> : datasets.length === 0 ? <EmptyState message="No datasets yet — create a draft above." /> : (
        <div className="overflow-hidden rounded-lg border border-soc-border mb-6">
          <table className="w-full text-left text-sm text-slate-400">
            <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
              <tr>
                <th className="px-4 py-3">Version</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Examples</th>
                <th className="px-4 py-3">Created</th><th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {datasets.map((d) => (
                <tr key={d.id} className={`hover:bg-soc-panel ${openId === d.id ? "bg-soc-panel" : ""}`}>
                  <td className="px-4 py-3 font-mono font-bold text-cyan-400">{d.version}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs ${statusClass(d.status)}`}>{d.status}</span></td>
                  <td className="px-4 py-3">{d.example_count}</td>
                  <td className="px-4 py-3">{d.created_at ? new Date(d.created_at).toLocaleString() : "—"}</td>
                  <td className="px-4 py-3 flex gap-3">
                    <button className="text-cyan-400 hover:underline" onClick={() => setOpenId(openId === d.id ? null : d.id)}>
                      {openId === d.id ? "Close" : d.status === "DRAFT" ? "Edit" : "View"}
                    </button>
                    {d.status === "FINALIZED" && (
                      <button className="text-amber-400 hover:underline" disabled={!!busy}
                        onClick={() => {
                          const l = window.prompt("Label for the new draft cloned from " + d.version + ":", d.version + "-next");
                          if (l && l.trim()) run("clone" + d.id, async () => { const r = await endpoints.cloneDataset(d.id, l.trim()); setOpenId(r.data.id); }, "Failed to clone dataset.");
                        }}>Clone</button>
                    )}
                    {d.status === "DRAFT" && (
                      <button className="text-red-400 hover:underline" disabled={!!busy}
                        onClick={() => { if (window.confirm(`Delete draft ${d.version}?`)) run("del" + d.id, () => endpoints.deleteDatasetDraft(d.id), "Failed to delete draft.", () => { if (openId === d.id) setOpenId(null); }); }}>
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open && (
        <div className="rounded-lg border border-soc-border bg-soc-panel p-4">
          <div className="flex items-center justify-between gap-4 flex-wrap mb-3">
            <div>
              <div className="font-mono font-bold text-cyan-400">{open.version}</div>
              <div className="text-xs text-slate-400">
                {open.status === "DRAFT" ? "Draft — editable" : `Finalized ${open.finalized_at ? new Date(open.finalized_at).toLocaleString() : ""} — read only`}
                {open.dataset_hash && <> · hash <span className="font-mono">{open.dataset_hash.slice(0, 12)}…</span></>}
              </div>
            </div>
            {editable && (
              <button disabled={!!busy || !open.example_count} className="btn-primary disabled:opacity-40 disabled:cursor-not-allowed"
                onClick={() => { if (window.confirm(`Finalize ${open.version}? It becomes read-only.`)) run("fin", () => endpoints.finalizeDataset(open.id), "Failed to finalize dataset.", refreshEditor); }}>
                {busy === "fin" ? "Finalizing…" : "Finalize"}
              </button>
            )}
          </div>

          {Object.keys(open.label_distribution || {}).length > 0 && (
            <div className="flex flex-wrap gap-2 mb-3">
              {Object.entries(open.label_distribution).map(([k, v]) => (
                <span key={k} className="px-2 py-0.5 rounded bg-slate-500/20 text-slate-300 text-xs font-mono">{k}: {v}</span>
              ))}
            </div>
          )}

          <h4 className="text-sm font-semibold text-slate-200 mb-2">Members ({members?.length ?? "…"})</h4>
          {!members ? <Loading /> : members.length === 0 ? <p className="text-sm text-slate-400 mb-4">No examples yet.</p> : (
            <ul className="divide-y divide-soc-border mb-4 max-h-72 overflow-auto">
              {members.map((ex) => (
                <li key={ex.id} className="py-2 flex items-center justify-between gap-3 text-sm">
                  <div className="min-w-0">
                    <div className="font-mono text-slate-200 truncate">{ex.raw_config_redacted}</div>
                    <div className="text-xs text-slate-400">{ex.vendor || "—"} · <span className="font-mono">{ex.intent || "UNKNOWN"}</span> · {ex.human_action}</div>
                  </div>
                  {editable && (
                    <button className="text-red-400 hover:underline shrink-0" disabled={!!busy}
                      onClick={() => run("rm" + ex.id, () => endpoints.removeDatasetExample(open.id, ex.id), "Failed to remove example.", refreshEditor)}>Remove</button>
                  )}
                </li>
              ))}
            </ul>
          )}

          {editable && (
            <>
              <h4 className="text-sm font-semibold text-slate-200 mb-2">Add validated examples</h4>
              {!available ? <Loading /> : available.length === 0 ? (
                <p className="text-sm text-slate-400">No other validated examples. Validate some on the Training Examples tab first.</p>
              ) : (
                <>
                  <ul className="divide-y divide-soc-border max-h-72 overflow-auto mb-3">
                    {available.map((ex) => (
                      <li key={ex.id} className="py-2 flex items-center gap-3 text-sm">
                        <input type="checkbox" checked={picked.has(ex.id)}
                          onChange={() => setPicked((p) => { const n = new Set(p); n.has(ex.id) ? n.delete(ex.id) : n.add(ex.id); return n; })} />
                        <div className="min-w-0">
                          <div className="font-mono text-slate-200 truncate">{ex.raw_config_redacted}</div>
                          <div className="text-xs text-slate-400">{ex.vendor || "—"} · <span className="font-mono">{ex.intent || "UNKNOWN"}</span> · {ex.human_action}</div>
                        </div>
                      </li>
                    ))}
                  </ul>
                  <div className="flex gap-3">
                    <button className="btn-primary disabled:opacity-40" disabled={!picked.size || !!busy}
                      onClick={() => run("add", () => endpoints.addDatasetExamples(open.id, [...picked]), "Failed to add examples.", refreshEditor)}>
                      Add {picked.size || ""} selected
                    </button>
                    <button className="text-cyan-400 hover:underline text-sm" onClick={() => setPicked(new Set(available.map((x) => x.id)))}>Select all</button>
                  </div>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
