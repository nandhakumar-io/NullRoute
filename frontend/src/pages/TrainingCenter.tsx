import { useEffect, useState } from "react";
import { 
  endpoints, 
  CommandMapping, 
  DatasetVersion, 
  TrainingJob, 
  ModelRegistryEntry 
} from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

export default function TrainingCenter() {
  const [activeTab, setActiveTab] = useState<"reviews" | "datasets" | "jobs" | "models">("reviews");

  // Reviews Tab state
  const [pending, setPending] = useState<CommandMapping[] | null>(null);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [correctionReasons, setCorrectionReasons] = useState<Record<string, string>>({});

  // Datasets Tab state
  const [datasets, setDatasets] = useState<DatasetVersion[] | null>(null);
  const [newDatasetLabel, setNewDatasetLabel] = useState("");

  // Jobs Tab state
  const [jobs, setJobs] = useState<TrainingJob[] | null>(null);
  const [selectedDatasetForJob, setSelectedDatasetForJob] = useState("");

  // Models Tab state
  const [models, setModels] = useState<ModelRegistryEntry[] | null>(null);

  function load() {
    if (activeTab === "reviews") {
      endpoints.pendingMappings().then((r) => setPending(r.data));
    } else if (activeTab === "datasets") {
      endpoints.datasets().then((r) => setDatasets(r.data));
    } else if (activeTab === "jobs") {
      endpoints.trainingJobs().then((r) => setJobs(r.data));
    } else if (activeTab === "models") {
      endpoints.registryModels().then((r) => setModels(r.data));
    }
  }

  useEffect(() => {
    load();
  }, [activeTab]);

  // --- Reviews Tab ---
  async function review(id: string, action: "approve" | "correct" | "reject") {
    await endpoints.reviewMapping(id, { 
      action, 
      normalized_parameter: edits[id] ? edits[id] : undefined,
      normalized_facts: edits[id] ? { [edits[id]]: "some_value" } : undefined, // simplified for ui
      correction_reason: correctionReasons[id]
    });
    load();
  }

  // --- Datasets Tab ---
  async function createDataset() {
    if (!newDatasetLabel) return;
    await endpoints.createDataset(newDatasetLabel);
    setNewDatasetLabel("");
    load();
  }

  // --- Jobs Tab ---
  async function createJob() {
    if (!selectedDatasetForJob) return;
    await endpoints.createTrainingJob(selectedDatasetForJob);
    load();
  }

  async function runJob(id: string) {
    await endpoints.runTrainingJob(id);
    load();
  }

  // --- Models Tab ---
  async function handleModelAction(id: string, action: "approve" | "reject" | "promote" | "rollback") {
    if (action === "approve") await endpoints.approveModel(id);
    else if (action === "reject") await endpoints.rejectModel(id);
    else if (action === "promote") await endpoints.promoteModel(id);
    else if (action === "rollback") await endpoints.rollbackModel(id);
    load();
  }

  return (
    <div>
      <PageHeader
        title="Training Center"
        subtitle="Manage the AI Human-in-the-Loop Feedback Architecture."
      />
      
      <div className="px-8 pb-4 border-b border-soc-border mb-6 flex gap-6">
        <button 
          onClick={() => setActiveTab("reviews")}
          className={`pb-2 font-medium ${activeTab === "reviews" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Human Review
        </button>
        <button 
          onClick={() => setActiveTab("datasets")}
          className={`pb-2 font-medium ${activeTab === "datasets" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Datasets
        </button>
        <button 
          onClick={() => setActiveTab("jobs")}
          className={`pb-2 font-medium ${activeTab === "jobs" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Training Jobs
        </button>
        <button 
          onClick={() => setActiveTab("models")}
          className={`pb-2 font-medium ${activeTab === "models" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Model Registry
        </button>
      </div>

      <div className="px-8 pb-8">
        {activeTab === "reviews" && (
          <div>
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
                        <pre className="bg-black/40 rounded-lg px-3 py-2 text-sm text-emerald-300 overflow-x-auto">{m.raw_command_pattern}</pre>

                        <div className="mt-3 text-xs text-slate-500">AI suggestion</div>
                        <div className="text-sm text-slate-300">{m.ai_suggested_meaning}</div>

                        <div className="mt-3 flex items-center gap-4 text-xs text-slate-500">
                          <span>Confidence: <span className="text-amber-400 font-semibold">{Math.round(m.confidence * 100)}%</span></span>
                          <span>Example value: <span className="text-slate-300">{m.example_value}</span></span>
                        </div>

                        <div className="mt-4">
                          <label className="block text-xs text-slate-500 mb-1">Correct mapped parameter (optional)</label>
                          <input
                            defaultValue={m.normalized_parameter}
                            onChange={(e) => setEdits((prev) => ({ ...prev, [m.id]: e.target.value }))}
                            className="w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600 font-mono"
                          />
                        </div>
                        <div className="mt-3">
                          <label className="block text-xs text-slate-500 mb-1">Reason for correction (required for corrections)</label>
                          <input
                            onChange={(e) => setCorrectionReasons((prev) => ({ ...prev, [m.id]: e.target.value }))}
                            className="w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600"
                            placeholder="Why was the AI wrong?"
                          />
                        </div>
                      </div>

                      <div className="flex flex-col gap-2 shrink-0 w-32">
                        <button onClick={() => review(m.id, "approve")} className="btn-primary text-sm w-full">✓ Approve</button>
                        <button onClick={() => review(m.id, "correct")} className="btn-secondary text-sm w-full bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30">✎ Correct</button>
                        <button onClick={() => review(m.id, "reject")} className="btn-secondary text-sm w-full">✕ Reject</button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === "datasets" && (
          <div>
            <div className="mb-6 flex gap-4">
              <input 
                value={newDatasetLabel}
                onChange={(e) => setNewDatasetLabel(e.target.value)}
                placeholder="Dataset Label (e.g. v2-network-rules)"
                className="flex-1 bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm font-mono text-slate-200"
              />
              <button onClick={createDataset} className="btn-primary">Compile Dataset</button>
            </div>
            
            {!datasets ? <Loading /> : datasets.length === 0 ? <EmptyState message="No datasets found." /> : (
              <div className="overflow-hidden rounded-lg border border-soc-border">
                <table className="w-full text-left text-sm text-slate-400">
                  <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
                    <tr>
                      <th className="px-4 py-3">Version</th>
                      <th className="px-4 py-3">Created</th>
                      <th className="px-4 py-3">Examples</th>
                      <th className="px-4 py-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-soc-border">
                    {datasets.map(d => (
                      <tr key={d.id} className="hover:bg-soc-panel">
                        <td className="px-4 py-3 font-mono font-bold text-cyan-400">{d.version}</td>
                        <td className="px-4 py-3">{new Date(d.created_at).toLocaleString()}</td>
                        <td className="px-4 py-3">{d.example_count}</td>
                        <td className="px-4 py-3 text-emerald-400">{d.validation_status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === "jobs" && (
          <div>
            <div className="mb-6 flex gap-4">
              <input 
                value={selectedDatasetForJob}
                onChange={(e) => setSelectedDatasetForJob(e.target.value)}
                placeholder="Dataset Version UUID"
                className="flex-1 bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm font-mono text-slate-200"
              />
              <button onClick={createJob} className="btn-primary">Create Training Job</button>
            </div>

            {!jobs ? <Loading /> : jobs.length === 0 ? <EmptyState message="No training jobs found." /> : (
              <div className="overflow-hidden rounded-lg border border-soc-border">
                <table className="w-full text-left text-sm text-slate-400">
                  <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
                    <tr>
                      <th className="px-4 py-3">Job ID</th>
                      <th className="px-4 py-3">Dataset Version</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-soc-border">
                    {jobs.map(j => (
                      <tr key={j.id} className="hover:bg-soc-panel">
                        <td className="px-4 py-3 font-mono">{j.id.split("-")[0]}</td>
                        <td className="px-4 py-3">{j.dataset_version_id}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            j.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-400' : 
                            j.status === 'FAILED' ? 'bg-red-500/20 text-red-400' : 
                            'bg-amber-500/20 text-amber-400'
                          }`}>
                            {j.status}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {j.status === 'QUEUED' && (
                            <button onClick={() => runJob(j.id)} className="text-cyan-400 hover:underline">Run</button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === "models" && (
          <div>
            {!models ? <Loading /> : models.length === 0 ? <EmptyState message="No models in registry." /> : (
              <div className="overflow-hidden rounded-lg border border-soc-border">
                <table className="w-full text-left text-sm text-slate-400">
                  <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
                    <tr>
                      <th className="px-4 py-3">Model</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Dataset</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-soc-border">
                    {models.map(m => (
                      <tr key={m.id} className="hover:bg-soc-panel">
                        <td className="px-4 py-3 font-mono text-slate-200">{m.model_name}</td>
                        <td className="px-4 py-3 font-semibold text-amber-500">{m.model_type}</td>
                        <td className="px-4 py-3">{m.dataset_version}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            m.status === 'PRODUCTION' ? 'bg-emerald-500/20 text-emerald-400' : 
                            m.status === 'APPROVED' ? 'bg-cyan-500/20 text-cyan-400' : 
                            m.status === 'REJECTED' ? 'bg-red-500/20 text-red-400' : 
                            'bg-slate-500/20 text-slate-300'
                          }`}>
                            {m.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 flex gap-2">
                          {m.status === 'CANDIDATE' && (
                            <>
                              <button onClick={() => handleModelAction(m.id, 'approve')} className="text-emerald-400 hover:underline">Approve</button>
                              <button onClick={() => handleModelAction(m.id, 'reject')} className="text-red-400 hover:underline">Reject</button>
                            </>
                          )}
                          {m.status === 'APPROVED' && (
                            <button onClick={() => handleModelAction(m.id, 'promote')} className="text-cyan-400 font-bold hover:underline">Promote to Prod</button>
                          )}
                          {m.status === 'PRODUCTION' && (
                            <button onClick={() => handleModelAction(m.id, 'rollback')} className="text-amber-400 hover:underline">Rollback</button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
