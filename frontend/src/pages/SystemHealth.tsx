import { useEffect, useState } from "react";
import { api, endpoints, AIHealth, ServiceHealthEntry, SystemHealth as SystemHealthData } from "../api";
import { PageHeader, Loading } from "../components/ui";

const STATUS_BADGE_CLASS: Record<string, string> = {
  HEALTHY: "badge-pass",
  DEGRADED: "badge-medium",
  UNAVAILABLE: "badge-fail",
  ERROR: "badge-critical",
  DISABLED: "badge-na",
};

function StatusPill({ status }: { status: string }) {
  return <span className={`badge ${STATUS_BADGE_CLASS[status] || "badge-na"}`}>{status}</span>;
}

function ServiceRow({ svc }: { svc: ServiceHealthEntry }) {
  return (
    <div className="flex items-start justify-between py-3 border-b border-soc-border last:border-b-0">
      <div className="min-w-0 pr-4">
        <div className="text-sm font-medium text-slate-200">{svc.name}</div>
        {svc.detail && <div className="text-xs text-slate-500 mt-0.5">{svc.detail}</div>}
        {svc.error && <div className="text-xs text-red-400 mt-0.5 break-words">{svc.error}</div>}
        {typeof svc.latency_ms === "number" && (
          <div className="text-xs text-slate-600 mt-0.5">{svc.latency_ms} ms</div>
        )}
      </div>
      <StatusPill status={svc.status} />
    </div>
  );
}

export default function SystemHealth() {
  const [aiHealth, setAiHealth] = useState<AIHealth | null>(null);
  const [apiStatus, setApiStatus] = useState<string>("pending");
  const [systemHealth, setSystemHealth] = useState<SystemHealthData | null>(null);
  const [systemHealthError, setSystemHealthError] = useState<string | null>(null);

  const load = async () => {
    try {
      const res = await api.get("/health");
      setApiStatus(res.data.status === "ok" ? "healthy" : "failing");
    } catch {
      setApiStatus("offline");
    }

    try {
      const aiRes = await endpoints.aiHealth();
      setAiHealth(aiRes.data);
    } catch {
      setAiHealth(null);
    }

    try {
      const sysRes = await endpoints.systemHealth();
      setSystemHealth(sysRes.data);
      setSystemHealthError(null);
    } catch {
      setSystemHealth(null);
      setSystemHealthError("Could not reach the API to check dependent services.");
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  if (!aiHealth && !systemHealth && apiStatus === "pending") return <Loading />;

  return (
    <div>
      <PageHeader
        title="System Health"
        subtitle="Real-time status of core services and optional integrations"
        action={
          <div className="flex items-center gap-3">
            {systemHealth && <StatusPill status={systemHealth.overall_status} />}
            <button onClick={load} className="btn-secondary">Refresh</button>
          </div>
        }
      />

      <div className="px-8 grid grid-cols-1 md:grid-cols-2 gap-6">

        <div className="card">
          <h3 className="text-sm font-semibold text-slate-100 mb-4 border-b border-soc-border pb-2">Core Services</h3>
          <div className="space-y-0">
            <div className="flex items-center justify-between py-3 border-b border-soc-border">
              <div>
                <div className="text-sm font-medium text-slate-200">REST API Backend</div>
                <div className="text-xs text-slate-500">Provides endpoints for CLI and UI</div>
              </div>
              <StatusPill status={apiStatus === "healthy" ? "HEALTHY" : "UNAVAILABLE"} />
            </div>
            {systemHealth ? (
              systemHealth.core_services.map((svc) => <ServiceRow key={svc.name} svc={svc} />)
            ) : (
              <div className="text-sm text-slate-500 py-3">
                {systemHealthError || "Loading…"}
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-slate-100 mb-4 border-b border-soc-border pb-2">Optional Integrations</h3>
          <div className="space-y-0">
            {systemHealth ? (
              systemHealth.optional_integrations.map((svc) => <ServiceRow key={svc.name} svc={svc} />)
            ) : (
              <div className="text-sm text-slate-500 py-3">
                {systemHealthError || "Loading…"}
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-slate-100 mb-4 border-b border-soc-border pb-2">AI / ML Pipelines</h3>
          {aiHealth ? (
             <div className="space-y-4">
               <div className="flex items-center justify-between">
                 <div>
                   <div className="text-sm font-medium text-slate-200">Zero-Shot Classifier</div>
                   <div className="text-xs text-slate-500">{aiHealth.classifier_backend} ({aiHealth.model_version})</div>
                 </div>
                 <span className={`px-2 py-1 rounded-full text-xs font-semibold ${aiHealth.classifier_loaded ? 'bg-emerald-950/50 text-emerald-400' : 'bg-amber-950/50 text-amber-500'}`}>
                   {aiHealth.classifier_loaded ? 'Ready' : 'Not Loaded'}
                 </span>
               </div>
               <div className="flex items-center justify-between">
                 <div>
                   <div className="text-sm font-medium text-slate-200">Semantic Embedder</div>
                   <div className="text-xs text-slate-500">{aiHealth.embedder_backend} (Dataset: {aiHealth.reference_examples} examples)</div>
                 </div>
                 <span className={`px-2 py-1 rounded-full text-xs font-semibold ${aiHealth.embedder_loaded ? 'bg-emerald-950/50 text-emerald-400' : 'bg-amber-950/50 text-amber-500'}`}>
                   {aiHealth.embedder_loaded ? 'Ready' : 'Not Loaded'}
                 </span>
               </div>
             </div>
          ) : (
            <div className="text-sm text-slate-500">AI Service unreachable.</div>
          )}
        </div>

      </div>
    </div>
  );
}