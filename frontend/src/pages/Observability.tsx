import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, ComplianceSummary, ConfidenceTrendOut, SystemHealth as SystemHealthData } from "../api";
import { PageHeader, Loading, StatCard } from "../components/ui";
import Sparkline from "../components/Sparkline";

// Grafana is an optional, separately self-hosted piece of this stack (see
// docker-compose.infra.yml). Embedding it in an <iframe> unconditionally
// meant this page rendered a permanently blank box for every install that
// hasn't stood Grafana up -- the iframe's onError never fires for a
// same-origin-policy / X-Frame-Options / connection-refused failure, only
// for a handful of resource-load errors browsers rarely emit for iframes.
// This page only *offers* the Grafana embed as an optional deep dive once
// we've actually confirmed Grafana is reachable.
const GRAFANA_URL = (import.meta as any).env?.VITE_GRAFANA_URL || "http://localhost:3001/d/compliance-overview?orgId=1&kiosk";

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

const MODEL_STATUS_TONE: Record<string, string> = {
  PRODUCTION: "badge-pass",
  ARCHIVED: "badge-na",
  CANDIDATE: "badge-medium",
  FAILED: "badge-fail",
};

// This page used to duplicate System Health's "Core Services" /
// "Optional Integrations" / classifier-embedder-ready cards wholesale --
// same rows, same labels, same data, fetched a second time. That's not
// observability, it's a second up/down page. Everything below is either
// a trend, a rate, or a deep-dive that System Health intentionally
// doesn't show (it's a point-in-time health check, not a metrics
// dashboard) -- the things a Grafana-style page is actually for.
export default function Observability() {
  const [systemHealth, setSystemHealth] = useState<SystemHealthData | null>(null);
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [trend, setTrend] = useState<ConfidenceTrendOut | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [grafanaReachable, setGrafanaReachable] = useState(false);
  const [showGrafana, setShowGrafana] = useState(false);

  async function load() {
    setError(null);
    try {
      const [healthRes, summaryRes, trendRes] = await Promise.all([
        endpoints.systemHealth().catch(() => ({ data: null })),
        endpoints.complianceSummary().catch(() => ({ data: null })),
        endpoints.confidenceTrend(30).catch(() => ({ data: null })),
      ]);
      setSystemHealth(healthRes.data);
      setSummary(summaryRes.data);
      setTrend(trendRes.data);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Could not reach the API to load observability data.");
    } finally {
      setLoading(false);
    }

    // Grafana is genuinely optional -- probe it separately so a missing
    // Grafana never blocks the rest of this page from rendering.
    fetch(GRAFANA_URL, { mode: "no-cors" })
      .then(() => setGrafanaReachable(true))
      .catch(() => setGrafanaReachable(false));
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  if (loading && !summary && !trend) return <Loading />;

  const allServices = [...(systemHealth?.core_services || []), ...(systemHealth?.optional_integrations || [])];
  const degradedOrDown = allServices.filter((s) => s.status !== "HEALTHY" && s.status !== "DISABLED");

  const points = trend?.points || [];
  const latest = points[points.length - 1];
  const confidenceSeries = points.map((p) => p.avg_classifier_confidence);
  const reviewRateSeries = points.map((p) => p.requires_review_rate * 100);
  const volumeSeries = points.map((p) => p.analysis_count);

  return (
    <div>
      <PageHeader
        title="Observability"
        subtitle="Trends and deep-dive metrics — service up/down status lives on System Health; this page is for the things that change gradually and need a chart, not a badge."
        action={
          <div className="flex items-center gap-3">
            {systemHealth && <StatusPill status={systemHealth.overall_status} />}
            <button onClick={load} className="btn-secondary">Refresh</button>
          </div>
        }
      />

      <div className="px-8 pb-8 space-y-6">
        {error && (
          <div className="card border border-red-500/30 text-sm text-red-400">{error}</div>
        )}

        {degradedOrDown.length > 0 && (
          <Link
            to="/system/health"
            className="card border border-amber-800/60 bg-amber-950/20 flex items-center justify-between text-sm hover:border-amber-600 transition-colors"
          >
            <span className="text-amber-300">
              {degradedOrDown.length} service{degradedOrDown.length === 1 ? "" : "s"} reporting issues — {degradedOrDown.map((s) => s.name).join(", ")}
            </span>
            <span className="text-amber-400 whitespace-nowrap">Open System Health →</span>
          </Link>
        )}

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Pending HITL Reviews"
            value={summary?.ai_health.pending_hitl_reviews ?? "—"}
            tone={summary && summary.ai_health.pending_hitl_reviews > 0 ? "medium" : "good"}
          />
          <StatCard
            label="Model Drift"
            value={trend ? (trend.drift_detected ? "Detected" : "Stable") : "—"}
            tone={trend?.drift_detected ? "critical" : "good"}
          />
          <StatCard
            label="Avg Classifier Confidence"
            value={latest ? `${(latest.avg_classifier_confidence * 100).toFixed(0)}%` : "—"}
            tone={latest && latest.avg_classifier_confidence < (trend?.confidence_threshold ?? 0) ? "medium" : "good"}
          />
          <StatCard
            label="Production Model F1"
            value={summary?.ai_health.production_model_macro_f1 != null ? summary.ai_health.production_model_macro_f1.toFixed(2) : "—"}
            tone="default"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="card">
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-sm font-semibold text-slate-100">AI Confidence Trend (30d)</h3>
              {trend?.drift_detected && <span className="badge badge-critical text-xs">Drift alert</span>}
            </div>
            <div className="text-xs text-slate-500 mb-4">
              Daily average classifier confidence across all AI interpretations — a real drift signal
              (recent quarter of the window vs. earliest quarter dropping by more than {((trend?.drift_alert_delta ?? 0.1) * 100).toFixed(0)}
              pts), not a synthetic or interpolated line.
            </div>
            {points.length >= 2 ? (
              <div className="space-y-4">
                <div className="flex items-center gap-4">
                  <Sparkline values={confidenceSeries} width={220} height={48} color="#22d3ee" />
                  <div>
                    <div className="text-2xl font-bold text-slate-100">{(latest.avg_classifier_confidence * 100).toFixed(0)}%</div>
                    <div className="text-xs text-slate-500">latest day avg confidence</div>
                  </div>
                </div>
                <div className="flex items-center gap-4 pt-3 border-t border-soc-border">
                  <Sparkline values={reviewRateSeries} width={220} height={40} color="#f59e0b" />
                  <div>
                    <div className="text-2xl font-bold text-slate-100">{(latest.requires_review_rate * 100).toFixed(0)}%</div>
                    <div className="text-xs text-slate-500">latest day HITL review rate</div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-sm text-slate-500 py-6 text-center border border-dashed border-soc-border rounded-lg">
                Not enough AI interpretation history yet to plot a trend — check back after a few days of scans.
              </div>
            )}
          </div>

          <div className="card">
            <h3 className="text-sm font-semibold text-slate-100 mb-1">AI Analysis Volume (30d)</h3>
            <div className="text-xs text-slate-500 mb-4">
              How many configuration lines the AI/RAG layer interpreted per day — a proxy for how much of
              the ingestion pipeline's normalization is landing on unknown syntax rather than the
              deterministic parser.
            </div>
            {points.length >= 2 ? (
              <div className="flex items-center gap-4">
                <Sparkline values={volumeSeries} width={220} height={48} color="#818cf8" />
                <div>
                  <div className="text-2xl font-bold text-slate-100">{latest.analysis_count}</div>
                  <div className="text-xs text-slate-500">interpretations, latest day</div>
                </div>
              </div>
            ) : (
              <div className="text-sm text-slate-500 py-6 text-center border border-dashed border-soc-border rounded-lg">
                No AI interpretation activity recorded in this window yet.
              </div>
            )}
            {summary && (
              <div className="flex items-center justify-between pt-4 mt-4 border-t border-soc-border text-sm">
                <span className="text-slate-400">Production model</span>
                <span className="text-slate-200 font-mono">
                  {summary.ai_health.production_model || "none promoted"}
                  {summary.ai_health.production_model_macro_f1 != null && ` (F1 ${summary.ai_health.production_model_macro_f1.toFixed(2)})`}
                </span>
              </div>
            )}
          </div>
        </div>

        {trend && trend.model_history.length > 0 && (
          <div className="card">
            <h3 className="text-sm font-semibold text-slate-100 mb-4 border-b border-soc-border pb-2">Model Lifecycle History</h3>
            <div className="space-y-0">
              {trend.model_history.map((m) => (
                <div key={m.model_id} className="flex items-center justify-between py-2.5 border-b border-soc-border last:border-b-0">
                  <div className="min-w-0 pr-4">
                    <div className="text-sm font-medium text-slate-200 font-mono">{m.model_version || m.model_id}</div>
                    <div className="text-xs text-slate-500 mt-0.5">
                      dataset {m.dataset_version}
                      {m.training_timestamp && ` · trained ${new Date(m.training_timestamp).toLocaleString()}`}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {m.accuracy != null && <span className="text-xs text-slate-500">acc {(m.accuracy * 100).toFixed(1)}%</span>}
                    <span className={`badge ${MODEL_STATUS_TONE[m.status] || "badge-na"}`}>{m.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Grafana Dashboard (optional)</h3>
              <div className="text-xs text-slate-500 mt-1">
                Detailed scan-duration, AI-inference-latency and queue-depth time series, collected via
                OpenTelemetry → VictoriaMetrics → Grafana (self-hosted, see{" "}
                <code className="text-cyan-400">docker-compose.infra.yml</code>). Import{" "}
                <code className="text-cyan-400">docs/grafana-dashboard.json</code> on first run.
              </div>
            </div>
            <span className={`badge ${grafanaReachable ? "badge-pass" : "badge-na"}`}>
              {grafanaReachable ? "Reachable" : "Not detected"}
            </span>
          </div>
          {grafanaReachable ? (
            showGrafana ? (
              <div className="aspect-video bg-black/40 rounded-lg border border-soc-border overflow-hidden">
                <iframe src={GRAFANA_URL} title="Grafana dashboard" className="w-full h-full" />
              </div>
            ) : (
              <button onClick={() => setShowGrafana(true)} className="btn-secondary text-sm">
                Load Grafana dashboard
              </button>
            )
          ) : (
            <div className="text-sm text-slate-500">
              Grafana isn't reachable at <code className="text-cyan-400">{GRAFANA_URL}</code>. Start the optional
              observability stack (<code className="text-cyan-400">docker compose -f docker-compose.infra.yml up -d</code>) to enable it.
            </div>
          )}
        </div>

        <div className="text-xs text-slate-500 text-center">
          Looking for service up/down status, core services, or optional integrations?{" "}
          <Link to="/system/health" className="text-cyan-400 hover:underline">That lives on System Health →</Link>
        </div>
      </div>
    </div>
  );
}