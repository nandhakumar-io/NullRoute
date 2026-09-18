import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, AIHealth, AIModelsInfo } from "../api";
import { PageHeader, Loading, EmptyState, StatCard } from "../components/ui";

// "AI Enabled / Classifier Loaded / Embedder Loaded" used to open this page
// as three more copies of the exact same up/down badges System Health
// already shows in its "AI / ML Pipelines" card -- this is the third
// place in the app that said the same "loaded / not loaded" thing. This
// page's actual job is the stuff System Health has no room for: which
// model version is active, what backend/path each component resolves to,
// and the decision thresholds -- so that's what leads now, with a link
// out for anyone who just wants the up/down check.
export default function AIAnalysisOverview() {
  const [health, setHealth] = useState<AIHealth | null>(null);
  const [models, setModels] = useState<AIModelsInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.all([endpoints.aiHealth(), endpoints.aiModels()])
      .then(([h, m]) => {
        setHealth(h.data);
        setModels(m.data);
      })
      .catch(() => setError("Could not reach the AI service."))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <PageHeader
        title="AI Analysis"
        subtitle="DistilBERT classifier + MiniLM semantic embeddings — interprets unknown configuration syntax, never a compliance PASS/FAIL"
      />
      <div className="px-8 pb-8 space-y-6">
        {loading && <Loading />}
        {!loading && error && <EmptyState message={error} />}
        {!loading && !error && health && (
          <>
            {!health.ai_enabled && (
              <div className="card border border-amber-800/60 bg-amber-950/20 text-sm text-amber-300">
                AI is disabled for this tenant — configuration lines that don't match a known parser will be
                left unclassified rather than interpreted.
              </div>
            )}

            <div className="card">
              <div className="flex items-center justify-between mb-3">
                <div className="font-semibold text-slate-200">Model Version</div>
                <Link to="/system/health" className="text-xs text-cyan-400 hover:underline whitespace-nowrap">
                  Component up/down status →
                </Link>
              </div>
              <div className="text-sm text-slate-400 space-y-1">
                <div>
                  Active model version: <span className="font-mono text-cyan-400">{health.model_version}</span>
                </div>
                {health.reference_dataset && (
                  <div className="truncate">
                    Reference dataset:{" "}
                    <span className="font-mono text-slate-500">{health.reference_dataset}</span>
                    {" "}({health.reference_examples} examples)
                  </div>
                )}
              </div>
            </div>

            {models && (
              <div className="card">
                <div className="font-semibold text-slate-200 mb-3">Loaded Components</div>
                <div className="space-y-3">
                  {models.models.map((m) => (
                    <div
                      key={m.component}
                      className="flex items-center justify-between border-b border-soc-border last:border-0 pb-3 last:pb-0"
                    >
                      <div>
                        <div className="text-sm font-medium text-slate-200 capitalize">{m.component}</div>
                        <div className="text-xs text-slate-500 font-mono mt-0.5">
                          {m.path || "(no path — using packaged default)"}
                        </div>
                      </div>
                      <div className="text-right">
                        <span className={`badge ${m.loaded ? "badge-pass" : "badge-fail"}`}>
                          {m.loaded ? "loaded" : "not loaded"}
                        </span>
                        <div className="text-xs text-slate-500 mt-1">
                          {m.backend} · v{m.version}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                {Object.keys(models.thresholds).length > 0 && (
                  <div className="mt-4 pt-4 border-t border-soc-border text-xs text-slate-500">
                    Decision thresholds:{" "}
                    {Object.entries(models.thresholds)
                      .map(([k, v]) => `${k}=${v}`)
                      .join(" · ")}
                  </div>
                )}
              </div>
            )}

            <div className="text-xs text-slate-500">
              Per-scan AI interpretations (intent, confidence, semantic similarity, decision) are shown on each
              scan's detail page. AI can identify and explain configuration intent, but never issues a compliance
              PASS/FAIL — that authority stays with OPA and Batfish. For confidence trends and drift detection
              over time, see <Link to="/observability" className="text-cyan-400 hover:underline">Observability</Link>.
            </div>
          </>
        )}
      </div>
    </div>
  );
}