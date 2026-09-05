import { PageHeader } from "../components/ui";

export default function Observability() {
  const grafanaUrl = "http://localhost:3001/d/compliance-overview?orgId=1&kiosk";

  return (
    <div>
      <PageHeader
        title="System Observability"
        subtitle="Scan duration, AI inference latency, queue activity, worker health, and unknown-command rate via Grafana"
      />
      <div className="px-8 pb-8">
        <div className="card">
          <div className="text-sm text-slate-400 mb-3">
            Metrics are collected via OpenTelemetry, stored in VictoriaMetrics, and visualized in Grafana
            (self-hosted, port 3001 in docker-compose). Import the dashboard JSON from{" "}
            <code className="text-cyan-400">docs/grafana-dashboard.json</code> on first run.
          </div>
          <div className="aspect-video bg-black/40 rounded-lg border border-soc-border flex items-center justify-center text-slate-600 text-sm">
            <iframe
              src={grafanaUrl}
              title="Grafana dashboard"
              className="w-full h-full rounded-lg"
              onError={(e) => (e.currentTarget.style.display = "none")}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
