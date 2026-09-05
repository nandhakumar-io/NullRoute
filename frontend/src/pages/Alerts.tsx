import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, Alert } from "../api";
import { PageHeader, Loading, EmptyState, SeverityBadge } from "../components/ui";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const STATUSES = ["OPEN", "ACKNOWLEDGED"];

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<string>("OPEN");
  const [severity, setSeverity] = useState<string>("");
  const [busyId, setBusyId] = useState<string | null>(null);

  function load() {
    setLoading(true);
    endpoints
      .alerts({ status: status || undefined, severity: severity || undefined })
      .then((r) => setAlerts(r.data.alerts))
      .finally(() => setLoading(false));
  }

  useEffect(load, [status, severity]);

  async function handleAck(a: Alert) {
    setBusyId(a.id);
    try {
      await endpoints.acknowledgeAlert(a.id);
      load();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <PageHeader
        title="Alerts"
        subtitle="Triggered by critical findings, high risk, drift, unknowns, and pipeline component failures"
        action={
          <div className="flex gap-2">
            <select
              className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All statuses</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <select
              className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All severities</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
        }
      />
      <div className="px-8 pb-8 space-y-3">
        {loading && <Loading />}
        {!loading && alerts.length === 0 && <EmptyState message="No alerts match the current filters." />}
        {!loading &&
          alerts.map((a) => (
            <div key={a.id} className="card">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={a.severity} />
                    <span className="badge badge-na">{a.category.replace(/_/g, " ")}</span>
                    <span className={`badge ${a.status === "OPEN" ? "badge-fail" : "badge-pass"}`}>
                      {a.status}
                    </span>
                  </div>
                  <div className="text-slate-200 font-medium mt-1">{a.title}</div>
                  {a.detail && <div className="text-xs text-slate-500 mt-1">{a.detail}</div>}
                  <div className="text-xs text-slate-500 mt-1">
                    {a.scan_id && (
                      <>
                        <Link className="text-cyan-400 hover:underline" to={`/scans/${a.scan_id}`}>
                          scan {a.scan_id}
                        </Link>
                        {" · "}
                      </>
                    )}
                    {new Date(a.created_at).toLocaleString()}
                    {a.acknowledged_by && ` · ack'd by ${a.acknowledged_by}`}
                  </div>
                </div>
                {a.status === "OPEN" && (
                  <button className="btn-secondary shrink-0" disabled={busyId === a.id} onClick={() => handleAck(a)}>
                    Acknowledge
                  </button>
                )}
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}
