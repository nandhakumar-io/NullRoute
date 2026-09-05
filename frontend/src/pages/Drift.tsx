import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, DriftEvent } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

export default function Drift() {
  const [events, setEvents] = useState<DriftEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [onlySecurityImpacting, setOnlySecurityImpacting] = useState(false);

  function load() {
    setLoading(true);
    endpoints
      .drift(onlySecurityImpacting ? { security_impacting: true } : undefined)
      .then((r) => setEvents(r.data.events))
      .finally(() => setLoading(false));
  }

  useEffect(load, [onlySecurityImpacting]);

  return (
    <div>
      <PageHeader
        title="Configuration Drift"
        subtitle="Immutable configuration snapshots — every collection is diffed against the previous one"
        action={
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input
              type="checkbox"
              checked={onlySecurityImpacting}
              onChange={(e) => setOnlySecurityImpacting(e.target.checked)}
            />
            Security-impacting only
          </label>
        }
      />
      <div className="px-8 pb-8 space-y-3">
        {loading && <Loading />}
        {!loading && events.length === 0 && (
          <EmptyState message="No drift detected yet — drift events appear after a device's configuration changes between collections." />
        )}
        {!loading &&
          events.map((e) => (
            <div key={e.id} className="card">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-slate-400">device {e.device_id}</span>
                    <span className={`badge ${e.security_impacting ? "badge-critical" : "badge-na"}`}>
                      {e.security_impacting ? "SECURITY-IMPACTING" : "COSMETIC"}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    {e.scan_id && (
                      <>
                        <Link className="text-cyan-400 hover:underline" to={`/scans/${e.scan_id}`}>
                          scan {e.scan_id}
                        </Link>
                        {" · "}
                      </>
                    )}
                    {new Date(e.created_at).toLocaleString()}
                  </div>
                  <div className="text-xs font-mono text-slate-500 mt-1 truncate">
                    {e.previous_hash ? `${e.previous_hash.slice(0, 12)} → ` : "(first collection) → "}
                    {e.current_hash.slice(0, 12)}
                  </div>
                  {e.changed_sections && e.changed_sections.length > 0 && (
                    <div className="text-xs text-slate-400 mt-1">
                      Changed sections: {e.changed_sections.join(", ")}
                    </div>
                  )}
                  {e.affected_controls && e.affected_controls.length > 0 && (
                    <div className="text-xs text-amber-400 mt-1">
                      Affected controls: {e.affected_controls.join(", ")}
                    </div>
                  )}
                </div>
                <div className="text-xs text-slate-500 shrink-0 text-right">
                  <div className="text-emerald-400">+{e.added_lines} lines</div>
                  <div className="text-red-400">-{e.removed_lines} lines</div>
                </div>
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}
