import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { endpoints, Device, NetworkInterface, NetworkRoute, Scan, DriftEvent } from "../api";
import { PageHeader, Loading, EmptyState, StatusBadge } from "../components/ui";

export default function DeviceDetail() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const [device, setDevice] = useState<Device | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [routes, setRoutes] = useState<NetworkRoute[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [drift, setDrift] = useState<DriftEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    if (!deviceId) return;
    setLoading(true);
    setNotFound(false);
    Promise.all([
      endpoints.device(deviceId),
      endpoints.deviceInterfaces(deviceId),
      endpoints.deviceRoutes(deviceId),
      endpoints.deviceScans(deviceId),
      endpoints.deviceDrift(deviceId),
    ])
      .then(([d, ifaces, rts, sc, dr]) => {
        setDevice(d.data);
        setInterfaces(ifaces.data);
        setRoutes(rts.data);
        setScans(sc.data);
        setDrift(dr.data.events);
      })
      .catch((e) => {
        if (e?.response?.status === 404) setNotFound(true);
      })
      .finally(() => setLoading(false));
  }, [deviceId]);

  if (loading) return <Loading />;
  if (notFound || !device) return <EmptyState message="Device not found." />;

  return (
    <div>
      <PageHeader
        title={device.hostname || "Unnamed device"}
        subtitle={
          <span className="font-mono text-xs">
            {[device.vendor, device.model, device.os, device.version].filter(Boolean).join(" · ") || device.id}
          </span>
        }
      />
      <div className="px-8 pb-8 space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Compliance Score</div>
            <div className="text-3xl font-bold mt-2 text-slate-100">
              {device.last_compliance_score != null ? `${device.last_compliance_score}%` : "—"}
            </div>
          </div>
          <div className="card">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Collection Status</div>
            <div className="text-lg font-bold mt-2 text-slate-100">{device.collection_status || "never collected"}</div>
          </div>
          <div className="card">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Management Address</div>
            <div className="text-lg font-mono mt-2 text-slate-100">{device.management_address || "—"}</div>
          </div>
          <div className="card">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Serial</div>
            <div className="text-lg font-mono mt-2 text-slate-100">{device.serial_number || "—"}</div>
          </div>
        </div>

        {device.last_collection_error && (
          <div className="card border-red-900/60 bg-red-950/20">
            <div className="text-sm font-semibold text-red-400">Last collection error</div>
            <div className="text-xs text-slate-400 mt-1">{device.last_collection_error}</div>
            {device.last_collection_transport && (
              <div className="text-xs text-slate-500 mt-1">via {device.last_collection_transport}</div>
            )}
          </div>
        )}

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Interfaces ({interfaces.length})</div>
          {interfaces.length === 0 ? (
            <div className="text-sm text-slate-500">No interface inventory recorded for this device yet.</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border">
                  <th className="py-2 pr-4">Name</th>
                  <th className="py-2 pr-4">IP</th>
                  <th className="py-2 pr-4">VLAN</th>
                  <th className="py-2 pr-4">VRF</th>
                  <th className="py-2 pr-4">State</th>
                </tr>
              </thead>
              <tbody>
                {interfaces.map((i) => (
                  <tr key={i.id} className="border-b border-soc-border/50">
                    <td className="py-2 pr-4 font-mono">{i.name}</td>
                    <td className="py-2 pr-4 font-mono">{i.ip_address || "—"}</td>
                    <td className="py-2 pr-4">{i.vlan || "—"}</td>
                    <td className="py-2 pr-4">{i.vrf || "—"}</td>
                    <td className="py-2 pr-4">{i.admin_state || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Routes ({routes.length})</div>
          {routes.length === 0 ? (
            <div className="text-sm text-slate-500">No route inventory recorded for this device yet.</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border">
                  <th className="py-2 pr-4">Destination</th>
                  <th className="py-2 pr-4">Next Hop</th>
                  <th className="py-2 pr-4">VRF</th>
                </tr>
              </thead>
              <tbody>
                {routes.map((r) => (
                  <tr key={r.id} className="border-b border-soc-border/50">
                    <td className="py-2 pr-4 font-mono">
                      {r.destination}
                      {r.mask ? `/${r.mask}` : ""}
                    </td>
                    <td className="py-2 pr-4 font-mono">{r.next_hop || "—"}</td>
                    <td className="py-2 pr-4">{r.vrf || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Recent Scans ({scans.length})</div>
          {scans.length === 0 ? (
            <div className="text-sm text-slate-500">No scans yet for this device.</div>
          ) : (
            <div className="space-y-2">
              {scans.slice(0, 10).map((s) => (
                <div key={s.id} className="flex items-center justify-between border-b border-soc-border/50 pb-2 last:border-0">
                  <Link className="text-cyan-400 hover:underline text-sm" to={`/scans/${s.id}`}>
                    {s.framework} scan · {new Date(s.created_at).toLocaleString()}
                  </Link>
                  <div className="flex items-center gap-2">
                    <StatusBadge status={s.status} />
                    {s.compliance_score != null && (
                      <span className="text-xs text-slate-500">{s.compliance_score}%</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Recent Drift ({drift.length})</div>
          {drift.length === 0 ? (
            <div className="text-sm text-slate-500">No configuration drift detected for this device.</div>
          ) : (
            <div className="space-y-2">
              {drift.slice(0, 10).map((e) => (
                <div key={e.id} className="flex items-center justify-between border-b border-soc-border/50 pb-2 last:border-0">
                  <div className="text-sm text-slate-300">{new Date(e.created_at).toLocaleString()}</div>
                  <div className="flex items-center gap-2 text-xs">
                    <span className={`badge ${e.security_impacting ? "badge-critical" : "badge-na"}`}>
                      {e.security_impacting ? "SECURITY-IMPACTING" : "COSMETIC"}
                    </span>
                    <span className="text-emerald-400">+{e.added_lines}</span>
                    <span className="text-red-400">-{e.removed_lines}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}