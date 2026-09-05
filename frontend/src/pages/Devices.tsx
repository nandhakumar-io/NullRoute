import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, Device } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

export default function Devices() {
  const [devices, setDevices] = useState<Device[] | null>(null);

  useEffect(() => {
    endpoints.devices().then((r) => setDevices(r.data));
  }, []);

  if (!devices) return <Loading />;

  return (
    <div>
      <PageHeader title="Devices" subtitle="All discovered and scanned network devices" />
      <div className="px-8">
        {devices.length === 0 ? (
          <EmptyState message="No devices yet. Upload a configuration from the Ingestion page." />
        ) : (
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border">
                  <th className="py-2 pr-4">Hostname</th>
                  <th className="py-2 pr-4">Vendor</th>
                  <th className="py-2 pr-4">Model</th>
                  <th className="py-2 pr-4">OS / Version</th>
                  <th className="py-2 pr-4">Last Scan</th>
                  <th className="py-2 pr-4">Score</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id} className="border-b border-soc-border/50 hover:bg-slate-800/30">
                    <td className="py-2 pr-4 font-medium text-slate-200">
                      <Link className="text-cyan-400 hover:underline" to={`/devices/${d.id}`}>
                        {d.hostname || "—"}
                      </Link>
                    </td>
                    <td className="py-2 pr-4">{d.vendor || "—"}</td>
                    <td className="py-2 pr-4">{d.model || "—"}</td>
                    <td className="py-2 pr-4">{[d.os, d.version].filter(Boolean).join(" ") || "—"}</td>
                    <td className="py-2 pr-4 text-slate-500">{d.last_scan_at ? new Date(d.last_scan_at).toLocaleString() : "never"}</td>
                    <td className="py-2 pr-4 font-semibold">
                      {d.last_compliance_score != null ? `${d.last_compliance_score}%` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}