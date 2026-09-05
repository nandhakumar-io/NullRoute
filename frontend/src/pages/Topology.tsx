import { useEffect, useState } from "react";
import { endpoints, Topology as TopologyData } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

export default function Topology() {
  const [topology, setTopology] = useState<TopologyData | null>(null);

  useEffect(() => {
    endpoints.topology().then((r) => setTopology(r.data));
  }, []);

  if (!topology) return <Loading />;

  const { nodes, links } = topology;
  const hostnameFor = (id: string) => nodes.find((n) => n.id === id)?.hostname || id.slice(0, 8);

  return (
    <div>
      <PageHeader
        title="Topology"
        subtitle="Devices and inferred adjacencies, derived from collected interface data (Phase 9)"
      />
      <div className="px-8 space-y-6">
        {nodes.length === 0 ? (
          <EmptyState message="No devices yet. Upload or collect a configuration first." />
        ) : (
          <>
            <div className="card overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b border-soc-border">
                    <th className="py-2 pr-4">Device</th>
                    <th className="py-2 pr-4">Vendor / Model</th>
                    <th className="py-2 pr-4">Mgmt Address</th>
                    <th className="py-2 pr-4">Interfaces</th>
                    <th className="py-2 pr-4">VLANs</th>
                    <th className="py-2 pr-4">VRFs</th>
                    <th className="py-2 pr-4">Compliance</th>
                  </tr>
                </thead>
                <tbody>
                  {nodes.map((n) => (
                    <tr key={n.id} className="border-b border-soc-border/50 hover:bg-slate-800/30">
                      <td className="py-2 pr-4 font-medium text-slate-200">{n.hostname || "—"}</td>
                      <td className="py-2 pr-4">{[n.vendor, n.model].filter(Boolean).join(" / ") || "—"}</td>
                      <td className="py-2 pr-4 text-slate-500">{n.management_address || "—"}</td>
                      <td className="py-2 pr-4">{n.interface_count}</td>
                      <td className="py-2 pr-4">{n.vlan_count}</td>
                      <td className="py-2 pr-4">{n.vrf_count}</td>
                      <td className="py-2 pr-4 font-semibold">
                        {n.last_compliance_score != null ? `${n.last_compliance_score}%` : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="card">
              <div className="text-sm font-semibold text-slate-200 mb-2">
                Inferred Links ({links.length})
              </div>
              <div className="text-xs text-slate-500 mb-3">
                Adjacency is inferred by matching interface IP addresses onto a shared subnet —
                never fabricated when no supporting data exists.
              </div>
              {links.length === 0 ? (
                <EmptyState message="No inferred links — either only one device has interface data, or no two devices share a subnet." />
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-slate-500 border-b border-soc-border">
                      <th className="py-2 pr-4">Subnet</th>
                      <th className="py-2 pr-4">Device A</th>
                      <th className="py-2 pr-4">Interface</th>
                      <th className="py-2 pr-4">Device B</th>
                      <th className="py-2 pr-4">Interface</th>
                    </tr>
                  </thead>
                  <tbody>
                    {links.map((l, idx) => (
                      <tr key={idx} className="border-b border-soc-border/50 hover:bg-slate-800/30">
                        <td className="py-2 pr-4 font-mono text-xs text-slate-400">{l.subnet}</td>
                        <td className="py-2 pr-4">{hostnameFor(l.source_device_id)}</td>
                        <td className="py-2 pr-4 text-slate-500">{l.source_interface || "—"}</td>
                        <td className="py-2 pr-4">{hostnameFor(l.target_device_id)}</td>
                        <td className="py-2 pr-4 text-slate-500">{l.target_interface || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
