import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  endpoints, Device, NetworkInterface, NetworkRoute, Scan, DriftEvent,
  ConfigSnapshot, SecurityDriftFinding, CompliancePostureHistory,
} from "../api";
import { PageHeader, Loading, EmptyState, StatusBadge } from "../components/ui";

const DRIFT_TYPE_STYLE: Record<string, string> = {
  SECURITY_DEGRADATION: "badge-critical",
  SECURITY_IMPROVEMENT: "badge-low",
  COMPLIANCE_IMPACT: "badge-high",
  CONFIGURATION_CHANGE: "badge-na",
  UNKNOWN_IMPACT: "badge-medium",
  NO_CHANGE: "badge-na",
};

function DriftTypeBadge({ driftType }: { driftType: string }) {
  return <span className={`badge ${DRIFT_TYPE_STYLE[driftType] || "badge-na"}`}>{driftType.replace(/_/g, " ")}</span>;
}

export default function DeviceDetail() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const [device, setDevice] = useState<Device | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [routes, setRoutes] = useState<NetworkRoute[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [drift, setDrift] = useState<DriftEvent[]>([]);
  const [snapshots, setSnapshots] = useState<ConfigSnapshot[]>([]);
  const [securityDrift, setSecurityDrift] = useState<SecurityDriftFinding[]>([]);
  const [posture, setPosture] = useState<CompliancePostureHistory | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  // Live SNMP metrics (sysDescr/sysUptime + IF-MIB interface table) --
  // pulled on demand via the Device Gateway's GET_FACTS/GET_INTERFACES
  // operations. These must explicitly request protocol="snmp": the
  // gateway's default transport resolution (registry.preferred_transport)
  // never picks SNMP for config collection (it's opt-in only, see
  // collectors/registry.py), so omitting it here would silently poll
  // SSH/NETCONF instead of the SNMP MIBs this panel is about.
  const [snmpFacts, setSnmpFacts] = useState<Record<string, any> | null>(null);
  const [snmpInterfaces, setSnmpInterfaces] = useState<Record<string, any>[]>([]);
  const [snmpHealth, setSnmpHealth] = useState<Record<string, any> | null>(null);
  const [latestSnapshot, setLatestSnapshot] = useState<Record<string, any> | null>(null);
  const [metricsHistory, setMetricsHistory] = useState<Record<string, any>[]>([]);
  const [snmpError, setSnmpError] = useState<string | null>(null);
  const [snmpLoading, setSnmpLoading] = useState(false);

  // Configuration History compare selection: up to two snapshot ids.
  const [compareSelection, setCompareSelection] = useState<string[]>([]);
  const [approving, setApproving] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  async function requestConfigCollection() {
    if (!deviceId) return;
    setScanning(true);
    try {
      await endpoints.collectAndScanDevice(deviceId, "ALL", device?.protocol || undefined);
      await reload();
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Scan request failed");
    } finally {
      setScanning(false);
    }
  }

  async function requestBackup() {
    if (!deviceId) return;
    setScanning(true);
    try {
      await endpoints.collectDeviceConfig(deviceId, device?.protocol || undefined);
      await reload();
      alert("Backup successfully collected.");
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Backup request failed");
    } finally {
      setScanning(false);
    }
  }

  function reload() {
    if (!deviceId) return;
    
    // Safely swallow 404s for optional telemetry endpoints
    const safeGet = (fetcher: Promise<any>, fallback: any) => fetcher.catch((e) => ({ data: fallback }));
    
    return Promise.all([
      endpoints.device(deviceId),
      safeGet(endpoints.deviceInterfaces(deviceId), []),
      safeGet(endpoints.deviceRoutes(deviceId), []),
      safeGet(endpoints.deviceScans(deviceId), []),
      safeGet(endpoints.deviceDrift(deviceId), { events: [] }),
      safeGet(endpoints.deviceSnapshots(deviceId), { snapshots: [] }),
      safeGet(endpoints.deviceDriftHistory(deviceId), { findings: [] }),
      safeGet(endpoints.deviceComplianceHistory(deviceId), null),
    ]).then(([d, i, r, s, dr, snap, sdrift, hist]) => {
      setDevice(d.data);
      setInterfaces(i.data);
      setRoutes(r.data);
      setScans(s.data);
      setDrift(dr.data.events);
      setSnapshots(snap.data.snapshots);
      setSecurityDrift(sdrift.data.findings);
      setPosture(hist?.data || null);
    });
  }

  useEffect(() => {
    if (!deviceId) return;
    setLoading(true);
    setNotFound(false);
    reload()!
      .catch((e) => {
        if (e?.response?.status === 404) setNotFound(true);
      })
      .finally(() => setLoading(false));
      
    const interval = setInterval(() => {
      reload()!.catch(() => {});
    }, 5000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId]);

  if (loading) return <Loading />;
  if (notFound || !device) return <EmptyState message="Device not found." />;

  const latestSnapshot = snapshots[0];
  const approvedSnapshot = snapshots.find((s) => s.is_approved_baseline);
  const openDegradations = securityDrift.filter((f) => f.drift_type === "SECURITY_DEGRADATION" && f.status === "OPEN");

  function toggleCompare(snapshotId: string) {
    setCompareSelection((prev) => {
      if (prev.includes(snapshotId)) return prev.filter((id) => id !== snapshotId);
      if (prev.length >= 2) return [prev[1], snapshotId];
      return [...prev, snapshotId];
    });
  }

  async function approveAsBaseline(snapshotId: string) {
    if (!deviceId) return;
    const reason = window.prompt("Reason for approving this snapshot as the golden baseline (optional):") || undefined;
    setApproving(snapshotId);
    try {
      await endpoints.approveBaseline(deviceId, snapshotId, reason);
      await reload();
    } finally {
      setApproving(null);
    }
  }

  async function pollSnmp() {
    if (!deviceId) return;
    setSnmpLoading(true);
    setSnmpError(null);
    try {
      const [factsRes, ifacesRes] = await Promise.all([
        endpoints.gatewayGetFacts(deviceId, "snmp"),
        endpoints.gatewayGetInterfaces(deviceId, "snmp"),
      ]);
      setSnmpFacts((factsRes.data as any)?.data ?? null);
      setSnmpInterfaces((ifacesRes.data as any)?.data?.interfaces ?? []);
    } catch (e: any) {
      // Most common cause: no snmp_community/snmp_v3 credential stored for
      // this device yet (Devices page -> Authentication -> add SNMP), or
      // the device is unreachable on UDP/161 (firewalled/ACL'd).
      setSnmpFacts(null);
      setSnmpInterfaces([]);
      setSnmpError(
        e?.response?.data?.detail?.error || e?.response?.data?.detail || e?.message || "SNMP poll failed"
      );
    } finally {
      setSnmpLoading(false);
    }
    // Health metrics (CPU/memory/interface traffic) are polled separately
    // so a device/agent that doesn't support HOST-RESOURCES-MIB doesn't
    // block the identity/interface panel above from populating.
    try {
      const healthRes = await endpoints.gatewayGetHealthMetrics(deviceId, "snmp");
      setSnmpHealth((healthRes.data as any)?.data ?? null);
    } catch (e: any) {
      setSnmpHealth(null);
    }
    // Utilization and trend come from the persisted snapshot history
    // (app.workers.metrics_poller_worker), not the live poll above --
    // utilization needs two samples over time, a single live read can't
    // produce it.
    try {
      const [latestRes, historyRes] = await Promise.all([
        endpoints.metricsLatest(deviceId),
        endpoints.metricsHistory(deviceId, 24),
      ]);
      setLatestSnapshot((latestRes.data as any)?.snapshot ?? null);
      setMetricsHistory((historyRes.data as any)?.snapshots ?? []);
    } catch (e: any) {
      setLatestSnapshot(null);
      setMetricsHistory([]);
    }
  }

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
        {/* Security Posture ---------------------------------------------- */}
        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Security Posture</div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Current Compliance</div>
              <div className="text-2xl font-bold mt-1 text-slate-100">
                {device.last_compliance_score != null ? `${device.last_compliance_score}%` : "—"}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Last Audit</div>
              <div className="text-sm font-mono mt-1 text-slate-100">
                {scans[0] ? new Date(scans[0].created_at).toLocaleString() : "never"}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Last Snapshot</div>
              <div className="text-sm font-mono mt-1 text-slate-100">
                {latestSnapshot ? new Date(latestSnapshot.collected_at || "").toLocaleString() : "—"}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Configuration Hash</div>
              <div className="text-xs font-mono mt-1 text-slate-400 truncate" title={latestSnapshot?.configuration_hash || ""}>
                {latestSnapshot?.configuration_hash ? latestSnapshot.configuration_hash.slice(0, 16) + "…" : "—"}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Drift Status</div>
              <div className="mt-1">
                {openDegradations.length > 0 ? (
                  <span className="badge badge-critical">{openDegradations.length} DEGRADATION(S)</span>
                ) : securityDrift.length > 0 ? (
                  <span className="badge badge-na">DRIFT (NO DEGRADATION)</span>
                ) : (
                  <span className="badge badge-low">STABLE</span>
                )}
              </div>
            </div>
          </div>
          {posture?.summary && (
            <div className="mt-3 text-sm text-slate-400 border-t border-soc-border pt-3">{posture.summary}</div>
          )}
          {approvedSnapshot && (
            <div className="mt-2 text-xs text-slate-500">
              Approved baseline: snapshot {approvedSnapshot.snapshot_id.slice(0, 8)}… ·{" "}
              {new Date(approvedSnapshot.collected_at || "").toLocaleString()}
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card text-left">
            <div className="flex items-start justify-between">
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Collection Status</div>
                <div className="text-lg font-bold mt-2 text-slate-100">{device.collection_status || "never collected"}</div>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={requestBackup}
                  disabled={scanning}
                  title="Pull config snapshot without running full compliance scan"
                  className="text-xs px-3 py-1 bg-slate-900 border border-slate-700 text-slate-300 rounded hover:bg-slate-800 transition-colors disabled:opacity-50"
                >
                  {scanning ? "..." : "Backup Config"}
                </button>
                <button
                  onClick={requestConfigCollection}
                  disabled={scanning}
                  className="text-xs px-3 py-1 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 transition-colors disabled:opacity-50"
                >
                  {scanning ? "Scanning..." : "Request Scan"}
                </button>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Management Address</div>
            <div className="text-lg font-mono mt-2 text-slate-100">{device.management_address || "—"}</div>
          </div>
          <div className="card">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Serial</div>
            <div className="text-lg font-mono mt-2 text-slate-100">{device.serial_number || "—"}</div>
          </div>
          <div className="card">
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Golden Config (Baseline)</div>
            <div className="text-lg font-mono mt-2 text-slate-100">
              {approvedSnapshot ? "SET" : "NOT SET"}
            </div>
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

        {/* Configuration History ------------------------------------------ */}
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="font-semibold text-slate-200">Configuration History ({snapshots.length})</div>
            {compareSelection.length === 2 && deviceId && (
              <Link
                className="text-xs text-cyan-400 hover:underline"
                to={`/devices/${deviceId}/compare?a=${compareSelection[0]}&b=${compareSelection[1]}`}
              >
                Compare selected snapshots →
              </Link>
            )}
          </div>
          {snapshots.length === 0 ? (
            <div className="text-sm text-slate-500">No configuration snapshots recorded for this device yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <div className="flex gap-3 pb-2 min-w-full">
                {snapshots.slice().reverse().map((s) => (
                  <div
                    key={s.snapshot_id}
                    className={`flex-shrink-0 w-40 border rounded-lg p-3 text-xs cursor-pointer transition ${
                      compareSelection.includes(s.snapshot_id)
                        ? "border-cyan-500 bg-cyan-950/20"
                        : "border-soc-border hover:border-slate-600"
                    }`}
                    onClick={() => toggleCompare(s.snapshot_id)}
                  >
                    <div className="text-slate-300 font-semibold">
                      {s.collected_at ? new Date(s.collected_at).toLocaleDateString() : "—"}
                    </div>
                    <div className="text-slate-500 mt-1">
                      {s.collected_at ? new Date(s.collected_at).toLocaleTimeString() : ""}
                    </div>
                    <div className="mt-2 font-mono text-slate-400 truncate" title={s.configuration_hash || ""}>
                      {s.configuration_hash ? s.configuration_hash.slice(0, 10) + "…" : "—"}
                    </div>
                    <div className="mt-2 flex items-center gap-1 flex-wrap">
                      {s.compliance_score != null && (
                        <span className="text-slate-400">{s.compliance_score}%</span>
                      )}
                      {s.is_approved_baseline && <span className="badge badge-low">GOLDEN CONFIG</span>}
                    </div>
                    <div className="mt-2 flex items-center gap-2">
                      <Link className="text-cyan-400 hover:underline" to={`/scans/${s.scan_id}`}>
                        scan
                      </Link>
                      {!s.is_approved_baseline && (
                        <button
                          className="text-slate-500 hover:text-slate-300 underline disabled:opacity-50"
                          disabled={approving === s.snapshot_id}
                          onClick={(e) => {
                            e.stopPropagation();
                            approveAsBaseline(s.snapshot_id);
                          }}
                        >
                          {approving === s.snapshot_id ? "setting..." : "set as golden config"}
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              <div className="text-xs text-slate-500 mt-2">
                Select two snapshots to compare raw config + security baseline diff.
              </div>
            </div>
          )}
        </div>

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
          <div className="flex items-center justify-between mb-3">
            <div className="font-semibold text-slate-200">Live SNMP Metrics</div>
            <button
              className="text-xs px-3 py-1.5 rounded border border-soc-border text-cyan-400 hover:border-cyan-600 disabled:opacity-50"
              disabled={snmpLoading}
              onClick={pollSnmp}
            >
              {snmpLoading ? "Polling…" : "Poll via SNMP"}
            </button>
          </div>
          {snmpError && (
            <div className="text-xs text-red-400 mb-2">{snmpError}</div>
          )}
          {!snmpFacts && snmpInterfaces.length === 0 && !snmpError && (
            <div className="text-sm text-slate-500">
              Not polled yet. This pulls live sysDescr/sysUptime and the IF-MIB interface table
              directly from the device over SNMP -- separate from the interfaces parsed out of a
              collected configuration above. Requires an SNMP credential on this device
              (Devices → Authentication → SNMP Community/v3).
            </div>
          )}
          {snmpFacts && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 text-sm">
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">sysName</div>
                <div className="font-mono mt-1 text-slate-100">{snmpFacts.sys_name || "—"}</div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">sysDescr</div>
                <div className="font-mono mt-1 text-slate-100 truncate" title={snmpFacts.sys_descr}>
                  {snmpFacts.sys_descr || "—"}
                </div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">sysUpTime (ticks)</div>
                <div className="font-mono mt-1 text-slate-100">{snmpFacts.sys_uptime_ticks || "—"}</div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">sysObjectID</div>
                <div className="font-mono mt-1 text-slate-100 truncate" title={snmpFacts.sys_object_id}>
                  {snmpFacts.sys_object_id || "—"}
                </div>
              </div>
            </div>
          )}
          {snmpHealth && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 text-sm border-t border-soc-border pt-4">
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">CPU (avg)</div>
                <div className="font-mono mt-1 text-slate-100">
                  {snmpHealth.cpu_average_pct != null ? `${snmpHealth.cpu_average_pct}%` : "—"}
                </div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Memory Used</div>
                <div className="font-mono mt-1 text-slate-100">
                  {snmpHealth.memory_used_pct != null ? `${snmpHealth.memory_used_pct}%` : "—"}
                </div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Memory Total</div>
                <div className="font-mono mt-1 text-slate-100">
                  {snmpHealth.memory_total_bytes
                    ? `${(snmpHealth.memory_total_bytes / (1024 * 1024)).toFixed(0)} MB`
                    : "—"}
                </div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Interfaces Reporting</div>
                <div className="font-mono mt-1 text-slate-100">
                  {(snmpHealth.interface_health || []).length || "—"}
                </div>
              </div>
            </div>
          )}
          {snmpHealth?.interface_health?.length > 0 && (
            <div className="mb-4">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">
                Interface Traffic &amp; Errors (SNMP IF-MIB)
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-500 border-b border-soc-border">
                    <th className="py-2 pr-4">ifIndex</th>
                    <th className="py-2 pr-4">Name</th>
                    <th className="py-2 pr-4">In (octets)</th>
                    <th className="py-2 pr-4">Out (octets)</th>
                    <th className="py-2 pr-4">In Errors</th>
                    <th className="py-2 pr-4">Out Errors</th>
                    <th className="py-2 pr-4">Discards (in/out)</th>
                    <th className="py-2 pr-4">Utilization (in/out)</th>
                  </tr>
                </thead>
                <tbody>
                  {snmpHealth.interface_health.map((row: Record<string, any>) => {
                    const util = (latestSnapshot?.interface_utilization || []).find(
                      (u: Record<string, any>) => u.if_index === row.if_index
                    );
                    return (
                    <tr key={row.if_index} className="border-b border-soc-border/50">
                      <td className="py-2 pr-4 font-mono">{row.if_index}</td>
                      <td className="py-2 pr-4 font-mono">{row.name || "—"}</td>
                      <td className="py-2 pr-4 font-mono">{row.in_octets_hc ?? "—"}</td>
                      <td className="py-2 pr-4 font-mono">{row.out_octets_hc ?? "—"}</td>
                      <td className={`py-2 pr-4 font-mono ${Number(row.in_errors) > 0 ? "text-red-400" : ""}`}>
                        {row.in_errors ?? "—"}
                      </td>
                      <td className={`py-2 pr-4 font-mono ${Number(row.out_errors) > 0 ? "text-red-400" : ""}`}>
                        {row.out_errors ?? "—"}
                      </td>
                      <td className="py-2 pr-4 font-mono">
                        {row.in_discards ?? "—"} / {row.out_discards ?? "—"}
                      </td>
                      <td className="py-2 pr-4 font-mono">
                        {util ? (
                          <span
                            className={
                              (util.in_utilization_pct ?? 0) >= 90 || (util.out_utilization_pct ?? 0) >= 90
                                ? "text-red-400"
                                : (util.in_utilization_pct ?? 0) >= 70 || (util.out_utilization_pct ?? 0) >= 70
                                ? "text-amber-400"
                                : ""
                            }
                          >
                            {util.in_utilization_pct != null ? `${util.in_utilization_pct}%` : "—"} /{" "}
                            {util.out_utilization_pct != null ? `${util.out_utilization_pct}%` : "—"}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
              <div className="text-[11px] text-slate-500 mt-1">
                Utilization is derived from consecutive polled snapshots (app.workers.metrics_poller_worker) and
                requires an interface speed known from the SNMP interface table; it may read "—" until at least two
                poll cycles have completed.
              </div>
            </div>
          )}
          {metricsHistory.length > 1 && (
            <div className="mb-4">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">
                CPU &amp; Memory — Last 24h ({metricsHistory.length} samples)
              </div>
              <div className="flex items-end gap-[2px] h-16">
                {[...metricsHistory].reverse().map((snap, i) => (
                  <div key={snap.id || i} className="flex-1 flex flex-col justify-end gap-[1px]" title={
                    `${snap.collected_at}: CPU ${snap.cpu_average_pct ?? "—"}% / Mem ${snap.memory_used_pct ?? "—"}%`
                  }>
                    <div
                      className="bg-blue-500/70 w-full"
                      style={{ height: `${Math.min(100, snap.cpu_average_pct ?? 0)}%` }}
                    />
                    <div
                      className="bg-emerald-500/70 w-full"
                      style={{ height: `${Math.min(100, snap.memory_used_pct ?? 0)}%` }}
                    />
                  </div>
                ))}
              </div>
              <div className="flex gap-4 text-[11px] text-slate-500 mt-1">
                <span><span className="inline-block w-2 h-2 bg-blue-500/70 mr-1" />CPU %</span>
                <span><span className="inline-block w-2 h-2 bg-emerald-500/70 mr-1" />Memory %</span>
              </div>
            </div>
          )}
          {snmpInterfaces.length > 0 && (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border">
                  <th className="py-2 pr-4">ifIndex</th>
                  <th className="py-2 pr-4">Name</th>
                  <th className="py-2 pr-4">Admin</th>
                  <th className="py-2 pr-4">Oper</th>
                  <th className="py-2 pr-4">Speed (bps)</th>
                  <th className="py-2 pr-4">MAC</th>
                </tr>
              </thead>
              <tbody>
                {snmpInterfaces.map((row) => (
                  <tr key={row.if_index} className="border-b border-soc-border/50">
                    <td className="py-2 pr-4 font-mono">{row.if_index}</td>
                    <td className="py-2 pr-4 font-mono">{row.name || "—"}</td>
                    <td className="py-2 pr-4">{row.admin_status || "—"}</td>
                    <td className="py-2 pr-4">{row.oper_status || "—"}</td>
                    <td className="py-2 pr-4 font-mono">{row.speed_bps || "—"}</td>
                    <td className="py-2 pr-4 font-mono">{row.mac_address || "—"}</td>
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
          <div className="font-semibold text-slate-200 mb-3">Security Baseline Drift ({securityDrift.length})</div>
          {securityDrift.length === 0 ? (
            <div className="text-sm text-slate-500">
              No normalized security-baseline drift detected for this device.
            </div>
          ) : (
            <div className="space-y-2">
              {securityDrift.slice(0, 15).map((f) => (
                <div key={f.drift_id} className="flex items-center justify-between border-b border-soc-border/50 pb-2 last:border-0 text-sm">
                  <div>
                    <div className="font-mono text-slate-300">{f.baseline_parameter}</div>
                    <div className="text-xs text-slate-500">
                      {String(f.previous_value)} → {String(f.current_value)}
                      {f.compliance_controls.length > 0 && <> · {f.compliance_controls.join(", ")}</>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <DriftTypeBadge driftType={f.drift_type} />
                    <span className="text-xs text-slate-500">{f.status}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Recent Raw Config Drift ({drift.length})</div>
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