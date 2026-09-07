import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { endpoints, Device, DiscoveredHost, DiscoverResponse, NetworkScanJob, NetworkScanJobCreate } from "../api";
import { PageHeader, Loading } from "../components/ui";
import StatCard from "../components/StatCard";

const FRAMEWORKS = ["ALL", "CIS", "NIST", "DISA_STIG", "ISO_27001"];
const DEFAULT_PORTS = "22,23,80,161,443,830,8443,6030,57400";

function JobStatusBadge({ status }: { status: string }) {
  const cls: Record<string, string> = {
    PENDING: "bg-slate-800 text-slate-400 border border-slate-700",
    RUNNING: "bg-cyan-950 text-cyan-300 border border-cyan-800",
    COMPLETED: "bg-emerald-950 text-emerald-300 border border-emerald-800",
    PARTIAL: "bg-amber-950 text-amber-300 border border-amber-800",
    FAILED: "bg-red-950 text-red-300 border border-red-800",
  };
  return <span className={`badge ${cls[status] ?? "bg-slate-800 text-slate-400"}`}>{status}</span>;
}

function TransportHint({ hints }: { hints: string[] }) {
  const colors: Record<string, string> = {
    ssh: "bg-cyan-950 text-cyan-300 border border-cyan-800",
    telnet: "bg-red-950 text-red-300 border border-red-800",
    snmp: "bg-purple-950 text-purple-300 border border-purple-800",
    netconf: "bg-blue-950 text-blue-300 border border-blue-800",
    restconf: "bg-indigo-950 text-indigo-300 border border-indigo-800",
    gnmi: "bg-emerald-950 text-emerald-300 border border-emerald-800",
    https: "bg-slate-800 text-slate-300 border border-slate-700",
    http: "bg-slate-800 text-slate-400 border border-slate-700",
  };
  return (
    <div className="flex flex-wrap gap-1">
      {hints.map((h) => (
        <span key={h} className={`badge text-[10px] ${colors[h] ?? "bg-slate-800 text-slate-400 border border-slate-700"}`}>
          {h}
        </span>
      ))}
    </div>
  );
}

type Tab = "jobs" | "discovery";

function ScanJobsTab({ devices }: { devices: Device[] }) {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState<NetworkScanJob[] | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [selectedDevices, setSelectedDevices] = useState<string[]>([]);
  const [runDiscovery, setRunDiscovery] = useState(false);
  const [cidr, setCidr] = useState("");
  const [framework, setFramework] = useState("ALL");
  const [includeBatfish, setIncludeBatfish] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const loadJobs = () =>
    endpoints.networkScans().then((r) => setJobs(r.data)).catch(() => setJobs([]));

  useEffect(() => {
    loadJobs();
    const iv = setInterval(loadJobs, 5000);
    return () => clearInterval(iv);
  }, []);

  const toggleDevice = (id: string) =>
    setSelectedDevices((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!runDiscovery && selectedDevices.length === 0) {
      setFormError("Select at least one device, or enable discovery with a CIDR.");
      return;
    }
    if (runDiscovery && !cidr.trim()) {
      setFormError("CIDR is required for discovery.");
      return;
    }
    setFormError(null);
    setSubmitting(true);
    try {
      const payload: NetworkScanJobCreate = {
        name: name || undefined,
        device_ids: selectedDevices.length > 0 ? selectedDevices : undefined,
        run_discovery: runDiscovery,
        target_cidr: runDiscovery ? cidr.trim() : undefined,
        framework,
        include_batfish: includeBatfish,
      };
      const r = await endpoints.createNetworkScan(payload);
      navigate(`/network-scans/${r.data.id}`);
    } catch (err: any) {
      setFormError(err?.response?.data?.detail || String(err));
      setSubmitting(false);
    }
  };

  if (!jobs) return <Loading />;

  return (
    <div>
      <div className="px-8 pt-4">
        <button className="btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? "Cancel" : "＋ New Network Scan"}
        </button>
      </div>

      {showForm && (
        <div className="px-8 mt-4 mb-6">
          <form onSubmit={handleSubmit} className="card max-w-3xl flex flex-col gap-5">
            <div className="text-sm font-semibold text-slate-200 mb-1">Configure Network Scan</div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Scan Name (optional)</label>
              <input className="input w-full" placeholder="e.g. Weekly compliance sweep" value={name} onChange={(e) => setName(e.target.value)} />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-2">Target Devices</label>
              <div className="max-h-48 overflow-y-auto border border-soc-border rounded-lg divide-y divide-soc-border/50">
                {devices.length === 0 && (
                  <div className="px-4 py-3 text-slate-500 text-sm">No devices in inventory yet</div>
                )}
                {devices.map((d) => (
                  <label key={d.id} className="flex items-center gap-3 px-4 py-2 cursor-pointer hover:bg-slate-800/40">
                    <input
                      type="checkbox"
                      checked={selectedDevices.includes(d.id)}
                      onChange={() => toggleDevice(d.id)}
                      className="accent-cyan-500"
                    />
                    <span className="text-slate-300 text-sm">{d.hostname || d.management_address || d.id}</span>
                    {d.vendor && <span className="badge bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">{d.vendor}</span>}
                    {d.management_address && <span className="font-mono text-xs text-slate-500">{d.management_address}</span>}
                  </label>
                ))}
              </div>
            </div>

            <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={runDiscovery}
                onChange={(e) => setRunDiscovery(e.target.checked)}
                className="accent-cyan-500"
              />
              Also run nmap discovery over a CIDR range
            </label>

            {runDiscovery && (
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">CIDR Range *</label>
                <input className="input w-full" placeholder="10.0.0.0/24" value={cidr} onChange={(e) => setCidr(e.target.value)} />
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Framework</label>
                <select className="select w-full" value={framework} onChange={(e) => setFramework(e.target.value)}>
                  {FRAMEWORKS.map((f) => <option key={f}>{f}</option>)}
                </select>
              </div>
              <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer self-end mb-1.5 select-none">
                <input
                  type="checkbox"
                  checked={includeBatfish}
                  onChange={(e) => setIncludeBatfish(e.target.checked)}
                  className="accent-cyan-500"
                />
                Include Batfish analysis
              </label>
            </div>

            {formError && (
              <div className="text-red-400 text-sm bg-red-950/40 border border-red-800 rounded-lg px-3 py-2">{formError}</div>
            )}

            <div>
              <button type="submit" className="btn-primary" disabled={submitting}>
                {submitting ? "Creating…" : "Create Scan Job"}
              </button>
            </div>
          </form>
        </div>
      )}

      {jobs.length > 0 && (
        <div className="px-8 mt-6 grid grid-cols-1 md:grid-cols-3 gap-6">
          <StatCard label="Total Scan Jobs" value={jobs.length} accent="blue" />
          <StatCard label="In Progress" value={jobs.filter(j => j.status === 'RUNNING' || j.status === 'PENDING').length} accent="amber" />
          <StatCard label="Finished" value={jobs.filter(j => j.status === 'COMPLETED' || j.status === 'PARTIAL' || j.status === 'FAILED').length} accent="green" />
        </div>
      )}

      <div className="px-8 mb-8 mt-6">        {jobs.length === 0 ? (
          <div className="card text-slate-500 text-sm">No network scan jobs yet. Create one above.</div>
        ) : (
          <div className="card p-0 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-soc-border text-slate-500 text-xs uppercase tracking-wide">
                  <th className="px-4 py-3 text-left">Name / ID</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Target</th>
                  <th className="px-4 py-3 text-left">Framework</th>
                  <th className="px-4 py-3 text-left">Devices</th>
                  <th className="px-4 py-3 text-left">Created</th>
                  <th className="px-4 py-3 text-left">Completed</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => (
                  <tr key={j.id} className="border-b border-soc-border/50 hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3">
                      <Link to={`/network-scans/${j.id}`} className="text-cyan-400 hover:underline font-medium">
                        {j.name || j.id.slice(0, 12)}
                      </Link>
                      {j.name && <div className="text-slate-600 font-mono text-[10px]">{j.id.slice(0, 12)}</div>}
                    </td>
                    <td className="px-4 py-3"><JobStatusBadge status={j.status} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      {j.target_cidr ?? (j.run_discovery ? "—" : "devices only")}
                    </td>
                    <td className="px-4 py-3">
                      <span className="badge bg-slate-800 text-slate-300 border border-slate-700">{j.framework}</span>
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {j.resolved_device_ids?.length ?? j.device_results?.length ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">
                      {j.created_at ? new Date(j.created_at).toLocaleString() : "—"}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">
                      {j.completed_at ? new Date(j.completed_at).toLocaleString() : "—"}
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

function DiscoveryTab({ existingDevices, onImported }: { existingDevices: Device[]; onImported: () => void }) {
  const navigate = useNavigate();
  const [cidr, setCidr] = useState("");
  const [ports, setPorts] = useState(DEFAULT_PORTS);
  const [serviceDetection, setServiceDetection] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<DiscoverResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const existingAddresses = useRef<Set<string>>(new Set());
  useEffect(() => {
    existingAddresses.current = new Set(
      existingDevices.map((d) => d.management_address).filter(Boolean) as string[]
    );
  }, [existingDevices]);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<{ count: number; deviceIds: string[] } | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cidr.trim()) return;
    setScanning(true);
    setResult(null);
    setError(null);
    setSelected(new Set());
    setImportResult(null);
    try {
      const r = await endpoints.discover({ cidr: cidr.trim(), ports: ports || undefined, service_detection: serviceDetection });
      setResult(r.data);
      const newHosts = r.data.hosts.filter((h: DiscoveredHost) => !existingAddresses.current.has(h.ip));
      setSelected(new Set(newHosts.map((h: DiscoveredHost) => h.ip)));
    } catch (err: any) {
      setError(err?.response?.data?.detail || String(err));
    } finally {
      setScanning(false);
    }
  };

  const toggleSelect = (ip: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(ip) ? next.delete(ip) : next.add(ip);
      return next;
    });
  };

  const toggleAll = () => {
    if (!result) return;
    const newHosts = result.hosts.filter((h) => !existingAddresses.current.has(h.ip));
    if (selected.size === newHosts.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(newHosts.map((h) => h.ip)));
    }
  };

  const handleImport = async () => {
    if (!result || selected.size === 0) return;
    setImporting(true);
    try {
      const hosts = result.hosts
        .filter((h) => selected.has(h.ip))
        .map((h) => ({ ip: h.ip, hostname: h.hostname ?? undefined, vendor_guess: h.vendor_guess ?? undefined }));
      const r = await endpoints.discoverImport({ hosts });
      const created: Device[] = r.data;
      setImportResult({ count: created.length, deviceIds: created.map((d) => d.id) });
      for (const d of created) {
        if (d.management_address) existingAddresses.current.add(d.management_address);
      }
      setSelected(new Set());
      onImported(); // refresh the shared device list so the Scan Jobs tab sees new devices too
    } catch (err: any) {
      setError(err?.response?.data?.detail || String(err));
    } finally {
      setImporting(false);
    }
  };

  const newHostCount = result ? result.hosts.filter((h) => !existingAddresses.current.has(h.ip)).length : 0;

  return (
    <div>
      <div className="px-8 pt-4">
        <form onSubmit={handleScan} className="card max-w-2xl flex flex-col gap-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">CIDR or Host *</label>
              <input
                className="input w-full"
                placeholder="10.0.0.0/24 or 192.168.1.1"
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Ports (comma-separated)</label>
              <input
                className="input w-full font-mono text-xs"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder={DEFAULT_PORTS}
              />
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={serviceDetection}
              onChange={(e) => setServiceDetection(e.target.checked)}
              className="accent-cyan-500"
            />
            Run service detection (slower, provides vendor guesses and banners)
          </label>
          <div className="flex items-center gap-3">
            <button type="submit" className="btn-primary" disabled={scanning || !cidr.trim()}>
              {scanning ? "Scanning…" : "Run Discovery"}
            </button>
            {scanning && (
              <span className="text-xs text-slate-400 animate-pulse">
                Nmap scan in progress — duration reflects real network latency
              </span>
            )}
          </div>
          {error && (
            <div className="text-red-400 text-sm bg-red-950/40 border border-red-800 rounded-lg px-3 py-2">
              {error}
            </div>
          )}
        </form>
      </div>

      {importResult && (
        <div className="px-8 mt-4">
          <div className="bg-emerald-950/40 border border-emerald-700 rounded-xl px-5 py-3 flex items-center justify-between">
            <span className="text-emerald-300 font-semibold">
              {importResult.count} device{importResult.count !== 1 ? "s" : ""} added to inventory
            </span>
            <button className="btn-primary text-sm" onClick={() => navigate("/devices")}>
              View Devices →
            </button>
          </div>
        </div>
      )}

      {result && (
        <div className="px-8 mt-6 mb-8">
          <div className="flex items-center justify-between mb-3">
            <div className="font-semibold text-slate-200">
              {result.host_count} host{result.host_count !== 1 ? "s" : ""} found in{" "}
              <span className="font-mono text-cyan-400">{result.cidr}</span>
              <span className="ml-3 text-xs text-slate-500">
                {newHostCount} new · {result.host_count - newHostCount} already in inventory
              </span>
            </div>
            <div className="flex gap-2">
              <button className="btn-secondary text-sm" onClick={toggleAll}>
                {selected.size === newHostCount && newHostCount > 0 ? "Deselect All" : "Select All New"}
              </button>
              <button
                className="btn-primary text-sm"
                disabled={selected.size === 0 || importing}
                onClick={handleImport}
              >
                {importing ? "Importing…" : `Import Selected (${selected.size})`}
              </button>
            </div>
          </div>

          <div className="card p-0 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-soc-border text-slate-500 text-xs uppercase tracking-wide">
                  <th className="px-4 py-3 text-left w-10"></th>
                  <th className="px-4 py-3 text-left">IP Address</th>
                  <th className="px-4 py-3 text-left">Hostname</th>
                  <th className="px-4 py-3 text-left">Vendor Guess</th>
                  <th className="px-4 py-3 text-left">Transports</th>
                  <th className="px-4 py-3 text-left">Open Ports</th>
                  <th className="px-4 py-3 text-left">Banner</th>
                  <th className="px-4 py-3 text-left">Status</th>
                </tr>
              </thead>
              <tbody>
                {result.hosts.map((host) => {
                  const isKnown = existingAddresses.current.has(host.ip);
                  return (
                    <tr
                      key={host.ip}
                      className={`border-b border-soc-border/50 transition-colors ${
                        isKnown ? "opacity-50" : "hover:bg-slate-800/30"
                      }`}
                    >
                      <td className="px-4 py-3">
                        {!isKnown && (
                          <input
                            type="checkbox"
                            checked={selected.has(host.ip)}
                            onChange={() => toggleSelect(host.ip)}
                            className="accent-cyan-500"
                          />
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-cyan-400 font-semibold">{host.ip}</td>
                      <td className="px-4 py-3 text-slate-300">{host.hostname ?? "—"}</td>
                      <td className="px-4 py-3">
                        {host.vendor_guess ? (
                          <span className="badge bg-slate-800 text-slate-200 border border-slate-700">{host.vendor_guess}</span>
                        ) : "—"}
                      </td>
                      <td className="px-4 py-3">
                        <TransportHint hints={host.transport_hints} />
                      </td>
                      <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                        {host.open_ports.join(", ") || "—"}
                      </td>
                      <td className="px-4 py-3 text-slate-500 text-xs max-w-[180px] truncate" title={host.banner ?? ""}>
                        {host.banner ?? "—"}
                      </td>
                      <td className="px-4 py-3">
                        {isKnown ? (
                          <span className="badge bg-slate-800 text-slate-400 border border-slate-700">Already in inventory</span>
                        ) : (
                          <span className="badge bg-cyan-950 text-cyan-300 border border-cyan-800">New</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default function NetworkScans({ initialTab }: { initialTab?: Tab }) {
  const [searchParams] = useSearchParams();
  const tabFromQuery = searchParams.get("tab") === "discovery" ? "discovery" : undefined;
  const [tab, setTab] = useState<Tab>(initialTab || tabFromQuery || "jobs");
  const [devices, setDevices] = useState<Device[]>([]);

  const loadDevices = () => {
    endpoints.devices({ limit: 500 }).then((r) => {
      const items = (r.data as any).items ?? r.data;
      setDevices(Array.isArray(items) ? items : []);
    }).catch(() => {});
  };

  useEffect(() => {
    loadDevices();
  }, []);

  return (
    <div>
      <PageHeader
        title="Network Scans & Discovery"
        subtitle="Probe your network for reachable devices and orchestrate discovery → collection → compliance → risk analysis scans, in one place"
      />
      <div className="px-8">
        <div className="flex gap-1 border-b border-soc-border">
          <button
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === "jobs" ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
            onClick={() => setTab("jobs")}
          >
            Scan Jobs
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === "discovery" ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
            onClick={() => setTab("discovery")}
          >
            Quick Discovery
          </button>
        </div>
      </div>
      {tab === "jobs" ? (
        <ScanJobsTab devices={devices} />
      ) : (
        <DiscoveryTab existingDevices={devices} onImported={loadDevices} />
      )}
    </div>
  );
}