import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { endpoints, Device, DiscoveredHost, DiscoveryJob } from "../api";
import { PageHeader, Loading } from "../components/ui";

const DEFAULT_PORTS = "22,23,80,161,443,830,8443,6030,57400";
const POLL_MS = 1500;
const ACTIVE_STATUSES = new Set(["PENDING", "RUNNING", "PAUSED"]);

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

function DiscoveryProgress({ job, onPause, onResume, onCancel, busy }: {
  job: DiscoveryJob;
  onPause: () => void;
  onResume: () => void;
  onCancel: () => void;
  busy: boolean;
}) {
  const active = ACTIVE_STATUSES.has(job.status);
  const toneClass =
    job.status === "FAILED" ? "text-red-400"
    : job.status === "CANCELLED" ? "text-slate-400"
    : job.status === "PAUSED" ? "text-amber-400"
    : "text-cyan-400";
  return (
    <div className="card max-w-2xl mt-4">
      <div className="flex items-center justify-between mb-2">
        <span className={`text-sm font-semibold ${toneClass}`}>
          {job.status === "PENDING" && "Starting nmap scan…"}
          {job.status === "RUNNING" && `Scanning… ${job.scanned_targets}/${job.total_targets || "?"} address(es)`}
          {job.status === "PAUSED" && `Paused at ${job.scanned_targets}/${job.total_targets} address(es)`}
          {job.status === "COMPLETED" && `Scan complete — ${job.host_count} host(s) found`}
          {job.status === "FAILED" && "Scan failed"}
          {job.status === "CANCELLED" && "Scan cancelled"}
        </span>
        <div className="flex gap-2">
          {job.status === "RUNNING" && (
            <button className="btn-secondary text-xs" disabled={busy} onClick={onPause}>Pause</button>
          )}
          {job.status === "PAUSED" && (
            <button className="btn-primary text-xs" disabled={busy} onClick={onResume}>Resume</button>
          )}
          {active && (
            <button className="btn-secondary text-xs text-red-400" disabled={busy} onClick={onCancel}>Cancel</button>
          )}
        </div>
      </div>
      {job.total_targets > 0 && (
        <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
          <div
            className={`h-full transition-all ${job.status === "PAUSED" ? "bg-amber-500" : "bg-cyan-500"}`}
            style={{ width: `${job.progress_pct}%` }}
          />
        </div>
      )}
      {job.error && (
        <div className="text-red-400 text-sm mt-2">{job.error}</div>
      )}
      <div className="text-xs text-slate-500 mt-2">
        This scan runs in the background — you can navigate away and come back; it will not block the rest of the app.
      </div>
    </div>
  );
}

export default function Discovery() {
  const navigate = useNavigate();
  const [cidr, setCidr] = useState("");
  const [ports, setPorts] = useState(DEFAULT_PORTS);
  const [serviceDetection, setServiceDetection] = useState(true);
  const [starting, setStarting] = useState(false);
  const [job, setJob] = useState<DiscoveryJob | null>(null);
  const [jobBusy, setJobBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [osDetection, setOsDetection] = useState(false);
  const pollRef = useRef<number | null>(null);

  // Existing devices list for "Already known" cross-reference
  const [existingDevices, setExistingDevices] = useState<Device[]>([]);
  const existingAddresses = useRef<Set<string>>(new Set());

  // Import state
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<{ count: number; deviceIds: string[] } | null>(null);

  useEffect(() => {
    endpoints.devices({ limit: 500 }).then((r) => {
      const items = r.data.items ?? r.data;
      setExistingDevices(Array.isArray(items) ? items : []);
      existingAddresses.current = new Set(
        (Array.isArray(items) ? items : [])
          .map((d: Device) => d.management_address)
          .filter(Boolean) as string[]
      );
    }).catch(() => {});
  }, []);

  // Poll the active job until it reaches a terminal state.
  useEffect(() => {
    if (!job || !ACTIVE_STATUSES.has(job.status)) {
      if (pollRef.current) window.clearInterval(pollRef.current);
      return;
    }
    pollRef.current = window.setInterval(async () => {
      try {
        const r = await endpoints.getDiscoveryJob(job.id);
        setJob(r.data);
        if (!ACTIVE_STATUSES.has(r.data.status)) {
          const newHosts = r.data.hosts.filter((h) => !existingAddresses.current.has(h.ip));
          setSelected(new Set(newHosts.map((h) => h.ip)));
        }
      } catch {
        // transient poll failure -- try again next tick
      }
    }, POLL_MS);
    return () => { if (pollRef.current) window.clearInterval(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job?.id, job?.status]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cidr.trim()) return;
    setStarting(true);
    setJob(null);
    setError(null);
    setSelected(new Set());
    setImportResult(null);
    try {
      const r = await endpoints.discover({ cidr: cidr.trim(), ports: ports || undefined, service_detection: serviceDetection, os_detection: osDetection });
      setJob(r.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || String(err));
    } finally {
      setStarting(false);
    }
  };

  const withJobBusy = (fn: () => Promise<any>) => async () => {
    setJobBusy(true);
    try {
      const r = await fn();
      setJob(r.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || String(err));
    } finally {
      setJobBusy(false);
    }
  };
  const handlePause = withJobBusy(() => endpoints.pauseDiscoveryJob(job!.id));
  const handleResume = withJobBusy(() => endpoints.resumeDiscoveryJob(job!.id));
  const handleCancel = withJobBusy(() => endpoints.cancelDiscoveryJob(job!.id));

  const toggleSelect = (ip: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(ip) ? next.delete(ip) : next.add(ip);
      return next;
    });
  };

  const toggleAll = () => {
    if (!job) return;
    const newHosts = job.hosts.filter((h) => !existingAddresses.current.has(h.ip));
    if (selected.size === newHosts.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(newHosts.map((h) => h.ip)));
    }
  };

  const handleImport = async () => {
    if (!job || selected.size === 0) return;
    setImporting(true);
    try {
      const hosts = job.hosts
        .filter((h) => selected.has(h.ip))
        .map((h) => ({ ip: h.ip, hostname: h.hostname ?? undefined, vendor_guess: h.vendor_guess ?? undefined }));
      const r = await endpoints.discoverImport({ hosts });
      const created: Device[] = r.data;
      setImportResult({ count: created.length, deviceIds: created.map((d) => d.id) });
      // Update existing addresses so re-imports are idempotent
      for (const d of created) {
        if (d.management_address) existingAddresses.current.add(d.management_address);
      }
      setSelected(new Set());
    } catch (err: any) {
      setError(err?.response?.data?.detail || String(err));
    } finally {
      setImporting(false);
    }
  };

  const newHostCount = job ? job.hosts.filter((h) => !existingAddresses.current.has(h.ip)).length : 0;
  const scanning = starting || (job !== null && ACTIVE_STATUSES.has(job.status));

  return (
    <div>
      <PageHeader
        title="Network Discovery"
        subtitle="Probe a CIDR range with nmap to find reachable devices before importing them into inventory"
      />

      {/* Scan form */}
      <div className="px-8">
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
          <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={osDetection}
              onChange={(e) => setOsDetection(e.target.checked)}
              className="accent-purple-500"
            />
            Run OS detection{" "}
            <span className="text-xs text-slate-500">(requires nmap CAP_NET_RAW / root privileges)</span>
          </label>
          <div className="flex items-center gap-3">
            <button type="submit" className="btn-primary" disabled={scanning || !cidr.trim()}>
              {starting ? "Starting…" : scanning ? "Scanning…" : "Run Discovery"}
            </button>
          </div>
          {error && (
            <div className="text-red-400 text-sm bg-red-950/40 border border-red-800 rounded-lg px-3 py-2">
              {error}
            </div>
          )}
        </form>
      </div>

      {job && (
        <div className="px-8">
          <DiscoveryProgress job={job} onPause={handlePause} onResume={handleResume} onCancel={handleCancel} busy={jobBusy} />
        </div>
      )}

      {/* Import success banner */}
      {importResult && (
        <div className="px-8 mt-4">
          <div className="bg-emerald-950/40 border border-emerald-700 rounded-xl px-5 py-3 flex items-center justify-between">
            <span className="text-emerald-300 font-semibold">
              {importResult.count} device{importResult.count !== 1 ? "s" : ""} added to inventory
            </span>
            <button
              className="btn-primary text-sm"
              onClick={() => navigate("/devices")}
            >
              View Devices →
            </button>
          </div>
        </div>
      )}

      {/* Results table */}
      {job && job.hosts.length > 0 && (
        <div className="px-8 mt-6 mb-8">
          <div className="flex items-center justify-between mb-3">
            <div className="font-semibold text-slate-200">
              {job.host_count} host{job.host_count !== 1 ? "s" : ""} found in{" "}
              <span className="font-mono text-cyan-400">{job.cidr}</span>
              <span className="ml-3 text-xs text-slate-500">
                {newHostCount} new · {job.host_count - newHostCount} already in inventory
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
                  <th className="px-4 py-3 text-left">OS Guess</th>
                  <th className="px-4 py-3 text-left">Transports</th>
                  <th className="px-4 py-3 text-left">Open Ports</th>
                  <th className="px-4 py-3 text-left">Banner</th>
                  <th className="px-4 py-3 text-left">Status</th>
                </tr>
              </thead>
              <tbody>
                {job.hosts.map((host) => {
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
                        {host.os_guess ? (
                          <span className="badge bg-violet-950 text-violet-300 border border-violet-800" title={host.os_guess}>
                            {host.os_guess.length > 28 ? host.os_guess.slice(0, 28) + "…" : host.os_guess}
                          </span>
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