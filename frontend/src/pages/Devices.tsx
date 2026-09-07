import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, Device, DeviceCreatePayload } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

function SnmpIndicator({ deviceId, protocol }: { deviceId: string; protocol: string | null | undefined }) {
  const [status, setStatus] = useState<"loading" | "up" | "down" | "none">("loading");
  const [uptime, setUptime] = useState<string>("");

  useEffect(() => {
    // Only attempt SNMP poll if the device indicates it uses SNMP, or if protocol is null (auto-detect)
    if (protocol && protocol !== "snmp") {
      setStatus("none");
      return;
    }
    endpoints.gatewayGetFacts(deviceId, "snmp")
      .then(res => {
        const facts = (res.data as any)?.data;
        if (facts && facts.sys_uptime_ticks) {
          setStatus("up");
          setUptime(facts.sys_uptime_ticks);
        } else {
          setStatus("down");
        }
      })
      .catch(() => setStatus("down"));
  }, [deviceId, protocol]);

  if (status === "none") return <span className="text-slate-600" title={`Protocol is ${protocol}`}>—</span>;
  if (status === "loading") return <span className="text-slate-500 animate-pulse">polling...</span>;
  if (status === "down") return <span className="text-red-400" title="SNMP Unreachable">Timeout</span>;
  return <span className="text-emerald-400 font-medium text-xs whitespace-nowrap overflow-hidden text-ellipsis block max-w-[120px]" title={uptime}>Live ({uptime.split(' ')[0] || "up"})</span>;
}

function DeviceFormModal({
  onClose,
  onSave,
  initialData,
}: {
  onClose: () => void;
  onSave: (data: DeviceCreatePayload, creds: any) => Promise<void>;
  initialData?: DeviceCreatePayload & { id?: string };
}) {
  const [formData, setFormData] = useState<DeviceCreatePayload>(
    initialData || { name: "", management_address: "", vendor: "", model: "", site: "", environment: "", protocol: "" }
  );
  
  // Credentials state
  const [sshUsername, setSshUsername] = useState("");
  const [sshPassword, setSshPassword] = useState("");
  const [snmpCommunity, setSnmpCommunity] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (saving) return; // guard against double-submit (double-click / Enter + click)
    setSaving(true);
    setSaveError(null);
    try {
      await onSave(formData, { sshUsername, sshPassword, snmpCommunity });
      onClose();
    } catch (err: any) {
      setSaveError(err?.response?.data?.detail || err?.message || "Failed to save device.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-soc-panel border border-soc-border rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden my-8">
        <div className="px-6 py-4 border-b border-soc-border flex justify-between items-center">
          <h2 className="text-lg font-bold text-slate-100">{initialData?.id ? "Edit Device" : "Add Device"}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">&times;</button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Name / Hostname (Required)</label>
              <input required className="input w-full" value={formData.name || formData.hostname || ""} onChange={e => setFormData({ ...formData, name: e.target.value })} />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Management IP (Required)</label>
              <input required className="input w-full" value={formData.management_address || ""} onChange={e => setFormData({ ...formData, management_address: e.target.value })} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Vendor</label>
              <input className="input w-full" value={formData.vendor || ""} onChange={e => setFormData({ ...formData, vendor: e.target.value })} />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Model</label>
              <input className="input w-full" value={formData.model || ""} onChange={e => setFormData({ ...formData, model: e.target.value })} />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Site</label>
              <input className="input w-full" value={formData.site || ""} onChange={e => setFormData({ ...formData, site: e.target.value })} />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Environment</label>
              <select className="select w-full" value={formData.environment || ""} onChange={e => setFormData({ ...formData, environment: e.target.value })}>
                <option value="">-- Select --</option>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="lab">Lab</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Management Protocol</label>
              <select className="select w-full" value={formData.protocol || ""} onChange={e => setFormData({ ...formData, protocol: e.target.value })}>
                <option value="">Auto-Detect</option>
                <option value="ssh">SSH (CLI)</option>
                <option value="netconf">NETCONF</option>
                <option value="restconf">RESTCONF</option>
                <option value="snmp">SNMP</option>
              </select>
            </div>
          </div>
          
          <div className="mt-6 pt-4 border-t border-soc-border">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Authentication (Optional)</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">SSH Username</label>
                <input className="input w-full" value={sshUsername} onChange={e => setSshUsername(e.target.value)} placeholder="admin" autoComplete="off" />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">SSH Password</label>
                <input type="password" className="input w-full" value={sshPassword} onChange={e => setSshPassword(e.target.value)} placeholder="••••••••" autoComplete="off" />
              </div>
              <div className="col-span-2">
                <label className="block text-xs font-semibold text-slate-400 mb-1">SNMP Community (v2c)</label>
                <input type="password" className="input w-full" value={snmpCommunity} onChange={e => setSnmpCommunity(e.target.value)} placeholder="public" autoComplete="off" />
              </div>
            </div>
            <p className="text-xs text-slate-500 mt-2">Credentials are piped securely into OpenBao Vault.</p>
          </div>

          {saveError && (
            <div className="text-red-400 text-sm bg-red-950/40 border border-red-800 rounded-lg px-3 py-2">
              {saveError}
            </div>
          )}

          <div className="pt-4 flex justify-end gap-3 border-t border-soc-border mt-4">
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={saving} className="btn-primary">
              {saving ? "Saving..." : "Save Device"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [editingDevice, setEditingDevice] = useState<Device | null>(null);
  const [loading, setLoading] = useState(false);
  const [pageError, setPageError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const [page, setPage] = useState(1);
  const limit = 20;
  const [search, setSearch] = useState("");
  const [total, setTotal] = useState(0);

  const load = (silent = false) => {
    if (!silent) setLoading(true);
    endpoints.devices({ limit, offset: (page - 1) * limit, search: search || undefined }).then((r) => {
      const items = (r.data as any).items ?? r.data;
      setDevices(Array.isArray(items) ? items : []);
      setTotal((r.data as any).total ?? items?.length ?? 0);
    }).catch((err) => {
      setPageError(err?.response?.data?.detail || "Failed to load devices.");
    }).finally(() => { if (!silent) setLoading(false); });
  };

  useEffect(() => {
    load();
    const interval = setInterval(() => load(true), 5000);
    return () => clearInterval(interval);
  }, [page, search]);

  const handleSave = async (data: DeviceCreatePayload, creds: any) => {
    let targetDeviceId = editingDevice?.id;
    // Ensure hostname is always populated -- the form only collects "name",
    // but list/detail views and the collector pipeline key off `hostname`.
    // Previously devices could be created with hostname: null, which showed
    // up as a blank/duplicate-looking row.
    const submitData: DeviceCreatePayload = {
      ...data,
      hostname: data.hostname || data.name || undefined,
    };
    if (editingDevice) {
      await endpoints.updateDevice(targetDeviceId!, submitData);
    } else {
      const response = await endpoints.createDevice(submitData);
      targetDeviceId = response.data.id;
    }

    // Attempt uploading credentials
    if (targetDeviceId && (creds.sshUsername || creds.sshPassword)) {
       await endpoints.storeCredentials(targetDeviceId, "ssh_password", { username: creds.sshUsername, password: creds.sshPassword });
    }
    if (targetDeviceId && creds.snmpCommunity) {
       await endpoints.storeCredentials(targetDeviceId, "snmp_community", { community: creds.snmpCommunity });
    }

    setPageError(null);
    load();
  };

  const handleDelete = async (id: string) => {
    if (deletingId) return; // guard against double-click firing two DELETEs
    if (confirm("Are you sure you want to delete this device? This will remove all associated findings and scans.")) {
      setDeletingId(id);
      setPageError(null);
      try {
        await endpoints.deleteDevice(id);
        load();
      } catch (err: any) {
        setPageError(err?.response?.data?.detail || "Failed to delete device. You may not have permission.");
      } finally {
        setDeletingId(null);
      }
    }
  };

  const toggleStatus = async (d: Device) => {
    setPageError(null);
    try {
      if (d.enabled) {
        await endpoints.disableDevice(d.id);
      } else {
        await endpoints.enableDevice(d.id);
      }
      load();
    } catch (err: any) {
      setPageError(err?.response?.data?.detail || "Failed to update device status.");
    }
  };

  if (!devices) return <Loading />;

  return (
    <div>
      <PageHeader
        title="Device Inventory"
        subtitle="Manage network devices, run discoveries, and collect configurations"
        action={
          <div className="flex gap-2">
            <Link to="/network-scans?tab=discovery" className="btn-secondary">Network Discovery</Link>
            <button onClick={() => { setEditingDevice(null); setShowModal(true); }} className="btn-primary">
              + Add Device
            </button>
          </div>
        }
      />
      <div className="px-8 pb-8">
        {pageError && (
          <div className="text-red-400 text-sm bg-red-950/40 border border-red-800 rounded-lg px-3 py-2 mb-3">
            {pageError}
          </div>
        )}
        <div className="flex gap-4 mb-4 items-center">
          <input 
            type="text" 
            placeholder="Search hostname, IP, or tags..." 
            className="input max-w-sm" 
            value={search} 
            onChange={(e) => { setSearch(e.target.value); setPage(1); }} 
          />
        </div>
        {loading && <div className="text-cyan-400 text-sm mb-2 text-right">Refreshing inventory...</div>}
        {devices.length === 0 && !loading ? (
          <EmptyState message="No devices in inventory yet. Add one manually or use Network Discovery." />
        ) : (
          <div className="card p-0 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-soc-border bg-slate-900/30">
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Hostname / Name</th>
                  <th className="px-4 py-3">Mgmt IP</th>
                  <th className="px-4 py-3">Hardware / OS</th>
                  <th className="px-4 py-3">Environment</th>
                  <th className="px-4 py-3">SNMP State</th>
                  <th className="px-4 py-3" title="Compliance Score">C-Score</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id} className={`border-b border-soc-border/50 hover:bg-slate-800/30 ${!d.enabled ? 'opacity-50' : ''}`}>
                    <td className="px-4 py-3">
                      <button onClick={() => toggleStatus(d)} className={`w-3 h-3 rounded-full ${d.enabled ? 'bg-emerald-500' : 'bg-slate-500'}`} title={d.enabled ? 'Enabled (Click to disable)' : 'Disabled (Click to enable)'} />
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-200">
                      <Link className="text-cyan-400 hover:underline" to={`/devices/${d.id}`}>
                        {d.hostname || d.name || "—"}
                      </Link>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400 text-xs">{d.management_address || "—"}</td>
                    <td className="px-4 py-3 text-xs">
                      <div>{[d.vendor, d.model].filter(Boolean).join(" ") || "—"}</div>
                      <div className="text-slate-500">{[d.os, d.version].filter(Boolean).join(" ")}</div>
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {d.environment && <span className="badge bg-slate-800 border-slate-700 mx-1 inline-block">{d.environment}</span>}
                      {d.protocol && <span className="badge bg-slate-800 border-slate-700 mx-1 inline-block uppercase">{d.protocol}</span>}
                      {d.site && <span className="ml-1 text-slate-500">{d.site}</span>}
                      {(!d.environment && !d.site && !d.protocol) && "—"}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {d.enabled ? <SnmpIndicator deviceId={d.id} protocol={d.protocol} /> : <span className="text-slate-600">—</span>}
                    </td>
                    <td className="px-4 py-3 font-semibold">
                      {d.last_compliance_score != null ? (
                        <span className={d.last_compliance_score >= 80 ? "text-emerald-400" : d.last_compliance_score >= 50 ? "text-amber-400" : "text-red-400"}>
                          {d.last_compliance_score}%
                        </span>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-3 text-right space-x-3">
                      <button onClick={() => { setEditingDevice(d); setShowModal(true); }} className="text-slate-400 hover:text-cyan-400 transition-colors" title="Edit Device">
                        <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" /></svg>
                      </button>
                      <button onClick={() => handleDelete(d.id)} disabled={deletingId === d.id} className="text-slate-400 hover:text-red-400 transition-colors disabled:opacity-40 disabled:cursor-wait" title="Delete Device">
                        <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="px-4 py-3 border-t border-soc-border bg-slate-900 flex justify-between items-center text-sm text-slate-400">
              <div>Showing {(page - 1) * limit + 1} to {Math.min(page * limit, total)} of {total} devices</div>
              <div className="flex gap-2">
                <button disabled={page === 1} onClick={() => setPage(p => p - 1)} className="btn-secondary py-1 px-3">Prev</button>
                <button disabled={page * limit >= total} onClick={() => setPage(p => p + 1)} className="btn-secondary py-1 px-3">Next</button>
              </div>
            </div>
          </div>
        )}
      </div>
      {showModal && (
        <DeviceFormModal
          initialData={editingDevice ? {
            id: editingDevice.id,
            name: editingDevice.name || editingDevice.hostname || "",
            management_address: editingDevice.management_address || "",
            vendor: editingDevice.vendor || "",
            model: editingDevice.model || "",
            site: editingDevice.site || "",
            environment: editingDevice.environment || "",
            protocol: editingDevice.protocol || ""
          } : undefined}
          onClose={() => { setShowModal(false); setEditingDevice(null); }}
          onSave={handleSave}
        />
      )}
    </div>
  );
}