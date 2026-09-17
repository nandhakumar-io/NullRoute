import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  endpoints,
  Device,
  ConfigSnapshot,
  BackupDestination,
  BackupDestinationType,
  BackupJob,
  BackupFleetSummary,
} from "../api";
import { PageHeader, Loading, EmptyState, StatCard } from "../components/ui";

type Tab = "snapshots" | "destinations" | "jobs";

const TYPE_LABEL: Record<BackupDestinationType, string> = {
  s3: "AWS S3",
  azure_blob: "Azure Blob Storage",
  sftp: "SFTP / Remote Server",
  local: "Local Filesystem",
};

const TYPE_ICON: Record<BackupDestinationType, string> = {
  s3: "☁️",
  azure_blob: "🔷",
  sftp: "🖥️",
  local: "💾",
};

function StatusPill({ status }: { status: string | null | undefined }) {
  const s = (status || "NEVER_TESTED").toUpperCase();
  const cls =
    s === "SUCCESS"
      ? "badge badge-low"
      : s === "FAILED"
      ? "badge badge-critical"
      : s === "RUNNING" || s === "PENDING"
      ? "badge badge-medium"
      : "badge badge-na";
  return <span className={cls}>{s.replace(/_/g, " ")}</span>;
}

export default function Backups() {
  const [tab, setTab] = useState<Tab>("snapshots");
  const [summary, setSummary] = useState<BackupFleetSummary | null>(null);
  const [loadingSummary, setLoadingSummary] = useState(true);

  const loadSummary = useCallback(() => {
    setLoadingSummary(true);
    endpoints
      .backupSummary()
      .then((res) => setSummary(res.data))
      .catch(() => setSummary(null))
      .finally(() => setLoadingSummary(false));
  }, []);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  return (
    <div>
      <PageHeader
        title="Config Backup & Network Change & Operations (NCO)"
        subtitle="Enterprise configuration backup, golden-config management, and remote DR export — compliant with change-control and retention policy"
      />

      <div className="px-8 pb-4 grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          label="Snapshot Coverage"
          value={
            loadingSummary || !summary
              ? "…"
              : `${summary.devices_with_snapshot}/${summary.total_devices}`
          }
          tone={
            summary && summary.total_devices > 0 && summary.devices_without_snapshot === 0
              ? "low"
              : "medium"
          }
        />
        <StatCard
          label="Golden Configs Approved"
          value={loadingSummary || !summary ? "…" : summary.devices_with_golden_config}
          tone="good"
        />
        <StatCard
          label="Remote Destinations"
          value={loadingSummary || !summary ? "…" : summary.destination_count}
        />
        <StatCard
          label="Destinations Healthy"
          value={
            loadingSummary || !summary
              ? "…"
              : `${summary.destinations_healthy}/${summary.destination_count}`
          }
          tone={
            summary && summary.destinations_failing > 0
              ? "critical"
              : "low"
          }
        />
        <StatCard
          label="Recent Export Success"
          value={
            loadingSummary || !summary || summary.recent_jobs_evaluated === 0
              ? "—"
              : `${Math.round(
                  (summary.recent_jobs_success / summary.recent_jobs_evaluated) * 100
                )}%`
          }
          tone={
            summary && summary.recent_jobs_failed > 0 && summary.recent_jobs_evaluated > 0
              ? summary.recent_jobs_failed / summary.recent_jobs_evaluated > 0.1
                ? "critical"
                : "medium"
              : "low"
          }
        />
      </div>

      <div className="px-8 pb-4">
        <div className="flex gap-1 border-b border-soc-border">
          {(
            [
              ["snapshots", "Device Snapshots"],
              ["destinations", "Remote Destinations"],
              ["jobs", "Export Job History"],
            ] as [Tab, string][]
          ).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={`px-4 py-2 text-sm font-semibold border-b-2 transition-colors ${
                tab === key
                  ? "border-cyan-500 text-cyan-300"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {tab === "snapshots" && <SnapshotsTab onExported={loadSummary} />}
      {tab === "destinations" && <DestinationsTab onChanged={loadSummary} />}
      {tab === "jobs" && <JobsTab />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Snapshots tab
// ---------------------------------------------------------------------------

function SnapshotsTab({ onExported }: { onExported: () => void }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>("");
  const [snapshots, setSnapshots] = useState<ConfigSnapshot[]>([]);
  const [destinations, setDestinations] = useState<BackupDestination[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingSnapshots, setLoadingSnapshots] = useState(false);
  const [backingUp, setBackingUp] = useState(false);
  const [approving, setApproving] = useState<string | null>(null);
  const [exportModal, setExportModal] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportSelection, setExportSelection] = useState<Record<string, boolean>>({});
  const [exportResult, setExportResult] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      endpoints.devices({ limit: 500 }),
      endpoints.backupDestinations().catch(() => ({ data: { destinations: [] } } as any)),
    ])
      .then(([devRes, destRes]) => {
        const items = (devRes.data as any).items ?? (Array.isArray(devRes.data) ? devRes.data : []);
        setDevices(items);
        if (items.length > 0) setSelectedDeviceId(items[0].id);
        setDestinations(destRes.data.destinations || []);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedDeviceId) {
      setSnapshots([]);
      return;
    }
    loadSnapshots(selectedDeviceId);
  }, [selectedDeviceId]);

  function loadSnapshots(deviceId: string) {
    setLoadingSnapshots(true);
    endpoints
      .deviceSnapshots(deviceId)
      .then((res) => setSnapshots(res.data.snapshots || []))
      .catch(() => setSnapshots([]))
      .finally(() => setLoadingSnapshots(false));
  }

  async function requestBackup() {
    if (!selectedDeviceId) return;
    const device = devices.find((d) => d.id === selectedDeviceId);
    setBackingUp(true);
    try {
      // NOTE: this used to call endpoints.collectDeviceConfig() (POST
      // /api/devices/{id}/collect), which only writes device.last_config_raw
      // on the Device row -- it never creates a Scan, so the collected
      // config could never appear in the snapshot list below no matter how
      // many times "Take Backup Now" reported success. collectAndScanDevice
      // (POST /api/devices/{id}/scan) is the endpoint that actually creates
      // an archived, listable Scan row (see routers/backups.py's docstring:
      // a "snapshot" IS a Scan with raw_config_path set) and triggers
      // auto-export to any configured remote destinations.
      await endpoints.collectAndScanDevice(selectedDeviceId, "ALL", device?.protocol || undefined);
      loadSnapshots(selectedDeviceId);
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Backup request failed");
    } finally {
      setBackingUp(false);
    }
  }

  async function approveAsGolden(snapshotId: string) {
    if (!selectedDeviceId) return;
    const reason =
      window.prompt("Reason for setting this snapshot as the Golden Config (optional):") ||
      undefined;
    setApproving(snapshotId);
    try {
      await endpoints.approveBaseline(selectedDeviceId, snapshotId, reason);
      loadSnapshots(selectedDeviceId);
    } finally {
      setApproving(null);
    }
  }

  async function downloadSnapshot(snapshotId: string) {
    if (!selectedDeviceId) return;
    try {
      const res = await endpoints.downloadSnapshot(selectedDeviceId, snapshotId);
      const blob = new Blob([res.data.content], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = res.data.filename || `${snapshotId}.cfg`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Download failed");
    }
  }

  function openExportModal(snapshotId: string) {
    setExportModal(snapshotId);
    setExportResult(null);
    const initial: Record<string, boolean> = {};
    destinations.forEach((d) => (initial[d.id] = d.enabled));
    setExportSelection(initial);
  }

  async function runExport() {
    if (!exportModal || !selectedDeviceId) return;
    const ids = Object.entries(exportSelection)
      .filter(([, v]) => v)
      .map(([k]) => k);
    if (ids.length === 0) {
      alert("Select at least one destination");
      return;
    }
    setExporting(true);
    setExportResult(null);
    try {
      const res = await endpoints.exportSnapshot(selectedDeviceId, exportModal, ids);
      const lines = res.data.results.map(
        (r) => `${r.destination_name || r.destination_id}: ${r.status}${r.error ? " — " + r.error : ""}`
      );
      setExportResult(lines.join("\n"));
      onExported();
    } catch (e: any) {
      setExportResult(e?.response?.data?.detail || "Export failed");
    } finally {
      setExporting(false);
    }
  }

  if (loading) return <Loading />;

  return (
    <div className="px-8 pb-8 flex flex-col md:flex-row gap-6">
      {/* Device Sidebar */}
      <div className="w-full md:w-1/4 flex flex-col gap-4">
        <div className="card p-4">
          <h3 className="text-sm uppercase tracking-wide text-slate-500 font-semibold mb-3">
            Select Device
          </h3>
          <div className="space-y-1 max-h-[70vh] overflow-y-auto pr-2">
            {devices.map((d) => (
              <button
                key={d.id}
                onClick={() => setSelectedDeviceId(d.id)}
                className={`w-full text-left px-3 py-2 rounded text-sm transition-colors ${
                  selectedDeviceId === d.id
                    ? "bg-cyan-950/60 text-cyan-300 border border-cyan-800"
                    : "text-slate-300 hover:bg-slate-800 border border-transparent"
                }`}
              >
                <div className="font-semibold truncate">{d.hostname || "Unnamed"}</div>
                <div className="text-xs text-slate-500 truncate">
                  {d.management_address || d.id}
                </div>
              </button>
            ))}
            {devices.length === 0 && (
              <div className="text-xs text-slate-500 italic">No devices found.</div>
            )}
          </div>
        </div>
      </div>

      {/* Snapshot Main Area */}
      <div className="w-full md:w-3/4 flex flex-col gap-4">
        <div className="card h-full">
          <div className="flex items-center justify-between mb-6 pb-4 border-b border-soc-border">
            <div>
              <h2 className="text-lg font-bold text-slate-200">
                {devices.find((d) => d.id === selectedDeviceId)?.hostname || "Select a device"}{" "}
                Backups
              </h2>
              <div className="text-sm text-slate-500 mt-1">
                Showing {snapshots.length} recorded configurations
              </div>
            </div>
            <button
              onClick={requestBackup}
              disabled={backingUp || !selectedDeviceId}
              className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 transition-colors disabled:opacity-50 text-sm font-semibold shadow-lg shadow-cyan-900/20"
            >
              {backingUp ? "Taking Backup..." : "Take Backup Now"}
            </button>
          </div>

          {loadingSnapshots ? (
            <div className="py-20 flex justify-center">
              <Loading />
            </div>
          ) : !selectedDeviceId ? (
            <EmptyState message="Select a device to view its backup history" />
          ) : snapshots.length === 0 ? (
            <EmptyState message="No backups recorded for this device yet." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead>
                  <tr className="text-slate-500 border-b border-soc-border uppercase text-xs">
                    <th className="py-3 px-4">Date</th>
                    <th className="py-3 px-4">Config Hash</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshots.map((s) => (
                    <tr
                      key={s.snapshot_id}
                      className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <td className="py-3 px-4">
                        <div className="text-slate-200 font-semibold">
                          {new Date(s.collected_at || "").toLocaleDateString()}
                        </div>
                        <div className="text-xs text-slate-500">
                          {new Date(s.collected_at || "").toLocaleTimeString()}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-400">
                        {s.configuration_hash ? s.configuration_hash.slice(0, 16) + "..." : "—"}
                        <div className="text-[10px] text-slate-600 mt-1">
                          ID: {s.snapshot_id.slice(0, 8)}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        {s.is_approved_baseline ? (
                          <span className="badge badge-low">GOLDEN CONFIG</span>
                        ) : (
                          <span className="badge badge-na">ARCHIVED</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right space-x-3 whitespace-nowrap">
                        <button
                          onClick={() => downloadSnapshot(s.snapshot_id)}
                          className="text-slate-400 hover:text-slate-200 text-xs hover:underline"
                        >
                          Download
                        </button>
                        <button
                          onClick={() => openExportModal(s.snapshot_id)}
                          disabled={destinations.length === 0}
                          title={
                            destinations.length === 0
                              ? "No remote destinations configured yet"
                              : "Export to remote destination"
                          }
                          className="text-cyan-400 hover:text-cyan-300 text-xs hover:underline disabled:opacity-40 disabled:no-underline"
                        >
                          Export
                        </button>
                        <Link
                          to={`/devices/${selectedDeviceId}/compare`}
                          className="text-cyan-400 hover:text-cyan-300 text-xs hover:underline"
                        >
                          Compare
                        </Link>
                        {!s.is_approved_baseline && (
                          <button
                            onClick={() => approveAsGolden(s.snapshot_id)}
                            disabled={approving === s.snapshot_id}
                            className="text-slate-500 hover:text-slate-300 text-xs hover:underline disabled:opacity-50"
                          >
                            {approving === s.snapshot_id ? "Setting..." : "Set Golden"}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Export Modal */}
      {exportModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
          <div className="card w-full max-w-md">
            <h3 className="text-lg font-bold text-slate-200 mb-1">Export Snapshot</h3>
            <p className="text-xs text-slate-500 mb-4">
              Push this configuration snapshot to selected remote backup destinations.
            </p>
            <div className="space-y-2 max-h-64 overflow-y-auto mb-4">
              {destinations.map((d) => (
                <label
                  key={d.id}
                  className="flex items-center gap-3 px-3 py-2 rounded border border-soc-border hover:bg-slate-800/40 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={!!exportSelection[d.id]}
                    onChange={(e) =>
                      setExportSelection((prev) => ({ ...prev, [d.id]: e.target.checked }))
                    }
                  />
                  <span className="text-lg">{TYPE_ICON[d.destination_type]}</span>
                  <div className="flex-1">
                    <div className="text-sm text-slate-200">{d.name}</div>
                    <div className="text-xs text-slate-500">{TYPE_LABEL[d.destination_type]}</div>
                  </div>
                  <StatusPill status={d.last_test_status} />
                </label>
              ))}
            </div>
            {exportResult && (
              <pre className="text-xs bg-slate-900 border border-soc-border rounded p-3 mb-4 whitespace-pre-wrap text-slate-300">
                {exportResult}
              </pre>
            )}
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setExportModal(null)}
                className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200"
              >
                Close
              </button>
              <button
                onClick={runExport}
                disabled={exporting}
                className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 text-sm font-semibold disabled:opacity-50"
              >
                {exporting ? "Exporting..." : "Export Now"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Destinations tab
// ---------------------------------------------------------------------------

const EMPTY_FORM = {
  id: null as string | null,
  name: "",
  destination_type: "s3" as BackupDestinationType,
  enabled: true,
  auto_export_enabled: false,
  auto_export_all: true,
  retention_days: "" as string | number,
  // s3
  bucket: "",
  region: "us-east-1",
  endpoint_url: "",
  use_path_style: false,
  access_key_id: "",
  secret_access_key: "",
  session_token: "",
  // azure
  container: "",
  account_name: "",
  connection_string: "",
  sas_token: "",
  account_key: "",
  // sftp
  host: "",
  port: "22",
  remote_path: "/backups",
  username: "",
  password: "",
  private_key: "",
  // local
  base_path: "",
};

function DestinationsTab({ onChanged }: { onChanged: () => void }) {
  const [destinations, setDestinations] = useState<BackupDestination[]>([]);
  const [loading, setLoading] = useState(true);
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message: string }>>({});

  const load = useCallback(() => {
    setLoading(true);
    endpoints
      .backupDestinations()
      .then((res) => setDestinations(res.data.destinations || []))
      .catch(() => setDestinations([]))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function openNew() {
    setForm({ ...EMPTY_FORM });
    setFormOpen(true);
  }

  function openEdit(d: BackupDestination) {
    const c = d.config || {};
    setForm({
      ...EMPTY_FORM,
      id: d.id,
      name: d.name,
      destination_type: d.destination_type,
      enabled: d.enabled,
      auto_export_enabled: d.auto_export_enabled,
      auto_export_all: d.auto_export_scope?.all !== false,
      retention_days: d.retention_days ?? "",
      bucket: c.bucket || "",
      region: c.region || "us-east-1",
      endpoint_url: c.endpoint_url || "",
      use_path_style: !!c.use_path_style,
      container: c.container || "",
      account_name: c.account_name || "",
      host: c.host || "",
      port: String(c.port || "22"),
      remote_path: c.remote_path || "/backups",
      username: c.username || "",
      base_path: c.base_path || "",
    });
    setFormOpen(true);
  }

  function buildConfig() {
    if (form.destination_type === "s3") {
      return {
        bucket: form.bucket,
        region: form.region,
        endpoint_url: form.endpoint_url || undefined,
        use_path_style: form.use_path_style,
        path_prefix: "netsec-auditor-backups",
      };
    }
    if (form.destination_type === "azure_blob") {
      return {
        container: form.container,
        account_name: form.account_name || undefined,
        path_prefix: "netsec-auditor-backups",
      };
    }
    if (form.destination_type === "local") {
      return {
        base_path: form.base_path || undefined,
        path_prefix: "netsec-auditor-backups",
      };
    }
    return {
      host: form.host,
      port: Number(form.port) || 22,
      remote_path: form.remote_path,
      username: form.username,
      path_prefix: "netsec-auditor-backups",
    };
  }

  function buildSecret(): Record<string, any> | undefined {
    if (form.destination_type === "s3") {
      if (!form.access_key_id && !form.secret_access_key) return undefined;
      return {
        access_key_id: form.access_key_id,
        secret_access_key: form.secret_access_key,
        session_token: form.session_token || undefined,
      };
    }
    if (form.destination_type === "azure_blob") {
      if (!form.connection_string && !form.sas_token && !form.account_key) return undefined;
      return {
        connection_string: form.connection_string || undefined,
        sas_token: form.sas_token || undefined,
        account_key: form.account_key || undefined,
      };
    }
    if (form.destination_type === "local") {
      // No credential material -- this is a filesystem path on the
      // backend's own host/volume.
      return undefined;
    }
    if (!form.password && !form.private_key) return undefined;
    return {
      password: form.password || undefined,
      private_key: form.private_key || undefined,
    };
  }

  async function save() {
    if (!form.name.trim()) {
      alert("Name is required");
      return;
    }
    setSaving(true);
    const payload = {
      name: form.name,
      destination_type: form.destination_type,
      enabled: form.enabled,
      config: buildConfig(),
      secret: buildSecret(),
      auto_export_enabled: form.auto_export_enabled,
      auto_export_scope: { all: form.auto_export_all },
      retention_days: form.retention_days === "" ? null : Number(form.retention_days),
    };
    try {
      if (form.id) {
        await endpoints.updateBackupDestination(form.id, payload);
      } else {
        await endpoints.createBackupDestination(payload as any);
      }
      setFormOpen(false);
      load();
      onChanged();
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function remove(d: BackupDestination) {
    if (!window.confirm(`Delete destination "${d.name}"? This cannot be undone.`)) return;
    await endpoints.deleteBackupDestination(d.id);
    load();
    onChanged();
  }

  async function test(d: BackupDestination) {
    setTesting(d.id);
    try {
      const res = await endpoints.testBackupDestination(d.id);
      setTestResults((prev) => ({ ...prev, [d.id]: res.data }));
      load();
      onChanged();
    } finally {
      setTesting(null);
    }
  }

  if (loading) return <div className="px-8"><Loading /></div>;

  return (
    <div className="px-8 pb-8">
      <div className="flex justify-between items-center mb-4">
        <p className="text-sm text-slate-500 max-w-xl">
          Configure remote destinations for encrypted-at-rest, off-platform disaster-recovery
          copies of device configurations. Credentials are stored in OpenBao and never returned
          by the API.
        </p>
        <button
          onClick={openNew}
          className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 text-sm font-semibold whitespace-nowrap"
        >
          + Add Destination
        </button>
      </div>

      {destinations.length === 0 ? (
        <EmptyState message="No remote backup destinations configured. Add AWS S3, Azure Blob Storage, or an SFTP server to enable off-platform disaster-recovery exports." />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {destinations.map((d) => (
            <div key={d.id} className="card flex flex-col gap-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-2xl">{TYPE_ICON[d.destination_type]}</span>
                  <div>
                    <div className="font-semibold text-slate-200">{d.name}</div>
                    <div className="text-xs text-slate-500">{TYPE_LABEL[d.destination_type]}</div>
                  </div>
                </div>
                {!d.enabled && <span className="badge badge-na">DISABLED</span>}
              </div>

              <div className="text-xs text-slate-500 space-y-1">
                <div className="flex justify-between">
                  <span>Credentials</span>
                  <span className={d.has_credentials ? "text-emerald-400" : "text-amber-400"}>
                    {d.has_credentials ? "Configured" : "Using default chain"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Auto-export</span>
                  <span>{d.auto_export_enabled ? "Enabled (on every scan)" : "Manual only"}</span>
                </div>
                <div className="flex justify-between">
                  <span>Retention</span>
                  <span>{d.retention_days ? `${d.retention_days} days` : "Indefinite"}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span>Connectivity</span>
                  <StatusPill status={testResults[d.id]?.success !== undefined ? (testResults[d.id].success ? "SUCCESS" : "FAILED") : d.last_test_status} />
                </div>
                {(testResults[d.id]?.message || d.last_test_message) && (
                  <div className="text-[11px] text-slate-600 truncate" title={testResults[d.id]?.message || d.last_test_message || ""}>
                    {testResults[d.id]?.message || d.last_test_message}
                  </div>
                )}
                {d.last_export_at && (
                  <div className="flex justify-between">
                    <span>Last export</span>
                    <span className={d.last_export_status === "FAILED" ? "text-red-400" : "text-slate-400"}>
                      {new Date(d.last_export_at).toLocaleString()}
                    </span>
                  </div>
                )}
              </div>

              <div className="flex justify-between items-center pt-3 border-t border-soc-border mt-auto">
                <button
                  onClick={() => test(d)}
                  disabled={testing === d.id}
                  className="text-cyan-400 hover:text-cyan-300 text-xs hover:underline disabled:opacity-50"
                >
                  {testing === d.id ? "Testing..." : "Test Connection"}
                </button>
                <div className="space-x-3">
                  <button
                    onClick={() => openEdit(d)}
                    className="text-slate-400 hover:text-slate-200 text-xs hover:underline"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => remove(d)}
                    className="text-red-400 hover:text-red-300 text-xs hover:underline"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {formOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4 overflow-y-auto py-8">
          <div className="card w-full max-w-lg">
            <h3 className="text-lg font-bold text-slate-200 mb-4">
              {form.id ? "Edit Destination" : "Add Remote Backup Destination"}
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-500">Name</label>
                <input
                  className="input w-full"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. Primary DR — S3 (us-east-1)"
                />
              </div>

              <div>
                <label className="text-xs text-slate-500">Destination Type</label>
                <div className="grid grid-cols-4 gap-2 mt-1">
                  {(["s3", "azure_blob", "sftp", "local"] as BackupDestinationType[]).map((t) => (
                    <button
                      key={t}
                      type="button"
                      disabled={!!form.id}
                      onClick={() => setForm((f) => ({ ...f, destination_type: t }))}
                      className={`px-2 py-2 rounded border text-xs font-semibold transition-colors disabled:opacity-40 ${
                        form.destination_type === t
                          ? "border-cyan-700 bg-cyan-950/60 text-cyan-300"
                          : "border-soc-border text-slate-400 hover:bg-slate-800/40"
                      }`}
                    >
                      {TYPE_ICON[t]} {TYPE_LABEL[t]}
                    </button>
                  ))}
                </div>
              </div>

              {form.destination_type === "s3" && (
                <div className="space-y-2 border-t border-soc-border pt-3">
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Bucket" value={form.bucket} onChange={(v) => setForm((f) => ({ ...f, bucket: v }))} placeholder="my-netsec-backups" />
                    <Field label="Region" value={form.region} onChange={(v) => setForm((f) => ({ ...f, region: v }))} placeholder="us-east-1" />
                  </div>
                  <Field label="Custom Endpoint URL (optional — for S3-compatible storage)" value={form.endpoint_url} onChange={(v) => setForm((f) => ({ ...f, endpoint_url: v }))} placeholder="https://s3.compatible-provider.com" />
                  <label className="flex items-center gap-2 text-xs text-slate-400">
                    <input type="checkbox" checked={form.use_path_style} onChange={(e) => setForm((f) => ({ ...f, use_path_style: e.target.checked }))} />
                    Use path-style addressing (needed for some S3-compatible providers, e.g. MinIO)
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Access Key ID" value={form.access_key_id} onChange={(v) => setForm((f) => ({ ...f, access_key_id: v }))} placeholder={form.id ? "Leave blank to keep existing" : "AKIA..."} />
                    <Field label="Secret Access Key" type="password" value={form.secret_access_key} onChange={(v) => setForm((f) => ({ ...f, secret_access_key: v }))} placeholder={form.id ? "Leave blank to keep existing" : "••••••••"} />
                  </div>
                  <Field label="Session Token (optional, for STS temp creds)" type="password" value={form.session_token} onChange={(v) => setForm((f) => ({ ...f, session_token: v }))} />
                  <p className="text-[11px] text-slate-600">Leave credentials blank to use the instance/environment IAM role instead of static keys.</p>
                </div>
              )}

              {form.destination_type === "azure_blob" && (
                <div className="space-y-2 border-t border-soc-border pt-3">
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Container" value={form.container} onChange={(v) => setForm((f) => ({ ...f, container: v }))} placeholder="netsec-backups" />
                    <Field label="Storage Account Name" value={form.account_name} onChange={(v) => setForm((f) => ({ ...f, account_name: v }))} placeholder="mystorageacct" />
                  </div>
                  <Field label="Connection String (recommended)" type="password" value={form.connection_string} onChange={(v) => setForm((f) => ({ ...f, connection_string: v }))} placeholder={form.id ? "Leave blank to keep existing" : "DefaultEndpointsProtocol=https;..."} />
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="SAS Token" type="password" value={form.sas_token} onChange={(v) => setForm((f) => ({ ...f, sas_token: v }))} />
                    <Field label="Account Key" type="password" value={form.account_key} onChange={(v) => setForm((f) => ({ ...f, account_key: v }))} />
                  </div>
                </div>
              )}

              {form.destination_type === "sftp" && (
                <div className="space-y-2 border-t border-soc-border pt-3">
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Host" value={form.host} onChange={(v) => setForm((f) => ({ ...f, host: v }))} placeholder="backup.example.com" />
                    <Field label="Port" value={form.port} onChange={(v) => setForm((f) => ({ ...f, port: v }))} placeholder="22" />
                  </div>
                  <Field label="Remote Path" value={form.remote_path} onChange={(v) => setForm((f) => ({ ...f, remote_path: v }))} placeholder="/backups" />
                  <Field label="Username" value={form.username} onChange={(v) => setForm((f) => ({ ...f, username: v }))} />
                  <Field label="Password" type="password" value={form.password} onChange={(v) => setForm((f) => ({ ...f, password: v }))} placeholder={form.id ? "Leave blank to keep existing" : ""} />
                  <div>
                    <label className="text-xs text-slate-500">Private Key (PEM, alternative to password)</label>
                    <textarea
                      className="input w-full font-mono text-xs h-20"
                      value={form.private_key}
                      onChange={(e) => setForm((f) => ({ ...f, private_key: e.target.value }))}
                      placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    />
                  </div>
                </div>
              )}

              {form.destination_type === "local" && (
                <div className="space-y-2 border-t border-soc-border pt-3">
                  <Field
                    label="Base Path (relative to the server's local backup root)"
                    value={form.base_path}
                    onChange={(v) => setForm((f) => ({ ...f, base_path: v }))}
                    placeholder="e.g. dr-site-a (leave blank for the root)"
                  />
                  <p className="text-[11px] text-slate-600">
                    Writes go to a directory on the backend's own disk/mounted volume
                    (configured via LOCAL_BACKUP_ROOT). No credentials needed — useful for an
                    on-prem NAS share or a dedicated backup volume mounted into the container.
                  </p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2 border-t border-soc-border pt-3">
                <Field label="Retention (days, blank = indefinite)" value={String(form.retention_days)} onChange={(v) => setForm((f) => ({ ...f, retention_days: v }))} placeholder="90" />
                <div className="flex flex-col justify-end gap-2">
                  <label className="flex items-center gap-2 text-xs text-slate-400">
                    <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} />
                    Enabled
                  </label>
                  <label className="flex items-center gap-2 text-xs text-slate-400">
                    <input type="checkbox" checked={form.auto_export_enabled} onChange={(e) => setForm((f) => ({ ...f, auto_export_enabled: e.target.checked }))} />
                    Auto-export after every scan
                  </label>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setFormOpen(false)} className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200">
                Cancel
              </button>
              <button
                onClick={save}
                disabled={saving}
                className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 text-sm font-semibold disabled:opacity-50"
              >
                {saving ? "Saving..." : form.id ? "Save Changes" : "Add Destination"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <div>
      <label className="text-xs text-slate-500">{label}</label>
      <input
        type={type}
        className="input w-full"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Job history tab
// ---------------------------------------------------------------------------

function JobsTab() {
  const [jobs, setJobs] = useState<BackupJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("");

  useEffect(() => {
    setLoading(true);
    endpoints
      .backupJobs({ status: statusFilter || undefined, limit: 200 })
      .then((res) => setJobs(res.data.jobs || []))
      .catch(() => setJobs([]))
      .finally(() => setLoading(false));
  }, [statusFilter]);

  return (
    <div className="px-8 pb-8">
      <div className="card">
        <div className="flex items-center justify-between mb-4 pb-4 border-b border-soc-border">
          <h2 className="text-lg font-bold text-slate-200">Export Job History</h2>
          <select
            className="input text-xs"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All statuses</option>
            <option value="SUCCESS">Success</option>
            <option value="FAILED">Failed</option>
            <option value="RUNNING">Running</option>
          </select>
        </div>

        {loading ? (
          <Loading />
        ) : jobs.length === 0 ? (
          <EmptyState message="No export jobs recorded yet." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="text-slate-500 border-b border-soc-border uppercase text-xs">
                  <th className="py-3 px-4">When</th>
                  <th className="py-3 px-4">Device</th>
                  <th className="py-3 px-4">Destination</th>
                  <th className="py-3 px-4">Trigger</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Bytes</th>
                  <th className="py-3 px-4">Duration</th>
                  <th className="py-3 px-4">Detail</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => (
                  <tr key={j.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                    <td className="py-3 px-4 text-xs text-slate-400">
                      {j.created_at ? new Date(j.created_at).toLocaleString() : "—"}
                    </td>
                    <td className="py-3 px-4 text-slate-300">{j.device_hostname || j.device_id.slice(0, 8)}</td>
                    <td className="py-3 px-4 text-slate-300">{j.destination_name || j.destination_id.slice(0, 8)}</td>
                    <td className="py-3 px-4 text-xs text-slate-500">{j.trigger}</td>
                    <td className="py-3 px-4"><StatusPill status={j.status} /></td>
                    <td className="py-3 px-4 text-xs text-slate-400">{j.bytes_written ? `${j.bytes_written} B` : "—"}</td>
                    <td className="py-3 px-4 text-xs text-slate-400">{j.duration_ms ? `${j.duration_ms} ms` : "—"}</td>
                    <td className="py-3 px-4 text-xs text-red-400 max-w-xs truncate" title={j.error || j.remote_path || ""}>
                      {j.error || j.remote_path || "—"}
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