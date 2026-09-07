import { useEffect, useState } from "react";
import { endpoints, AuditSchedule } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

const FREQUENCIES = ["manual", "hourly", "daily", "weekly"];

function StatusPill({ status }: { status: string | null }) {
  const s = status || "NEVER RUN";
  const cls = s === "SUCCESS" ? "badge-pass" : s === "FAILED" ? "badge-fail" : s === "PARTIAL" ? "badge-medium" : "badge-na";
  return <span className={`badge ${cls}`}>{s.replace(/_/g, " ")}</span>;
}

export default function Schedules() {
  const [schedules, setSchedules] = useState<AuditSchedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [frequency, setFrequency] = useState("daily");
  const [framework, setFramework] = useState("ALL");
  const [scopeAll, setScopeAll] = useState(true);
  const [deviceIds, setDeviceIds] = useState("");

  function load() {
    setLoading(true);
    endpoints
      .schedules()
      .then((r) => setSchedules(r.data))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  async function handleCreate() {
    if (!name.trim()) return;
    setError(null);
    try {
      const scope = scopeAll
        ? { all: true }
        : { device_ids: deviceIds.split(",").map((s) => s.trim()).filter(Boolean) };
      await endpoints.createSchedule({ name, frequency, framework, enabled: true, scope });
      setName("");
      setDeviceIds("");
      load();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to create schedule");
    }
  }

  async function handleToggle(s: AuditSchedule) {
    setBusyId(s.id);
    try {
      await endpoints.updateSchedule(s.id, { enabled: !s.enabled });
      load();
    } finally {
      setBusyId(null);
    }
  }

  async function handleRunNow(s: AuditSchedule) {
    setBusyId(s.id);
    setError(null);
    try {
      await endpoints.runScheduleNow(s.id);
      load();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Run failed");
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(s: AuditSchedule) {
    setBusyId(s.id);
    try {
      await endpoints.deleteSchedule(s.id);
      load();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <PageHeader
        title="Scheduled Audits"
        subtitle="Recurring scans executed by the background scheduler worker — never run inline on a request"
      />
      <div className="px-8 pb-8 space-y-6">
        <div className="card space-y-3">
          <div className="text-sm font-semibold text-slate-200">New schedule</div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <input
              className="input w-full"
              placeholder="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <select className="select w-full" value={frequency} onChange={(e) => setFrequency(e.target.value)}>
              {FREQUENCIES.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
            <input
              className="input w-full"
              placeholder="Framework (e.g. ALL, CIS, NIST)"
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
            />
            <label className="flex items-center gap-2 text-sm text-slate-400">
              <input type="checkbox" checked={scopeAll} onChange={(e) => setScopeAll(e.target.checked)} />
              All devices
            </label>
          </div>
          {!scopeAll && (
            <input
              className="input w-full"
              placeholder="Comma-separated device IDs"
              value={deviceIds}
              onChange={(e) => setDeviceIds(e.target.value)}
            />
          )}
          {error && <div className="text-sm text-red-400">{error}</div>}
          <button className="btn-primary" onClick={handleCreate}>
            Create schedule
          </button>
        </div>

        {loading && <Loading />}
        {!loading && schedules.length === 0 && <EmptyState message="No schedules yet — create one above." />}
        {!loading &&
          schedules.map((s) => (
            <div key={s.id} className="card">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-slate-200">{s.name}</span>
                    <span className="badge badge-na">{s.frequency}</span>
                    <span className={`badge ${s.enabled ? "badge-pass" : "badge-na"}`}>
                      {s.enabled ? "ENABLED" : "DISABLED"}
                    </span>
                    <StatusPill status={s.last_run_status} />
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    scope: {s.scope?.all ? "all devices" : `${s.scope?.device_ids?.length || 0} device(s)`} ·
                    framework: {s.framework} · created by {s.created_by || "—"}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    last run: {s.last_run ? new Date(s.last_run).toLocaleString() : "never"}
                    {" · "}
                    next run: {s.next_run ? new Date(s.next_run).toLocaleString() : "—"}
                  </div>
                  {s.last_run_detail && <div className="text-xs text-slate-400 mt-1">{s.last_run_detail}</div>}
                </div>
                <div className="flex gap-2 shrink-0">
                  <button className="btn-secondary" disabled={busyId === s.id} onClick={() => handleRunNow(s)}>
                    Run now
                  </button>
                  <button className="btn-secondary" disabled={busyId === s.id} onClick={() => handleToggle(s)}>
                    {s.enabled ? "Disable" : "Enable"}
                  </button>
                  <button className="btn-secondary" disabled={busyId === s.id} onClick={() => handleDelete(s)}>
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}
