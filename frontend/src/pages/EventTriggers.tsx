import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  endpoints,
  EventTrigger,
  EventTriggerLog,
  EventTriggerMetadata,
} from "../api";
import { PageHeader, Loading, EmptyState, StatCard } from "../components/ui";

// Friendly labels/descriptions for the known event subjects — the backend
// treats event_type as an open string (new subjects get added over time),
// so anything not in this map still works, just rendered as-is.
const EVENT_TYPE_LABELS: Record<string, string> = {
  "compliance.scan.completed": "Compliance scan completed",
  "metrics.threshold_breached": "Metric threshold breached",
  "finding.created": "New finding created",
  "config.uploaded": "Config uploaded",
  "config.parsed": "Config parsed",
  "config.normalized": "Config normalized",
  "drift.detected": "Drift detected",
  "change_request.created": "Change request created",
  "change_request.approved": "Change request approved",
  "device.config_changed": "Device reported a config change (syslog/commit)",
  "device.device_reloaded": "Device reloaded/restarted (syslog)",
  "device.syslog_received": "Any syslog message received (unclassified)",
};

const ACTION_TYPE_LABELS: Record<string, string> = {
  create_alert: "Raise an alert",
  run_schedule: "Run a schedule now",
  run_scan: "Scan device(s) now",
};

function OutcomeBadge({ outcome }: { outcome: string }) {
  const cls =
    outcome === "fired"
      ? "badge-pass"
      : outcome === "error"
      ? "badge-fail"
      : outcome.startsWith("skipped")
      ? "badge-na"
      : "badge-medium";
  return <span className={`badge ${cls}`}>{outcome.replace(/_/g, " ")}</span>;
}

function TriggerLogs({ triggerId }: { triggerId: string }) {
  const [logs, setLogs] = useState<EventTriggerLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    endpoints
      .eventTriggerLogs(triggerId)
      .then((r) => {
        if (!cancelled) setLogs(r.data);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [triggerId]);

  if (loading) return <div className="text-xs text-slate-500 py-2">Loading firing history…</div>;
  if (logs.length === 0)
    return <div className="text-xs text-slate-500 py-2">No firings recorded yet for this trigger.</div>;

  return (
    <div className="space-y-1.5 mt-2">
      {logs.map((l) => (
        <div key={l.id} className="rounded-md border border-soc-border bg-soc-bg/40 p-2 text-xs flex items-start gap-2 flex-wrap">
          <OutcomeBadge outcome={l.outcome} />
          <span className="text-slate-400">{new Date(l.created_at).toLocaleString()}</span>
          <span className="text-slate-500 font-mono">{l.event_type}</span>
          {l.error && <span className="text-red-400">{l.error}</span>}
        </div>
      ))}
    </div>
  );
}

export default function EventTriggers() {
  const [triggers, setTriggers] = useState<EventTrigger[]>([]);
  const [metadata, setMetadata] = useState<EventTriggerMetadata | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // New trigger form state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [eventType, setEventType] = useState("");
  const [actionType, setActionType] = useState("create_alert");
  const [severity, setSeverity] = useState("HIGH");
  const [alertMessage, setAlertMessage] = useState("");
  const [scheduleId, setScheduleId] = useState("");
  const [cooldownSeconds, setCooldownSeconds] = useState(0);
  const [schedules, setSchedules] = useState<{ id: string; name: string }[]>([]);
  const [devices, setDevices] = useState<{ id: string; name: string }[]>([]);
  const [scanDeviceIds, setScanDeviceIds] = useState<string[]>([]);
  const [scanUseEventDevice, setScanUseEventDevice] = useState(true);

  function load() {
    setLoading(true);
    Promise.all([endpoints.eventTriggers(), endpoints.eventTriggerMetadata(), endpoints.schedules(), endpoints.devices()])
      .then(([t, m, s, d]) => {
        setTriggers(t.data);
        setMetadata(m.data);
        setSchedules(s.data.map((x) => ({ id: x.id, name: x.name })));
        setDevices((d.data.items || []).map((x) => ({ id: x.id, name: x.name || x.hostname || x.id })));
        if (!eventType && m.data.event_types.length > 0) setEventType(m.data.event_types[0]);
      })
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  const stats = useMemo(() => {
    const enabled = triggers.filter((t) => t.enabled).length;
    const totalFirings = triggers.reduce((acc, t) => acc + (t.trigger_count || 0), 0);
    return { total: triggers.length, enabled, disabled: triggers.length - enabled, totalFirings };
  }, [triggers]);

  async function handleCreate() {
    if (!name.trim() || !eventType) return;
    setError(null);
    const action_config =
      actionType === "run_schedule"
        ? { schedule_id: scheduleId }
        : actionType === "run_scan"
        ? scanUseEventDevice ? {} : { device_ids: scanDeviceIds }
        : { severity, message: alertMessage || `${name} fired` };
    if (actionType === "run_schedule" && !scheduleId) {
      setError("Pick a schedule to run for this action.");
      return;
    }
    if (actionType === "run_scan" && !scanUseEventDevice && scanDeviceIds.length === 0) {
      setError("Pick at least one device to scan, or use the device from the triggering event.");
      return;
    }
    try {
      await endpoints.createEventTrigger({
        name,
        description: description || undefined,
        enabled: true,
        event_type: eventType,
        action_type: actionType,
        action_config,
        cooldown_seconds: cooldownSeconds || 0,
      });
      setName("");
      setDescription("");
      setAlertMessage("");
      setScheduleId("");
      setCooldownSeconds(0);
      load();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to create event trigger");
    }
  }

  async function handleToggle(t: EventTrigger) {
    setBusyId(t.id);
    try {
      await endpoints.updateEventTrigger(t.id, {
        name: t.name,
        description: t.description,
        enabled: !t.enabled,
        event_type: t.event_type,
        filter: t.filter,
        action_type: t.action_type,
        action_config: t.action_config,
        cooldown_seconds: t.cooldown_seconds,
      });
      load();
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(t: EventTrigger) {
    if (!window.confirm(`Delete trigger "${t.name}"? This cannot be undone.`)) return;
    setBusyId(t.id);
    try {
      await endpoints.deleteEventTrigger(t.id);
      load();
    } finally {
      setBusyId(null);
    }
  }

  async function handleTest(t: EventTrigger) {
    setBusyId(t.id);
    setError(null);
    try {
      await endpoints.testEventTrigger(t.id, { simulated: true });
      setExpandedId(t.id);
      load();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Test firing failed");
    } finally {
      setBusyId(null);
    }
  }

  function scheduleName(id?: string) {
    return schedules.find((s) => s.id === id)?.name || id || "—";
  }

  return (
    <div>
      <PageHeader
        title="Event-Driven Scanning"
        subtitle="Trigger a scan, raise an alert, or launch a schedule the instant a real event happens — a device commits a config change (syslog), drift is detected, a scan completes, a metric breaches — instead of waiting for the clock. Complements the time-based Schedules page."
      />
      <div className="px-8 pb-8 space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Triggers" value={stats.total} />
          <StatCard label="Enabled" value={stats.enabled} tone="good" />
          <StatCard label="Disabled" value={stats.disabled} />
          <StatCard label="Total firings" value={stats.totalFirings} />
        </div>

        <div className="card space-y-3">
          <div className="text-sm font-semibold text-slate-200">New event trigger</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <input
              className="input w-full"
              placeholder="Name (e.g. Escalate on FAIL scan)"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <input
              className="input w-full"
              placeholder="Description (optional)"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
            <div>
              <label className="text-xs text-slate-500 block mb-1">When this happens</label>
              <select className="select w-full" value={eventType} onChange={(e) => setEventType(e.target.value)}>
                {(metadata?.event_types || []).map((et) => (
                  <option key={et} value={et}>
                    {EVENT_TYPE_LABELS[et] || et}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Do this</label>
              <select className="select w-full" value={actionType} onChange={(e) => setActionType(e.target.value)}>
                {(metadata?.action_types || ["create_alert", "run_schedule"]).map((at) => (
                  <option key={at} value={at}>
                    {ACTION_TYPE_LABELS[at] || at}
                  </option>
                ))}
              </select>
            </div>

            {actionType === "create_alert" ? (
              <>
                <div>
                  <label className="text-xs text-slate-500 block mb-1">Alert severity</label>
                  <select className="select w-full" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                    {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
                <input
                  className="input w-full"
                  placeholder="Alert message (optional)"
                  value={alertMessage}
                  onChange={(e) => setAlertMessage(e.target.value)}
                />
              </>
            ) : actionType === "run_schedule" ? (
              <div>
                <label className="text-xs text-slate-500 block mb-1">Schedule to run</label>
                <select className="select w-full" value={scheduleId} onChange={(e) => setScheduleId(e.target.value)}>
                  <option value="">Select a schedule…</option>
                  {schedules.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </select>
                {schedules.length === 0 && (
                  <div className="text-xs text-slate-500 mt-1">
                    No schedules yet — create one on the{" "}
                    <Link className="underline decoration-dotted" to="/schedules">Schedules</Link> page first.
                  </div>
                )}
              </div>
            ) : (
              <div className="md:col-span-2">
                <label className="text-xs text-slate-500 block mb-1">Which device(s) to scan</label>
                <div className="flex items-center gap-4 mb-2">
                  <label className="flex items-center gap-2 text-xs text-slate-400">
                    <input type="radio" checked={scanUseEventDevice} onChange={() => setScanUseEventDevice(true)} />
                    Use the device from the triggering event (e.g. the device that sent the syslog message)
                  </label>
                  <label className="flex items-center gap-2 text-xs text-slate-400">
                    <input type="radio" checked={!scanUseEventDevice} onChange={() => setScanUseEventDevice(false)} />
                    Always scan specific device(s)
                  </label>
                </div>
                {!scanUseEventDevice && (
                  <select
                    multiple
                    className="select w-full h-28"
                    value={scanDeviceIds}
                    onChange={(e) => setScanDeviceIds(Array.from(e.target.selectedOptions).map((o) => o.value))}
                  >
                    {devices.map((d) => (
                      <option key={d.id} value={d.id}>{d.name}</option>
                    ))}
                  </select>
                )}
              </div>
            )}

            <div>
              <label className="text-xs text-slate-500 block mb-1">Cooldown (seconds)</label>
              <input
                type="number"
                min={0}
                className="input w-full"
                value={cooldownSeconds}
                onChange={(e) => setCooldownSeconds(Number(e.target.value) || 0)}
              />
              <div className="text-xs text-slate-600 mt-1">Suppresses repeat firings within this window.</div>
            </div>
          </div>
          {error && <div className="text-sm text-red-400">{error}</div>}
          <button className="btn-primary" onClick={handleCreate}>
            Create trigger
          </button>
        </div>

        {loading && <Loading />}
        {!loading && triggers.length === 0 && (
          <EmptyState message="No event triggers yet — create one above to react to events instead of waiting for the schedule." />
        )}
        {!loading &&
          triggers.map((t) => (
            <div key={t.id} className="card">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-slate-200">{t.name}</span>
                    <span className={`badge ${t.enabled ? "badge-pass" : "badge-na"}`}>
                      {t.enabled ? "ENABLED" : "DISABLED"}
                    </span>
                    <span className="badge badge-na">{EVENT_TYPE_LABELS[t.event_type] || t.event_type}</span>
                    <span className="badge badge-medium">
                      → {ACTION_TYPE_LABELS[t.action_type] || t.action_type}
                      {t.action_type === "run_schedule" && `: ${scheduleName(t.action_config?.schedule_id)}`}
                      {t.action_type === "run_scan" &&
                        (t.action_config?.device_ids?.length
                          ? `: ${t.action_config.device_ids.length} device(s)`
                          : ": device from event")}
                    </span>
                  </div>
                  {t.description && <div className="text-xs text-slate-500 mt-1">{t.description}</div>}
                  <div className="text-xs text-slate-500 mt-1">
                    fired {t.trigger_count} time{t.trigger_count === 1 ? "" : "s"} · last:{" "}
                    {t.last_triggered_at ? new Date(t.last_triggered_at).toLocaleString() : "never"}
                    {t.cooldown_seconds > 0 && ` · cooldown ${t.cooldown_seconds}s`}
                  </div>
                  <div className="mt-2">
                    <button
                      className="text-xs text-slate-400 hover:text-slate-200 underline decoration-dotted"
                      onClick={() => setExpandedId(expandedId === t.id ? null : t.id)}
                    >
                      {expandedId === t.id ? "Hide firing history" : "Show firing history"}
                    </button>
                    {expandedId === t.id && <TriggerLogs triggerId={t.id} />}
                  </div>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button className="btn-secondary" disabled={busyId === t.id} onClick={() => handleTest(t)} title="Fire this trigger's event with a synthetic payload">
                    Test fire
                  </button>
                  <button className="btn-secondary" disabled={busyId === t.id} onClick={() => handleToggle(t)}>
                    {t.enabled ? "Disable" : "Enable"}
                  </button>
                  <button className="btn-secondary" disabled={busyId === t.id} onClick={() => handleDelete(t)}>
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}

        <div className="card space-y-1.5">
          <div className="text-sm font-semibold text-slate-200">Event-driven scanning inputs</div>
          <div className="text-xs text-slate-500">
            Point a syslog relay (rsyslog/forwarder) or SIEM webhook action at this URL for real, event-driven
            scanning — e.g. a network engineer commits a config change on a router and it's scanned within
            seconds instead of waiting for the next schedule. Each message is classified (config change / reload /
            unclassified) and matched to a known device by hostname or source IP, then published as a{" "}
            <span className="font-mono">device.config_changed</span> event — create a trigger above with action{" "}
            <em>Scan device(s) now</em> to act on it.
          </div>
          <div className="text-xs text-slate-600 font-mono bg-soc-bg/40 rounded p-2 mt-1">
            POST /api/webhooks/syslog/&#123;tenant_id&#125;{"\n"}
            Header: X-Webhook-Secret: &lt;shared secret, if configured&gt;{"\n"}
            Body: {"{"} "message": "&lt;raw syslog line&gt;", "source_ip": "&lt;optional&gt;" {"}"}
          </div>
          <div className="text-xs text-slate-600">
            Generic events (scan completed, drift detected, etc.) can also be pushed directly:{" "}
            <span className="font-mono">POST /api/webhooks/events/&#123;tenant_id&#125;/&#123;event_type&#125;</span>
          </div>
        </div>
      </div>
    </div>
  );
}
