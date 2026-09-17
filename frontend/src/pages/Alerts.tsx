import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  endpoints,
  Alert,
  AlertChannel,
  AlertChannelType,
  AlertChannelCreate,
  AlertRule,
  AlertRuleCreate,
  PushSubscriptionSummary,
  SimulatableCategory,
} from "../api";
import { PageHeader, Loading, EmptyState, SeverityBadge, StatCard } from "../components/ui";
import { pushSupported, getPushStatus, subscribeToPush, unsubscribeFromPush } from "../lib/push";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const STATUSES = ["OPEN", "ACKNOWLEDGED"];

type Tab = "feed" | "channels" | "rules" | "push";

const CHANNEL_LABEL: Record<AlertChannelType, string> = {
  email: "Email (SMTP)",
  ntfy: "ntfy",
  webhook: "Webhook",
  push: "Browser Push",
};

const CHANNEL_ICON: Record<AlertChannelType, string> = {
  email: "✉️",
  ntfy: "🔔",
  webhook: "🪝",
  push: "📱",
};

function StatusPill({ status }: { status: string | null | undefined }) {
  const s = (status || "NEVER_TESTED").toUpperCase();
  const cls =
    s === "SUCCESS"
      ? "badge badge-low"
      : s === "FAILED"
      ? "badge badge-critical"
      : "badge badge-na";
  return <span className={cls}>{s.replace(/_/g, " ")}</span>;
}

export default function Alerts() {
  const [tab, setTab] = useState<Tab>("feed");
  const [counts, setCounts] = useState<{ open: number; channels: number; rules: number } | null>(null);

  const refreshCounts = useCallback(() => {
    Promise.all([
      endpoints.alerts({ status: "OPEN" }).catch(() => ({ data: { alerts: [] } } as any)),
      endpoints.alertChannels().catch(() => ({ data: { count: 0 } } as any)),
      endpoints.alertRules().catch(() => ({ data: { count: 0 } } as any)),
    ]).then(([a, c, r]) => {
      setCounts({ open: a.data.alerts.length, channels: c.data.count, rules: r.data.count });
    });
  }, []);

  useEffect(() => {
    refreshCounts();
  }, [refreshCounts]);

  return (
    <div>
      <PageHeader
        title="Alerting"
        subtitle="Enterprise alert routing — feed, channels (email / ntfy / webhook / push), rule-based routing, and browser push"
      />
      <div className="px-8 pb-4">
        <div className="grid grid-cols-3 gap-4 mb-4">
          <StatCard label="Open Alerts" value={counts?.open ?? "…"} tone={counts && counts.open > 0 ? "critical" : "good"} />
          <StatCard label="Notification Channels" value={counts?.channels ?? "…"} />
          <StatCard label="Routing Rules" value={counts?.rules ?? "…"} />
        </div>
        <div className="flex gap-1 border-b border-soc-border">
          {([
            ["feed", "Alert Feed"],
            ["channels", "Channels"],
            ["rules", "Routing Rules"],
            ["push", "Browser Push"],
          ] as [Tab, string][]).map(([t, label]) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
                tab === t
                  ? "border-cyan-500 text-cyan-300"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {tab === "feed" && <FeedTab />}
      {tab === "channels" && <ChannelsTab onChanged={refreshCounts} />}
      {tab === "rules" && <RulesTab onChanged={refreshCounts} />}
      {tab === "push" && <PushTab />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Alert feed
// ---------------------------------------------------------------------------

/**
 * Buttons that create a REAL alert through the real dispatch path, so an
 * operator can prove their webhook / ntfy / email / push wiring works
 * without waiting for a genuine incident.
 *
 * Simulated alerts are marked server-side (`extra.simulated`) and render
 * with a "SIMULATED" badge in the feed — they are never presented as real
 * security events.
 */
function SimulateEventButtons({ onSimulated }: { onSimulated: () => void }) {
  const [cats, setCats] = useState<SimulatableCategory[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<{ category: string; dispatch: Record<string, string> } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    endpoints
      .simulatableCategories()
      .then((r) => setCats(r.data.categories))
      .catch(() => setCats([]));
  }, []);

  async function fire(category: string) {
    setBusy(category);
    setError(null);
    setResult(null);
    try {
      const r = await endpoints.simulateAlert({ category });
      setResult({ category, dispatch: r.data.dispatch_results || {} });
      onSimulated();
    } catch (e: any) {
      setError(
        e?.response?.status === 403
          ? "Your role can't create alerts. Ask an admin or operator to run the simulation."
          : e?.response?.data?.detail || "Simulation failed — see server logs.",
      );
    } finally {
      setBusy(null);
    }
  }

  if (cats === null) return null;
  if (cats.length === 0) return null;

  return (
    <div className="mt-6 pt-5 border-t border-soc-border/60">
      <div className="text-sm font-medium text-slate-300">Verify your alert pipeline</div>
      <div className="text-xs text-slate-500 mt-1 max-w-lg mx-auto">
        Generate a test event to confirm your channels and browser push actually fire. These are
        recorded as simulated and are clearly badged in the feed.
      </div>
      <div className="flex flex-wrap gap-2 justify-center mt-4">
        {cats.map((c) => (
          <button
            key={c.category}
            onClick={() => fire(c.category)}
            disabled={busy !== null}
            title={c.title}
            className="px-3 py-2 rounded-lg text-xs font-medium border border-soc-border
                       bg-soc-panel/60 backdrop-blur text-slate-300
                       hover:border-cyan-600/70 hover:text-cyan-300 hover:bg-cyan-950/30
                       transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy === c.category ? "Dispatching…" : `Simulate ${c.category.replace(/_/g, " ")}`}
          </button>
        ))}
      </div>

      {error && <div className="mt-3 text-xs text-red-400">{error}</div>}

      {result && (
        <div className="mt-4 mx-auto max-w-lg text-left rounded-lg border border-soc-border bg-soc-panel/50 p-3">
          <div className="text-xs text-slate-300 font-medium mb-1.5">
            {result.category.replace(/_/g, " ")} dispatched — channel results:
          </div>
          {Object.keys(result.dispatch).length === 0 ? (
            <div className="text-xs text-slate-500 italic">
              No channels are configured, so the alert was stored but not delivered anywhere. Add a
              channel in the Channels tab, then simulate again.
            </div>
          ) : (
            <div className="space-y-1">
              {Object.entries(result.dispatch).map(([ch, outcome]) => {
                const ok = /sent|ok|success|delivered/i.test(outcome);
                const skipped = /skip/i.test(outcome);
                return (
                  <div key={ch} className="flex items-start gap-2 text-xs">
                    <span
                      className={`mt-1 inline-block w-1.5 h-1.5 rounded-full shrink-0 ${
                        ok ? "bg-emerald-400" : skipped ? "bg-slate-500" : "bg-red-400"
                      }`}
                    />
                    <span className="text-slate-400 font-mono">{ch}</span>
                    <span
                      className={
                        ok ? "text-emerald-400" : skipped ? "text-slate-500" : "text-red-400"
                      }
                    >
                      {outcome}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FeedTab() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<string>("OPEN");
  const [severity, setSeverity] = useState<string>("");
  const [busyId, setBusyId] = useState<string | null>(null);
  // Bumped after a simulation so the poller briefly switches to a fast
  // cadence -- the operator should see the alert land within ~a second,
  // which is the whole point of the button.
  const [liveUntil, setLiveUntil] = useState<number>(0);

  // `silent` keeps the spinner from flashing on every background poll.
  const load = useCallback(
    (silent = false) => {
      if (!silent) setLoading(true);
      endpoints
        .alerts({ status: status || undefined, severity: severity || undefined })
        .then((r) => setAlerts(r.data.alerts))
        .finally(() => {
          if (!silent) setLoading(false);
        });
    },
    [status, severity],
  );

  useEffect(() => load(), [load]);

  // There's no alert WebSocket/SSE channel on the backend today, so this is
  // polling: 2s for 20s after a simulation (so the feed visibly reacts),
  // 15s otherwise. Both are cheap -- GET /api/alerts is a single indexed
  // tenant-scoped query.
  useEffect(() => {
    const id = setInterval(
      () => {
        if (document.hidden) return; // don't poll a backgrounded tab
        load(true);
      },
      Date.now() < liveUntil ? 2000 : 15000,
    );
    return () => clearInterval(id);
  }, [load, liveUntil]);

  const handleSimulated = useCallback(() => {
    setLiveUntil(Date.now() + 20000);
    load(true);
  }, [load]);

  async function handleAck(a: Alert) {
    setBusyId(a.id);
    try {
      await endpoints.acknowledgeAlert(a.id);
      load();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="px-8 pb-8 space-y-3">
      <div className="flex gap-2 mb-2">
        <select
          className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>
      {loading && <Loading />}
      {!loading && alerts.length === 0 && (
        <div
          className="px-8 py-10 rounded-xl text-center border border-dashed border-soc-border
                     bg-soc-panel/40 backdrop-blur-sm"
        >
          <div className="text-slate-400 text-sm">
            {status || severity
              ? "No alerts match the current filters."
              : "No alerts yet — nothing has breached a policy or drifted from baseline."}
          </div>
          {(status || severity) && (
            <button
              onClick={() => {
                setStatus("");
                setSeverity("");
              }}
              className="mt-2 text-xs text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
            >
              Clear filters
            </button>
          )}
          <SimulateEventButtons onSimulated={handleSimulated} />
        </div>
      )}
      {!loading &&
        alerts.map((a) => (
          <div key={a.id} className="card">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <SeverityBadge severity={a.severity} />
                  <span className="badge badge-na">{a.category.replace(/_/g, " ")}</span>
                  <span className={`badge ${a.status === "OPEN" ? "badge-fail" : "badge-pass"}`}>
                    {a.status}
                  </span>
                  {(a.extra as any)?.simulated && (
                    <span
                      className="badge border border-amber-600/50 bg-amber-950/40 text-amber-300"
                      title={`Test event created by ${(a.extra as any)?.simulated_by || "a user"} — not a real security event.`}
                    >
                      SIMULATED
                    </span>
                  )}
                </div>
                <div className="text-slate-200 font-medium mt-1">{a.title}</div>
                {a.detail && <div className="text-xs text-slate-500 mt-1">{a.detail}</div>}
                {a.dispatch_results && Object.keys(a.dispatch_results).length > 0 && (
                  <div className="flex gap-1 flex-wrap mt-2">
                    {Object.entries(a.dispatch_results).map(([channel, result]) => (
                      <span
                        key={channel}
                        title={result}
                        className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          /^(sent|success|delivered|published)/i.test(result)
                            ? "border-emerald-800 text-emerald-400 bg-emerald-950/40"
                            : "border-red-800 text-red-400 bg-red-950/40"
                        }`}
                      >
                        {channel}
                      </span>
                    ))}
                  </div>
                )}
                <div className="text-xs text-slate-500 mt-1">
                  {a.scan_id && (
                    <>
                      <Link className="text-cyan-400 hover:underline" to={`/scans/${a.scan_id}`}>
                        scan {a.scan_id}
                      </Link>
                      {" · "}
                    </>
                  )}
                  {new Date(a.created_at).toLocaleString()}
                  {a.acknowledged_by && ` · ack'd by ${a.acknowledged_by}`}
                </div>
              </div>
              {a.status === "OPEN" && (
                <button className="btn-secondary shrink-0" disabled={busyId === a.id} onClick={() => handleAck(a)}>
                  Acknowledge
                </button>
              )}
            </div>
          </div>
        ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Channels tab
// ---------------------------------------------------------------------------

const EMPTY_CHANNEL_FORM = (): AlertChannelCreate => ({
  name: "",
  channel_type: "ntfy",
  enabled: true,
  config: {},
  secret: {},
});

function ChannelsTab({ onChanged }: { onChanged: () => void }) {
  const [channels, setChannels] = useState<AlertChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<AlertChannel | null>(null);
  const [form, setForm] = useState<AlertChannelCreate>(EMPTY_CHANNEL_FORM());
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    endpoints
      .alertChannels()
      .then((r) => setChannels(r.data.channels))
      .finally(() => setLoading(false));
  }, []);

  useEffect(load, [load]);

  function openCreate() {
    setEditing(null);
    setForm(EMPTY_CHANNEL_FORM());
    setError(null);
    setModalOpen(true);
  }

  function openEdit(c: AlertChannel) {
    setEditing(c);
    setForm({ name: c.name, channel_type: c.channel_type, enabled: c.enabled, config: c.config || {}, secret: {} });
    setError(null);
    setModalOpen(true);
  }

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const payload = { ...form };
      if (!payload.secret || Object.keys(payload.secret).length === 0) delete (payload as any).secret;
      if (editing) {
        await endpoints.updateAlertChannel(editing.id, payload);
      } else {
        await endpoints.createAlertChannel(payload);
      }
      setModalOpen(false);
      load();
      onChanged();
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || "Failed to save channel");
    } finally {
      setSaving(false);
    }
  }

  async function remove(c: AlertChannel) {
    if (!confirm(`Delete channel "${c.name}"? This cannot be undone.`)) return;
    await endpoints.deleteAlertChannel(c.id);
    load();
    onChanged();
  }

  async function test(c: AlertChannel) {
    setTestingId(c.id);
    try {
      const r = await endpoints.testAlertChannel(c.id);
      setTestResult((prev) => ({ ...prev, [c.id]: r.data.message }));
    } catch (e: any) {
      setTestResult((prev) => ({ ...prev, [c.id]: e?.response?.data?.detail?.message || e?.message || "Test failed" }));
    } finally {
      setTestingId(null);
      load();
    }
  }

  function setConfig(key: string, value: any) {
    setForm((f) => ({ ...f, config: { ...f.config, [key]: value } }));
  }
  function setSecret(key: string, value: any) {
    setForm((f) => ({ ...f, secret: { ...(f.secret || {}), [key]: value } }));
  }

  return (
    <div className="px-8 pb-8">
      <div className="flex justify-end mb-4">
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 text-sm font-semibold"
        >
          + Add Channel
        </button>
      </div>
      {loading && <Loading />}
      {!loading && channels.length === 0 && (
        <EmptyState message="No notification channels configured. Add email, ntfy, webhook, or push to start routing alerts." />
      )}
      <div className="space-y-3">
        {channels.map((c) => (
          <div key={c.id} className="card">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="min-w-0 flex items-start gap-3">
                <span className="text-2xl">{CHANNEL_ICON[c.channel_type]}</span>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-slate-200 font-medium">{c.name}</span>
                    <span className="badge badge-na">{CHANNEL_LABEL[c.channel_type]}</span>
                    {!c.enabled && <span className="badge badge-fail">Disabled</span>}
                    <StatusPill status={c.last_test_status} />
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    {c.channel_type === "email" && `${(c.config.to_addresses || []).join(", ") || "no recipients"} via ${c.config.smtp_host || "?"}`}
                    {c.channel_type === "ntfy" && `${c.config.server_url || "https://ntfy.sh"}/${c.config.topic || "?"}`}
                    {c.channel_type === "webhook" && (c.config.url || "no URL set")}
                    {c.channel_type === "push" && "delivers to all subscribed browsers for this tenant"}
                  </div>
                  {c.last_test_message && (
                    <div className="text-xs text-slate-600 mt-1">Last test: {c.last_test_message}</div>
                  )}
                  {testResult[c.id] && <div className="text-xs text-cyan-400 mt-1">{testResult[c.id]}</div>}
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <button className="btn-secondary" disabled={testingId === c.id} onClick={() => test(c)}>
                  {testingId === c.id ? "Testing…" : "Test"}
                </button>
                <button className="btn-secondary" onClick={() => openEdit(c)}>
                  Edit
                </button>
                <button className="px-3 py-1.5 text-sm text-red-400 hover:text-red-300" onClick={() => remove(c)}>
                  Delete
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
          <div className="card w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-bold text-slate-200 mb-4">{editing ? "Edit Channel" : "Add Notification Channel"}</h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Name</label>
                <input
                  className="input w-full"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. NOC on-call ntfy"
                />
              </div>
              {!editing && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Type</label>
                  <select
                    className="input w-full"
                    value={form.channel_type}
                    onChange={(e) => setForm((f) => ({ ...f, channel_type: e.target.value as AlertChannelType, config: {} }))}
                  >
                    <option value="ntfy">ntfy</option>
                    <option value="email">Email (SMTP)</option>
                    <option value="webhook">Webhook</option>
                    <option value="push">Browser Push (all subscribed users)</option>
                  </select>
                </div>
              )}

              {form.channel_type === "ntfy" && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Server URL</label>
                    <input className="input w-full" value={form.config.server_url || ""} onChange={(e) => setConfig("server_url", e.target.value)} placeholder="https://ntfy.sh" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Topic</label>
                    <input className="input w-full" value={form.config.topic || ""} onChange={(e) => setConfig("topic", e.target.value)} placeholder="netsec-noc-alerts" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Access Token (optional, for private/self-hosted ntfy)</label>
                    <input type="password" className="input w-full" onChange={(e) => setSecret("access_token", e.target.value)} placeholder="leave blank to keep existing" autoComplete="off" />
                  </div>
                </>
              )}

              {form.channel_type === "email" && (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">SMTP Host</label>
                      <input className="input w-full" value={form.config.smtp_host || ""} onChange={(e) => setConfig("smtp_host", e.target.value)} placeholder="smtp.example.com" />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">SMTP Port</label>
                      <input type="number" className="input w-full" value={form.config.smtp_port || 587} onChange={(e) => setConfig("smtp_port", Number(e.target.value))} />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">From Address</label>
                    <input className="input w-full" value={form.config.from_address || ""} onChange={(e) => setConfig("from_address", e.target.value)} placeholder="alerts@yourdomain.com" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">To Addresses (comma-separated)</label>
                    <input
                      className="input w-full"
                      value={(form.config.to_addresses || []).join(", ")}
                      onChange={(e) => setConfig("to_addresses", e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
                      placeholder="noc@yourdomain.com, oncall@yourdomain.com"
                    />
                  </div>
                  <label className="flex items-center gap-2 text-sm text-slate-300">
                    <input type="checkbox" checked={form.config.use_tls !== false} onChange={(e) => setConfig("use_tls", e.target.checked)} />
                    Use STARTTLS
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">SMTP Username</label>
                      <input className="input w-full" onChange={(e) => setSecret("username", e.target.value)} placeholder="leave blank to keep existing" autoComplete="off" />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">SMTP Password</label>
                      <input type="password" className="input w-full" onChange={(e) => setSecret("password", e.target.value)} placeholder="leave blank to keep existing" autoComplete="off" />
                    </div>
                  </div>
                </>
              )}

              {form.channel_type === "webhook" && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Webhook URL</label>
                    <input className="input w-full" value={form.config.url || ""} onChange={(e) => setConfig("url", e.target.value)} placeholder="https://hooks.example.com/alerts" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Auth Header Name (optional)</label>
                    <input className="input w-full" value={form.config.secret_header_name || ""} onChange={(e) => setConfig("secret_header_name", e.target.value)} placeholder="X-Webhook-Token" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Auth Header Value</label>
                    <input type="password" className="input w-full" onChange={(e) => setSecret("header_value", e.target.value)} placeholder="leave blank to keep existing" autoComplete="off" />
                  </div>
                </>
              )}

              {form.channel_type === "push" && (
                <p className="text-xs text-slate-500">
                  Delivers to every browser subscribed via the Browser Push tab for this tenant. No further config needed — create the channel, then reference it from a routing rule.
                </p>
              )}

              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={form.enabled !== false} onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} />
                Enabled
              </label>

              {error && <div className="text-xs text-red-400">{error}</div>}
            </div>
            <div className="flex justify-end gap-2 mt-5">
              <button onClick={() => setModalOpen(false)} className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200">
                Cancel
              </button>
              <button
                onClick={save}
                disabled={saving || !form.name}
                className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 text-sm font-semibold disabled:opacity-50"
              >
                {saving ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Rules tab
// ---------------------------------------------------------------------------

const EMPTY_RULE_FORM = (): AlertRuleCreate => ({
  name: "",
  enabled: true,
  match_categories: [],
  match_severities: [],
  channel_ids: [],
});

function RulesTab({ onChanged }: { onChanged: () => void }) {
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [channels, setChannels] = useState<AlertChannel[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<AlertRule | null>(null);
  const [form, setForm] = useState<AlertRuleCreate>(EMPTY_RULE_FORM());
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([endpoints.alertRules(), endpoints.alertChannels(), endpoints.alertCategories()])
      .then(([r, c, cat]) => {
        setRules(r.data.rules);
        setChannels(c.data.channels);
        setCategories(cat.data.categories);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(load, [load]);

  function openCreate() {
    setEditing(null);
    setForm(EMPTY_RULE_FORM());
    setError(null);
    setModalOpen(true);
  }

  function openEdit(r: AlertRule) {
    setEditing(r);
    setForm({ name: r.name, enabled: r.enabled, match_categories: r.match_categories, match_severities: r.match_severities, channel_ids: r.channel_ids });
    setError(null);
    setModalOpen(true);
  }

  function toggle(list: string[], value: string): string[] {
    return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
  }

  async function save() {
    setSaving(true);
    setError(null);
    try {
      if (editing) {
        await endpoints.updateAlertRule(editing.id, form);
      } else {
        await endpoints.createAlertRule(form);
      }
      setModalOpen(false);
      load();
      onChanged();
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || "Failed to save rule");
    } finally {
      setSaving(false);
    }
  }

  async function remove(r: AlertRule) {
    if (!confirm(`Delete routing rule "${r.name}"?`)) return;
    await endpoints.deleteAlertRule(r.id);
    load();
    onChanged();
  }

  function channelName(id: string) {
    return channels.find((c) => c.id === id)?.name || id;
  }

  return (
    <div className="px-8 pb-8">
      <p className="text-xs text-slate-500 mb-4">
        Rules match alerts by category and/or severity and fan them out to the selected channels. A rule with no category/severity filters matches every alert. Rules with no match are not routed — the alert still appears in the feed but nothing is notified.
      </p>
      <div className="flex justify-end mb-4">
        <button
          onClick={openCreate}
          disabled={channels.length === 0}
          className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 text-sm font-semibold disabled:opacity-50"
          title={channels.length === 0 ? "Add a channel first" : undefined}
        >
          + Add Rule
        </button>
      </div>
      {loading && <Loading />}
      {!loading && rules.length === 0 && (
        <EmptyState message="No routing rules configured. Alerts are generated but not dispatched to any channel until a rule routes them." />
      )}
      <div className="space-y-3">
        {rules.map((r) => (
          <div key={r.id} className="card">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-slate-200 font-medium">{r.name}</span>
                  {!r.enabled && <span className="badge badge-fail">Disabled</span>}
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  {r.match_severities.length > 0 ? r.match_severities.join(", ") : "any severity"}
                  {" · "}
                  {r.match_categories.length > 0 ? r.match_categories.join(", ").replace(/_/g, " ") : "any category"}
                </div>
                <div className="flex gap-1 flex-wrap mt-2">
                  {r.channel_ids.map((id) => (
                    <span key={id} className="badge badge-na">{channelName(id)}</span>
                  ))}
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <button className="btn-secondary" onClick={() => openEdit(r)}>Edit</button>
                <button className="px-3 py-1.5 text-sm text-red-400 hover:text-red-300" onClick={() => remove(r)}>Delete</button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
          <div className="card w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-bold text-slate-200 mb-4">{editing ? "Edit Rule" : "Add Routing Rule"}</h3>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Name</label>
                <input className="input w-full" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="e.g. Critical findings to NOC" />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Match Severities (none = any)</label>
                <div className="flex gap-2 flex-wrap">
                  {SEVERITIES.map((s) => (
                    <button
                      type="button"
                      key={s}
                      onClick={() => setForm((f) => ({ ...f, match_severities: toggle(f.match_severities || [], s) }))}
                      className={`text-xs px-2 py-1 rounded border ${
                        (form.match_severities || []).includes(s)
                          ? "border-cyan-600 text-cyan-300 bg-cyan-950/50"
                          : "border-soc-border text-slate-500"
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Match Categories (none = any)</label>
                <div className="flex gap-2 flex-wrap max-h-32 overflow-y-auto">
                  {categories.map((c) => (
                    <button
                      type="button"
                      key={c}
                      onClick={() => setForm((f) => ({ ...f, match_categories: toggle(f.match_categories || [], c) }))}
                      className={`text-xs px-2 py-1 rounded border ${
                        (form.match_categories || []).includes(c)
                          ? "border-cyan-600 text-cyan-300 bg-cyan-950/50"
                          : "border-soc-border text-slate-500"
                      }`}
                    >
                      {c.replace(/_/g, " ")}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Channels</label>
                <div className="space-y-1">
                  {channels.map((c) => (
                    <label key={c.id} className="flex items-center gap-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={form.channel_ids.includes(c.id)}
                        onChange={() => setForm((f) => ({ ...f, channel_ids: toggle(f.channel_ids, c.id) }))}
                      />
                      {CHANNEL_ICON[c.channel_type]} {c.name}
                    </label>
                  ))}
                </div>
              </div>
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={form.enabled !== false} onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} />
                Enabled
              </label>
              {error && <div className="text-xs text-red-400">{error}</div>}
            </div>
            <div className="flex justify-end gap-2 mt-5">
              <button onClick={() => setModalOpen(false)} className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
              <button
                onClick={save}
                disabled={saving || !form.name}
                className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 text-sm font-semibold disabled:opacity-50"
              >
                {saving ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Push tab
// ---------------------------------------------------------------------------

function PushTab() {
  const [status, setStatus] = useState<"subscribed" | "unsubscribed" | "unsupported" | "denied" | "loading">("loading");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [subs, setSubs] = useState<PushSubscriptionSummary[]>([]);
  const [loadingSubs, setLoadingSubs] = useState(true);

  const refresh = useCallback(() => {
    getPushStatus().then(setStatus);
    setLoadingSubs(true);
    endpoints
      .pushSubscriptions()
      .then((r) => setSubs(r.data.subscriptions))
      .finally(() => setLoadingSubs(false));
  }, []);

  useEffect(refresh, [refresh]);

  async function enable() {
    setBusy(true);
    setError(null);
    try {
      await subscribeToPush();
      refresh();
    } catch (e: any) {
      setError(e?.message || "Failed to subscribe to push notifications");
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    setBusy(true);
    try {
      await unsubscribeFromPush();
      refresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="px-8 pb-8 space-y-6">
      <div className="card max-w-xl">
        <div className="font-semibold text-slate-200 mb-1">This browser</div>
        <p className="text-xs text-slate-500 mb-3">
          Subscribe this browser to receive native push notifications for alerts routed to a "Browser Push" channel — even when this tab isn't open.
        </p>
        {status === "unsupported" && <div className="text-xs text-amber-400">Push notifications aren't supported in this browser.</div>}
        {status === "denied" && <div className="text-xs text-red-400">Notification permission was denied. Enable it in your browser's site settings to subscribe.</div>}
        {(status === "subscribed" || status === "unsubscribed" || status === "loading") && (
          <div className="flex items-center gap-3">
            <span className={`badge ${status === "subscribed" ? "badge-pass" : "badge-na"}`}>
              {status === "loading" ? "Checking…" : status === "subscribed" ? "Subscribed" : "Not subscribed"}
            </span>
            {status !== "loading" &&
              (status === "subscribed" ? (
                <button className="btn-secondary" disabled={busy} onClick={disable}>
                  {busy ? "Working…" : "Unsubscribe"}
                </button>
              ) : (
                <button
                  className="px-4 py-2 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900 text-sm font-semibold disabled:opacity-50"
                  disabled={busy}
                  onClick={enable}
                >
                  {busy ? "Subscribing…" : "Subscribe this browser"}
                </button>
              ))}
          </div>
        )}
        {error && <div className="text-xs text-red-400 mt-2">{error}</div>}
      </div>

      <div>
        <div className="font-semibold text-slate-200 mb-2">All subscribed devices (this tenant)</div>
        {loadingSubs && <Loading />}
        {!loadingSubs && subs.length === 0 && <EmptyState message="No browsers are subscribed to push yet." />}
        <div className="space-y-2">
          {subs.map((s) => (
            <div key={s.id} className="card flex items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="text-sm text-slate-300 truncate">{s.user_agent || "Unknown device"}</div>
                <div className="text-xs text-slate-500">
                  Subscribed {s.created_at ? new Date(s.created_at).toLocaleString() : "—"}
                  {s.last_used_at && ` · last delivered ${new Date(s.last_used_at).toLocaleString()}`}
                </div>
                {s.last_error && <div className="text-xs text-red-400 mt-1">{s.last_error}</div>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}