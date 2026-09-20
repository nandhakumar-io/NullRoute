import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { endpoints, Scan, Device } from "../api";
import {
  PageHeader, Loading, EmptyState, StatCard, DecisionPipeline,
  opaTone, batfishTone, riskTone, decisionTone, PipelineStepData,
} from "../components/ui";
import { errorMessage, useToast } from "../lib/toast";
import { useConfirm } from "../lib/confirm";

const DECISION_OPTIONS = ["ALL", "PASS", "REVIEW", "BLOCK", "PENDING", "STOPPED"];
const DECISION_LABEL: Record<string, string> = {
  ALL: "All decisions", PASS: "Passed", REVIEW: "Needs review", BLOCK: "Blocked",
  PENDING: "In progress", STOPPED: "Stopped / failed",
};
const TERMINAL = new Set(["completed", "review", "blocked", "failed", "stopped"]);
const MAX_FILES = 50;
const MAX_FILE_BYTES = 5 * 1024 * 1024;

/** A pipeline is in flight (queued, running, paused or stopping) -- i.e. it
 * isn't finished and isn't stopped. NB: a finished scan keeps
 * control_state="RUNNING", so this must look at status, not control_state. */
function isActive(s: Scan): boolean {
  return !TERMINAL.has(s.status) && s.control_state !== "STOPPED";
}
function isStopped(s: Scan): boolean {
  return s.status === "stopped" || s.control_state === "STOPPED";
}
/** Stop is meaningful for anything live or paused (not already finished). */
const canStop = (s: Scan) => isActive(s);
const canResume = (s: Scan) => s.control_state === "PAUSED" || s.control_state === "STOPPED";

const STAGE_TEXT: Record<string, string> = {
  queued: "Queued", uploaded: "Starting", resuming: "Resuming", parsed: "Parsing", normalized: "Normalizing",
  opa_evaluating: "OPA", batfish_evaluating: "Batfish", correlating: "Correlating",
};

function statusOf(s: Scan): { label: string; cls: string; pulse?: boolean } {
  if (s.control_state === "STOP_REQUESTED") return { label: "Stopping…", cls: "badge-medium", pulse: true };
  if (s.control_state === "PAUSE_REQUESTED") return { label: "Pausing…", cls: "badge-medium", pulse: true };
  if (s.control_state === "PAUSED") return { label: "Paused", cls: "badge-medium" };
  if (isStopped(s)) return { label: "Stopped", cls: "bg-slate-800 text-slate-400 border border-slate-700" };
  if (s.status === "failed") return { label: "Failed", cls: "badge-fail" };
  if (isActive(s)) return { label: STAGE_TEXT[s.status] || "Running", cls: "badge-medium", pulse: true };
  return { label: s.final_decision || "PENDING", cls: s.final_decision === "PASS" ? "badge-pass" : s.final_decision === "BLOCK" ? "badge-fail" : "badge-medium" };
}
type SortMode = "priority" | "recent";
const DECISION_PRIORITY: Record<string, number> = { BLOCK: 0, REVIEW: 1, PASS: 3 };

function StatusPill({ scan }: { scan: Scan }) {
  const st = statusOf(scan);
  return (
    <span className={`badge ${st.cls} text-sm px-3 py-1 inline-flex items-center gap-1.5`}>
      {st.pulse && <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />}
      {st.label}
    </span>
  );
}

function buildSteps(s: Scan): PipelineStepData[] {
  return [
    {
      label: "Normalized",
      ...(s.status === "failed"
        ? { value: "FAILED", tone: "fail" as const }
        : ["queued", "uploaded", "parsed", "resuming"].includes(s.status) || (isStopped(s) && !s.opa_decision && !s.final_decision)
          ? { value: isStopped(s) ? "STOPPED" : "PENDING", tone: "pending" as const }
          : { value: "MODELED", tone: "pass" as const }),
      sublabel: "Vendor config -> common security model",
    },
    { label: "OPA", value: (s.opa_decision || "PENDING").replace(/_/g, " "), tone: opaTone(s.opa_decision), sublabel: "Deterministic policy engine" },
    { label: "Batfish", value: (s.batfish_status || "N/A").replace(/_/g, " "), tone: batfishTone(s.batfish_status), sublabel: "Network behavior verification" },
    { label: "Risk", value: s.risk_level || "N/A", tone: riskTone(s.risk_level), sublabel: s.risk_score != null ? `score ${s.risk_score}` : undefined },
    { label: "Decision", value: s.final_decision || (isStopped(s) ? "STOPPED" : "PENDING"), tone: decisionTone(s.final_decision), sublabel: s.final_reason || undefined },
  ];
}

/** Row-level pipeline: reveals Normalized -> OPA -> Batfish -> Risk -> Decision
 * one step at a time on first mount instead of rendering every step's final
 * tone the instant the scan list loads, so the validation flow actually
 * reads as a pipeline rather than a wall of dots that all light up at once. */
function ScanPipelineRow({ scan }: { scan: Scan }) {
  const steps = useMemo(() => buildSteps(scan), [scan]);
  const [revealed, setRevealed] = useState(0);
  const seen = useRef(false);
  useEffect(() => {
    if (seen.current) { setRevealed(steps.length); return; }
    seen.current = true;
    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setRevealed(i);
      if (i >= steps.length) clearInterval(id);
    }, 220);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return <DecisionPipeline size="sm" steps={steps} revealedCount={revealed} />;
}

export default function Validation() {
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const [scans, setScans] = useState<Scan[]>([]);
  const [devices, setDevices] = useState<Record<string, Device>>({});
  const [loading, setLoading] = useState(true);
  const [decisionFilter, setDecisionFilter] = useState("ALL");
  const [frameworkFilter, setFrameworkFilter] = useState("ALL");
  const [sortMode, setSortMode] = useState<SortMode>("priority");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<Set<string>>(new Set()); // rows with an action in flight
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  // Same stale-snapshot guard as RunningPipelines: a poll that began before
  // an action finished must not overwrite the state that action produced.
  const seq = useRef(0);

  const markBusy = (ids: string[], on: boolean) =>
    setBusy((prev) => {
      const next = new Set(prev);
      ids.forEach((i) => (on ? next.add(i) : next.delete(i)));
      return next;
    });

  const load = useCallback(async () => {
    const mine = ++seq.current;
    try {
      const res = await endpoints.scans({ limit: 500 });
      if (mine !== seq.current) return;
      setScans(res.data);
      // Drop selections for scans that no longer exist.
      setSelected((prev) => {
        const alive = new Set(res.data.map((s) => s.id));
        const next = new Set([...prev].filter((i) => alive.has(i)));
        return next.size === prev.size ? prev : next;
      });
    } catch {
      /* keep last known list on a failed poll */
    }
  }, []);

  useEffect(() => {
    Promise.all([load(), endpoints.devices({ limit: 500 }).catch(() => null)]).then(([, deviceRes]) => {
      if (deviceRes) {
        const items = ((deviceRes.data as any).items ?? deviceRes.data) as Device[];
        const map: Record<string, Device> = {};
        (Array.isArray(items) ? items : []).forEach((d) => { map[d.id] = d; });
        setDevices(map);
      }
    }).finally(() => setLoading(false));
  }, [load]);

  // Live progress: poll while anything is still in flight (fast when the
  // tab is visible), otherwise stay quiet.
  const anyActive = scans.some(isActive);
  useEffect(() => {
    if (!anyActive) return;
    const id = window.setInterval(() => { if (!document.hidden) load(); }, 2500);
    return () => window.clearInterval(id);
  }, [anyActive, load]);

  const frameworks = useMemo(
    () => Array.from(new Set(scans.map((s) => s.framework).filter(Boolean))).sort(),
    [scans]
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const rows = scans
      .filter((s) => {
        switch (decisionFilter) {
          case "ALL": return true;
          case "PENDING": return isActive(s);
          case "STOPPED": return isStopped(s) || s.status === "failed";
          default: return s.final_decision === decisionFilter && !isActive(s);
        }
      })
      .filter((s) => frameworkFilter === "ALL" || s.framework === frameworkFilter)
      .filter((s) => {
        if (!q) return true;
        const device = devices[s.device_id];
        return (
          s.id.toLowerCase().includes(q) ||
          s.framework?.toLowerCase().includes(q) ||
          s.source_filename?.toLowerCase().includes(q) ||
          device?.hostname?.toLowerCase().includes(q) ||
          device?.management_address?.toLowerCase().includes(q)
        );
      });
    if (sortMode === "priority") {
      // BLOCK, REVIEW, then in-progress/unknown, PASS last -- surface what
      // needs a human first. Stable, so ties keep most-recent-first.
      return [...rows].sort((a, b) => {
        const pa = DECISION_PRIORITY[a.final_decision || "PENDING"] ?? 2;
        const pb = DECISION_PRIORITY[b.final_decision || "PENDING"] ?? 2;
        return pa - pb;
      });
    }
    return rows;
  }, [scans, decisionFilter, frameworkFilter, search, devices, sortMode]);

  if (loading) return <Loading />;

  const counts = {
    PASS: scans.filter((s) => s.final_decision === "PASS" && !isActive(s)).length,
    REVIEW: scans.filter((s) => s.final_decision === "REVIEW" && !isActive(s)).length,
    BLOCK: scans.filter((s) => s.final_decision === "BLOCK" && !isActive(s)).length,
    PENDING: scans.filter(isActive).length,
    STOPPED: scans.filter((s) => isStopped(s) || s.status === "failed").length,
  };

  const statCardCls = (active: boolean) =>
    `text-left transition-all ${active ? "ring-2 ring-cyan-600 rounded-xl" : "hover:opacity-80"}`;
  const toggleFilter = (v: string) => setDecisionFilter(decisionFilter === v ? "ALL" : v);

  // ---- selection ---------------------------------------------------------
  const visibleIds = filtered.map((s) => s.id);
  const allSelected = visibleIds.length > 0 && visibleIds.every((i) => selected.has(i));
  const someSelected = visibleIds.some((i) => selected.has(i));
  const toggleOne = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  const toggleAll = () =>
    setSelected((prev) => {
      const next = new Set(prev);
      allSelected ? visibleIds.forEach((i) => next.delete(i)) : visibleIds.forEach((i) => next.add(i));
      return next;
    });
  const selectedScans = scans.filter((s) => selected.has(s.id));
  const selectedActive = selectedScans.filter(canStop);

  // ---- actions -----------------------------------------------------------
  async function stopScans(targets: Scan[]) {
    const stoppable = targets.filter(canStop);
    if (stoppable.length === 0) return;
    const ok = await confirm(
      stoppable.length === 1
        ? "Stop this scan immediately? Progress already saved is kept and it can be resumed later."
        : `Stop ${stoppable.length} scans immediately? Progress already saved is kept and each can be resumed later.`,
      { title: stoppable.length === 1 ? "Stop scan" : `Stop ${stoppable.length} scans`, confirmLabel: "Stop now", danger: true }
    );
    if (!ok) return;
    const ids = stoppable.map((s) => s.id);
    markBusy(ids, true);
    try {
      const res = await endpoints.bulkStopScans(ids, true);
      seq.current++; // invalidate in-flight polls
      const done = new Set(res.data.stopped);
      const now = new Date().toISOString();
      setScans((prev) =>
        prev.map((s) => (done.has(s.id) ? { ...s, status: "stopped", control_state: "STOPPED", stopped_at: now } : s))
      );
      const skipped = res.data.skipped.length;
      toast.success(`Stopped ${res.data.stopped.length} scan${res.data.stopped.length === 1 ? "" : "s"}${skipped ? ` (${skipped} already finished)` : ""}.`);
    } catch (e) {
      toast.error(errorMessage(e, "Failed to stop the scan(s)"));
    } finally {
      markBusy(ids, false);
      load();
    }
  }

  async function resumeScan(scan: Scan) {
    markBusy([scan.id], true);
    try {
      const res = await endpoints.resumeScan(scan.id);
      seq.current++;
      setScans((prev) => prev.map((s) => (s.id === scan.id ? { ...s, ...res.data } : s)));
      toast.info("Scan resumed.");
    } catch (e) {
      toast.error(errorMessage(e, "Failed to resume the scan"));
    } finally {
      markBusy([scan.id], false);
      load();
    }
  }

  async function deleteScans(targets: Scan[]) {
    if (targets.length === 0) return;
    const running = targets.filter(isActive).length;
    const ok = await confirm(
      `Permanently delete ${targets.length === 1 ? "this scan" : `${targets.length} scans`} and their findings, OPA/Batfish results and AI analysis? ` +
        `Evidence records and device snapshots are kept but detached. This can't be undone.` +
        (running ? `\n\n${running} still running — they will be stopped first only if you confirm the follow-up prompt.` : ""),
      { title: targets.length === 1 ? "Delete scan" : `Delete ${targets.length} scans`, confirmLabel: "Delete", danger: true }
    );
    if (!ok) return;
    const ids = targets.map((s) => s.id);
    markBusy(ids, true);
    try {
      let deleted: string[] = [];
      let res = await endpoints.bulkDeleteScans(ids, false);
      deleted = res.data.deleted;
      // Running scans and golden baselines are refused without `force`; ask
      // once, explicitly, before overriding either.
      const protectedIds = res.data.failed.filter((f) => /still running|golden baseline/i.test(f.detail)).map((f) => f.id);
      if (protectedIds.length > 0) {
        const again = await confirm(
          `${protectedIds.length} scan${protectedIds.length === 1 ? " is" : "s are"} still running or ${protectedIds.length === 1 ? "is a" : "are"} golden baseline${protectedIds.length === 1 ? "" : "s"}. ` +
            `Stop any running ones and delete ${protectedIds.length === 1 ? "it" : "them"} anyway?`,
          { title: "Delete anyway?", confirmLabel: "Delete anyway", danger: true }
        );
        if (again) {
          res = await endpoints.bulkDeleteScans(protectedIds, true);
          deleted = [...deleted, ...res.data.deleted];
          res.data.failed.forEach((f) => toast.error(`${f.id.slice(0, 8)}: ${f.detail}`));
        }
      } else {
        res.data.failed.forEach((f) => toast.error(`${f.id.slice(0, 8)}: ${f.detail}`));
      }
      if (deleted.length > 0) {
        seq.current++;
        const gone = new Set(deleted);
        setScans((prev) => prev.filter((s) => !gone.has(s.id)));
        setSelected((prev) => new Set([...prev].filter((i) => !gone.has(i))));
        toast.success(`Deleted ${deleted.length} scan${deleted.length === 1 ? "" : "s"}.`);
      }
    } catch (e) {
      toast.error(errorMessage(e, "Failed to delete the scan(s)"));
    } finally {
      markBusy(ids, false);
      load();
    }
  }

  async function uploadFiles(list: FileList | File[]) {
    const files = Array.from(list);
    if (files.length === 0) return;
    if (files.length > MAX_FILES) {
      toast.error(`Too many files: ${files.length}. Upload at most ${MAX_FILES} at a time.`);
      return;
    }
    const tooBig = files.filter((f) => f.size > MAX_FILE_BYTES);
    if (tooBig.length > 0) toast.info(`${tooBig.length} file${tooBig.length === 1 ? " is" : "s are"} over 5MB and will be recorded as failed.`);
    setUploading(true);
    try {
      const fw = frameworkFilter !== "ALL" ? frameworkFilter : "ALL";
      const res = await endpoints.bulkUploadConfigs(files, fw);
      const failed = res.data.filter((s) => s.status === "failed");
      seq.current++;
      // Show the new rows immediately; polling then follows their progress.
      setScans((prev) => [...res.data.map(({ baseline_json, findings, ...rest }) => rest as Scan), ...prev]);
      setDecisionFilter("ALL");
      if (failed.length > 0) toast.error(`${failed.length} of ${res.data.length} file(s) could not be scanned: ${failed[0].error}`);
      const ok = res.data.length - failed.length;
      if (ok > 0) toast.success(`Queued ${ok} scan${ok === 1 ? "" : "s"}.`);
    } catch (e) {
      toast.error(errorMessage(e, "Upload failed"));
    } finally {
      setUploading(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  const onCardClick = (e: React.MouseEvent, scan: Scan, needsRemediation: boolean) => {
    if ((e.target as HTMLElement).closest("a,button,input,label,select")) return;
    navigate(needsRemediation ? `/scans/${scan.id}#remediation` : `/scans/${scan.id}`);
  };

  return (
    <div
      className="pb-10"
      onDragOver={(e) => { if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); setDragOver(true); } }}
      onDragLeave={(e) => { if (e.currentTarget === e.target) setDragOver(false); }}
      onDrop={(e) => { e.preventDefault(); setDragOver(false); uploadFiles(e.dataTransfer.files); }}
    >
      <PageHeader
        title="Validation"
        subtitle="Correlated decision per scan — OPA (deterministic policy) × Batfish (network behavior) × Risk, per the correlation precedence rules. The LLM never determines this outcome."
        action={
          <div className="shrink-0">
            <input
              ref={fileInput}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => e.target.files && uploadFiles(e.target.files)}
            />
            <button className="btn-primary text-sm" disabled={uploading} onClick={() => fileInput.current?.click()}>
              {uploading ? "Uploading…" : "Upload configs"}
            </button>
          </div>
        }
      />

      {dragOver && (
        <div className="mx-8 mb-4 rounded-xl border-2 border-dashed p-6 text-center text-sm ui-tone-info">
          Drop configuration files to scan them (up to {MAX_FILES}, 5MB each)
        </div>
      )}

      <div className="px-8 grid grid-cols-2 md:grid-cols-5 gap-4 mb-2">
        <button className={statCardCls(decisionFilter === "PASS")} onClick={() => toggleFilter("PASS")}>
          <StatCard label="Passed" value={counts.PASS} tone="good" />
        </button>
        <button className={statCardCls(decisionFilter === "REVIEW")} onClick={() => toggleFilter("REVIEW")}>
          <StatCard label="Needs Review" value={counts.REVIEW} tone="medium" />
        </button>
        <button className={statCardCls(decisionFilter === "BLOCK")} onClick={() => toggleFilter("BLOCK")}>
          <StatCard label="Blocked" value={counts.BLOCK} tone="critical" />
        </button>
        <button className={statCardCls(decisionFilter === "PENDING")} onClick={() => toggleFilter("PENDING")}>
          <StatCard label="In progress" value={counts.PENDING} tone="default" />
        </button>
        <button className={statCardCls(decisionFilter === "STOPPED")} onClick={() => toggleFilter("STOPPED")}>
          <StatCard label="Stopped / failed" value={counts.STOPPED} tone="default" />
        </button>
      </div>
      <div className="px-8 mb-6 text-xs text-slate-500">
        Click a card to filter · showing the {scans.length} most recent scans · drop files anywhere on this page to upload
      </div>

      <div className="px-8 pb-8 space-y-4">
        <div className="flex gap-3 items-center flex-wrap justify-between">
          <div className="flex gap-3 items-center flex-wrap">
            <select className="select text-sm" value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
              {DECISION_OPTIONS.map((d) => (
                <option key={d} value={d}>{DECISION_LABEL[d]}</option>
              ))}
            </select>
            {frameworks.length > 1 && (
              <select className="select text-sm" value={frameworkFilter} onChange={(e) => setFrameworkFilter(e.target.value)}>
                <option value="ALL">All frameworks</option>
                {frameworks.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
            )}
            <select className="select text-sm" value={sortMode} onChange={(e) => setSortMode(e.target.value as SortMode)}>
              <option value="priority">Needs attention first</option>
              <option value="recent">Most recent first</option>
            </select>
            <input
              className="input w-64 text-sm"
              placeholder="Search by device, file, scan ID, or framework…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <span className="text-xs text-slate-500">{filtered.length} of {scans.length} scans</span>
        </div>

        {/* Selection / bulk-action bar */}
        <div className="flex items-center gap-3 flex-wrap ui-inset px-4 py-2.5">
          <label className="flex items-center gap-2 text-sm cursor-pointer select-none" style={{ color: "var(--ink)" }}>
            <input
              type="checkbox"
              className="ui-check"
              checked={allSelected}
              ref={(el) => { if (el) el.indeterminate = !allSelected && someSelected; }}
              onChange={toggleAll}
              disabled={visibleIds.length === 0}
            />
            {selected.size > 0 ? `${selected.size} selected` : "Select all"}
          </label>
          <div className="flex-1" />
          <button
            className="ui-btn ui-btn-neutral ui-btn-sm"
            disabled={selectedActive.length === 0}
            onClick={() => stopScans(selectedActive)}
          >
            Stop{selectedActive.length ? ` (${selectedActive.length})` : ""}
          </button>
          <button
            className="ui-btn ui-btn-reject ui-btn-sm"
            disabled={selected.size === 0}
            onClick={() => deleteScans(selectedScans)}
          >
            Delete{selected.size ? ` (${selected.size})` : ""}
          </button>
          {selected.size > 0 && (
            <button className="ui-btn ui-btn-ghost ui-btn-sm" onClick={() => setSelected(new Set())}>Clear</button>
          )}
        </div>

        {filtered.length === 0 && <EmptyState message="No scans match this filter." />}

        {filtered.map((s) => {
          const device = devices[s.device_id];
          const active = isActive(s);
          const needsRemediation = !active && (s.final_decision === "BLOCK" || s.final_decision === "REVIEW");
          const rowBusy = busy.has(s.id);
          const title = s.source_filename || device?.hostname || device?.management_address || `Device ${s.device_id.slice(0, 8)}`;
          return (
            <div
              key={s.id}
              onClick={(e) => onCardClick(e, s, needsRemediation)}
              className={`card block p-5 cursor-pointer hover:border-cyan-700/60 hover:shadow-cyan-900/10 transition-all ${selected.has(s.id) ? "ui-selected" : ""} ${rowBusy ? "opacity-60" : ""}`}
            >
              <div className="flex items-start justify-between gap-6 flex-wrap mb-4">
                <div className="flex items-start gap-3 min-w-0">
                  <input
                    type="checkbox"
                    className="ui-check mt-2"
                    checked={selected.has(s.id)}
                    onChange={() => toggleOne(s.id)}
                    aria-label={`Select scan ${s.id.slice(0, 8)}`}
                  />
                  <div className="min-w-0">
                    <div className="flex items-center gap-3 flex-wrap">
                      <Link to={`/scans/${s.id}`} className="font-semibold text-lg text-slate-200 hover:underline break-all">
                        {title}
                      </Link>
                      <StatusPill scan={s} />
                      {device?.vendor && <span className="badge bg-slate-800 text-slate-400 border border-slate-700 text-xs">{device.vendor}</span>}
                    </div>
                    <div className="text-sm text-slate-500 mt-1.5 flex items-center gap-2 flex-wrap">
                      <span className="font-mono">{s.id.slice(0, 8)}</span>
                      <span>·</span>
                      <span>{s.framework}</span>
                      <span>·</span>
                      <span>{new Date(s.created_at).toLocaleString()}</span>
                      <span>·</span>
                      <span className={s.evidence_id ? "text-emerald-600" : "text-slate-500"}>
                        {s.evidence_id ? "Evidence anchored" : "No evidence yet"}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="shrink-0 flex items-start gap-5">
                  <div className="flex items-center gap-2">
                    {canStop(s) && (
                      <button className="ui-btn ui-btn-neutral ui-btn-sm" disabled={rowBusy || s.control_state === "STOP_REQUESTED"} onClick={() => stopScans([s])}>
                        {s.control_state === "STOP_REQUESTED" ? "Stopping…" : "Stop"}
                      </button>
                    )}
                    {canResume(s) && (
                      <button className="ui-btn ui-btn-neutral ui-btn-sm" disabled={rowBusy} onClick={() => resumeScan(s)}>Resume</button>
                    )}
                    <button className="ui-btn ui-btn-reject ui-btn-sm" disabled={rowBusy} onClick={() => deleteScans([s])}>Delete</button>
                  </div>
                  <div className="text-right">
                    <div className="text-4xl font-bold text-slate-100">
                      {s.compliance_score != null ? `${s.compliance_score}%` : "—"}
                    </div>
                    <div className="text-xs uppercase tracking-wide text-slate-500">compliance</div>
                  </div>
                </div>
              </div>

              <ScanPipelineRow scan={s} />

              {(s.status === "failed" || isStopped(s)) && s.error && (
                <div className="text-sm mt-4 pt-3 border-t border-soc-border ui-muted">{s.error}</div>
              )}

              {needsRemediation && (
                <div className="flex items-center justify-between gap-3 mt-4 pt-3 border-t border-soc-border">
                  <span className="text-xs text-amber-400">
                    AI remediation is available for this scan's failing controls — review the synthesized
                    commands, create a Change Request, then approve it there before it can deploy
                    (human approval is always required; nothing auto-deploys on its own).
                  </span>
                  <Link to={`/scans/${s.id}#remediation`} className="btn-secondary text-xs whitespace-nowrap">Open Remediation →</Link>
                </div>
              )}

              {!active && s.final_reason && (
                <div className="text-sm text-slate-400 mt-4 pt-3 border-t border-soc-border">{s.final_reason}</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
