import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { endpoints, Scan } from "../api";
import { useToast } from "../lib/toast";
import { useConfirm } from "../lib/confirm";

const STAGE_LABEL: Record<string, string> = {
  queued: "Queued",
  resuming: "Resuming",
  uploaded: "Starting",
  parsed: "Parsing",
  normalized: "Normalizing",
  opa_evaluating: "OPA evaluation",
  batfish_evaluating: "Batfish evaluation",
  correlating: "Correlating",
  paused: "Paused",
};

function stageLabel(s: Scan): string {
  if (s.control_state === "PAUSE_REQUESTED") return "Pause requested…";
  if (s.control_state === "STOP_REQUESTED") return "Stopping…";
  if (s.control_state === "PAUSED") return `Paused at ${s.pipeline_stage || "start"}`;
  return STAGE_LABEL[s.status] || s.status;
}

/** Header widget: a badge showing how many pipelines are currently running
 * (queued, mid-stage, or paused/stop-requested), with a dropdown to jump to
 * one or stop it immediately -- rather than having to open each scan's own
 * page to find its Pause/Stop buttons. Polls independently of whatever page
 * is open so the count stays current from anywhere in the app. */
export default function RunningPipelines() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [open, setOpen] = useState(false);
  const [stoppingIds, setStoppingIds] = useState<Set<string>>(new Set());
  // Bumped whenever the list is changed by an action. A poll that started
  // before the bump carries a stale snapshot (it may still list a scan that
  // was just stopped) and must not overwrite the fresher state -- that race
  // is what made the count drop and then jump back up.
  const pollSeq = useRef(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();

  const refresh = useCallback(async () => {
    const seq = ++pollSeq.current;
    try {
      const res = await endpoints.runningScans();
      if (seq === pollSeq.current) setScans(res.data);
    } catch {
      // Best-effort -- a failed poll just leaves the last known list showing.
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, open ? 2000 : 5000);
    return () => window.clearInterval(id);
  }, [refresh, open]);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  async function stopMany(targets: Scan[], title: string, message: string) {
    if (targets.length === 0) return;
    const ok = await confirm(message, { title, confirmLabel: "Stop now", danger: true });
    if (!ok) return;
    const ids = targets.map((t) => t.id);
    setStoppingIds((prev) => new Set([...prev, ...ids]));
    try {
      // One call, one server-side pass: every live task is cancelled together
      // and each scan is persisted as STOPPED before this returns.
      const res = await endpoints.bulkStopScans(ids, true);
      const gone = new Set([...res.data.stopped, ...res.data.skipped.map((s) => s.id)]);
      pollSeq.current++; // invalidate any in-flight poll snapshot
      setScans((prev) => prev.filter((s) => !gone.has(s.id)));
      toast.success(ids.length === 1 ? "Pipeline stopped." : `Stopped ${res.data.stopped.length} pipelines.`);
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || "Failed to stop the pipeline");
    } finally {
      setStoppingIds((prev) => {
        const next = new Set(prev);
        ids.forEach((i) => next.delete(i));
        return next;
      });
      refresh(); // reconcile with the server's truth either way
    }
  }

  const stopNow = (scan: Scan) =>
    stopMany(
      [scan],
      "Stop pipeline now",
      "Stop this pipeline immediately? It is cancelled mid-stage rather than waiting for its next checkpoint. Whatever it already saved is kept, and it can be resumed later from there."
    );

  const stopAll = () =>
    stopMany(
      scans.filter((s) => s.control_state !== "PAUSED"),
      "Stop all pipelines",
      `Stop all ${scans.filter((s) => s.control_state !== "PAUSED").length} running or queued pipelines immediately? Saved progress is kept and each can be resumed later.`
    );

  const count = scans.length;

  return (
    <div className="relative" ref={rootRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="relative shrink-0 h-9 px-3 rounded-md border flex items-center gap-2 transition-colors text-sm"
        style={{ borderColor: "var(--border)", color: count > 0 ? "var(--ink)" : "var(--ink-muted)" }}
        title="Running pipelines"
      >
        <span
          className={`w-2 h-2 rounded-full ${count > 0 ? "bg-cyan-400 animate-pulse" : "bg-slate-600"}`}
        />
        <span className="hidden md:inline">Pipelines</span>
        <span
          className="min-w-[1.25rem] h-5 px-1 rounded-full text-xs flex items-center justify-center font-semibold"
          style={{
            background: count > 0 ? "var(--brand-soft)" : "transparent",
            color: count > 0 ? "var(--brand)" : "var(--ink-faint)",
          }}
        >
          {count}
        </span>
      </button>

      {open && (
        <div
          className="absolute right-0 mt-2 w-[min(24rem,calc(100vw-1.5rem))] max-h-[28rem] overflow-y-auto rounded-lg border shadow-xl z-[70]"
          style={{ background: "var(--panel)", borderColor: "var(--border)" }}
        >
          <div
            className="px-4 py-3 border-b text-sm font-semibold flex items-center justify-between gap-3 sticky top-0"
            style={{ borderColor: "var(--border)", color: "var(--ink)", background: "var(--panel)" }}
          >
            <span>Running pipelines {count > 0 && `(${count})`}</span>
            {count > 1 && (
              <button
                onClick={stopAll}
                disabled={stoppingIds.size > 0}
                className="text-xs font-medium px-2.5 py-1 rounded-md border border-red-800/60 text-red-400 hover:bg-red-500/10 disabled:opacity-50"
              >
                Stop all
              </button>
            )}
          </div>

          {count === 0 && (
            <div className="px-4 py-6 text-sm text-center" style={{ color: "var(--ink-faint)" }}>
              No pipelines are currently running.
            </div>
          )}

          {scans.map((s) => (
            <div key={s.id} className="px-4 py-3 border-b last:border-b-0 flex items-center justify-between gap-3" style={{ borderColor: "var(--border)" }}>
              <button
                className="min-w-0 text-left"
                onClick={() => {
                  navigate(`/scans/${s.id}`);
                  setOpen(false);
                }}
              >
                <div className="text-sm font-medium truncate" style={{ color: "var(--ink)" }}>
                  {s.source_filename || `Scan ${s.id.slice(0, 8)}`} · {s.framework}
                </div>
                <div className="text-xs mt-0.5" style={{ color: "var(--ink-faint)" }}>
                  {stageLabel(s)}
                </div>
              </button>
              <button
                onClick={() => stopNow(s)}
                disabled={stoppingIds.has(s.id) || s.control_state === "STOP_REQUESTED"}
                className="shrink-0 text-xs font-medium px-2.5 py-1.5 rounded-md border border-red-800/60 text-red-400 hover:bg-red-500/10 disabled:opacity-50"
                title="Cancel this pipeline immediately, without waiting for its next checkpoint"
              >
                {stoppingIds.has(s.id) ? "Stopping…" : "Stop now"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}