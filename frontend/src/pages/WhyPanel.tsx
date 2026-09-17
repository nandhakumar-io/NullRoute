import { useState } from "react";

/**
 * Reusable [WHY?] component (Phase 1 spec, section 8 / Phase 2 spec, section 12).
 *
 * Used anywhere a decision needs to be explained back to raw evidence:
 * a compliance finding (raw config -> normalized value -> control -> OPA
 * policy -> OPA decision) or an AI interpretation (confidence -> semantic
 * similarity -> model agreement -> unknown syntax -> review requirement).
 *
 * This component only *displays* evidence passed in by the caller — it
 * never computes or infers a compliance/AI decision itself, per the rule
 * that "AI may assist interpretation but must never directly determine
 * compliance."
 */
export type WhyRow = {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  tone?: "neutral" | "pass" | "fail" | "review" | "unknown";
};

const TONE_CLASSES: Record<NonNullable<WhyRow["tone"]>, string> = {
  neutral: "text-slate-300",
  pass: "text-emerald-400",
  fail: "text-red-400",
  review: "text-amber-400",
  unknown: "text-slate-500",
};

export function WhyPanel({
  title = "Why?",
  rows,
  defaultOpen = false,
}: {
  title?: string;
  rows: WhyRow[];
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="card p-0 overflow-hidden border border-soc-border">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-4 py-2.5 text-left hover:bg-slate-800/30 transition-colors"
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-cyan-950 text-cyan-400 text-xs font-bold border border-cyan-800">
            ?
          </span>
          {title}
        </span>
        <span className="text-xs text-slate-500">{open ? "Hide ▾" : "Show ▸"}</span>
      </button>
      {open && (
        <div className="border-t border-soc-border px-4 py-3 space-y-2">
          {rows.map((r, i) => (
            <div key={i} className="flex flex-col sm:flex-row sm:items-baseline gap-1 sm:gap-3 text-sm">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide sm:w-44 shrink-0">
                {r.label}
              </div>
              <div
                className={`${r.mono ? "font-mono text-xs" : ""} ${
                  TONE_CLASSES[r.tone ?? "neutral"]
                } break-all whitespace-pre-wrap`}
              >
                {r.value ?? "—"}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** A single stage in a RAW -> NORMALIZED -> CONTROL -> POLICY -> RESULT chain. */
export type TraceStage = {
  label: string;
  value: React.ReactNode;
  tone?: "neutral" | "pass" | "fail" | "review" | "unknown";
};

const STAGE_TONE_CLASSES: Record<NonNullable<TraceStage["tone"]>, string> = {
  neutral: "border-slate-700 bg-slate-800/60 text-slate-200",
  pass: "border-emerald-800 bg-emerald-950/40 text-emerald-300",
  fail: "border-red-800 bg-red-950/40 text-red-300",
  review: "border-amber-800 bg-amber-950/40 text-amber-300",
  unknown: "border-slate-700 bg-slate-900/60 text-slate-500",
};

/** Vertical/horizontal traceability chain used by Finding Detail and Control Detail. */
export function TraceabilityChain({ stages }: { stages: TraceStage[] }) {
  return (
    <div className="flex flex-col gap-0">
      {stages.map((s, i) => (
        <div key={i} className="flex flex-col items-stretch">
          <div
            className={`rounded-md border px-3 py-2 ${STAGE_TONE_CLASSES[s.tone ?? "neutral"]}`}
          >
            <div className="text-[10px] font-semibold uppercase tracking-wide opacity-70 mb-0.5">
              {s.label}
            </div>
            <div className="font-mono text-xs break-all whitespace-pre-wrap">{s.value ?? "—"}</div>
          </div>
          {i < stages.length - 1 && (
            <div className="flex justify-center py-1 text-slate-600 text-sm leading-none">↓</div>
          )}
        </div>
      ))}
    </div>
  );
}