import { ReactNode, useEffect, useState } from "react";

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex items-start justify-between px-8 pt-8 pb-4">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">{title}</h1>
        {subtitle && <p className="text-sm text-slate-500 mt-1">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function StatCard({ label, value, tone = "default" }: { label: string; value: ReactNode; tone?: "default" | "critical" | "high" | "medium" | "low" | "good" }) {
  const toneClass: Record<string, string> = {
    default: "text-slate-100",
    critical: "text-red-400",
    high: "text-orange-400",
    medium: "text-amber-400",
    low: "text-emerald-400",
    good: "text-cyan-400",
  };
  return (
    <div className="card">
      <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">{label}</div>
      <div className={`text-3xl font-bold mt-2 ${toneClass[tone]}`}>{value}</div>
    </div>
  );
}

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const cls: Record<string, string> = {
    CRITICAL: "badge-critical",
    HIGH: "badge-high",
    MEDIUM: "badge-medium",
    LOW: "badge-low",
  };
  const value = severity || "UNKNOWN";
  return <span className={`badge ${cls[value] || "badge-na"}`}>{value}</span>;
}

export function ResultBadge({ result }: { result?: string | null }) {
  const cls: Record<string, string> = {
    PASS: "badge-pass",
    FAIL: "badge-fail",
    NOT_APPLICABLE: "badge-na",
    // UNVERIFIED means "not yet human-approved" (see IMPLEMENTATION_AUDIT.md
    // §A) — deliberately amber (same treatment as MEDIUM severity), never
    // green/pass or gray/n-a, so a reviewer can't mistake "not yet
    // reviewed" for either a clean pass or an irrelevant control.
    UNVERIFIED: "badge-medium",
  };
  const value = result || "UNKNOWN";
  return <span className={`badge ${cls[value] || "badge-na"}`}>{value.replace("_", " ")}</span>;
}

export function StatusBadge({ status }: { status?: string | null }) {
  const map: Record<string, string> = {
    completed: "badge-pass",
    failed: "badge-fail",
    uploaded: "badge-na",
    parsed: "badge-medium",
    normalized: "badge-medium",
  };
  const value = status || "unknown";
  return <span className={`badge ${map[value] || "badge-na"}`}>{value}</span>;
}

export function ScoreRing({ score }: { score: number }) {
  const color = score >= 80 ? "#34d399" : score >= 50 ? "#fbbf24" : "#f87171";
  return (
    <div className="relative w-24 h-24">
      <svg viewBox="0 0 36 36" className="w-24 h-24 -rotate-90">
        <circle cx="18" cy="18" r="16" fill="none" stroke="#1e2a44" strokeWidth="3" />
        <circle
          cx="18" cy="18" r="16" fill="none" stroke={color} strokeWidth="3"
          strokeDasharray={`${score}, 100`} strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center font-bold text-lg" style={{ color }}>
        {score}%
      </div>
    </div>
  );
}

export function Loading() {
  return <div className="px-8 py-12 text-slate-500 text-sm">Loading…</div>;
}

export function EmptyState({ message }: { message: string }) {
  return <div className="px-8 py-12 text-slate-500 text-sm border border-dashed border-soc-border rounded-xl text-center">{message}</div>;
}

/**
 * A `.card` that can be shrunk to just its header. Collapse state persists
 * per-storageKey in localStorage so a user's dashboard layout preference
 * survives a refresh. Use a stable, unique `storageKey` per card (e.g.
 * "dashboard.card.riskDistribution").
 */
export function CollapsibleCard({
  title, subtitle, action, storageKey, defaultCollapsed = false, children,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
  storageKey: string;
  defaultCollapsed?: boolean;
  children: ReactNode;
}) {
  const fullKey = `netsecauditor.card.${storageKey}`;
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    const stored = localStorage.getItem(fullKey);
    if (stored === "1") return true;
    if (stored === "0") return false;
    return defaultCollapsed;
  });

  useEffect(() => {
    localStorage.setItem(fullKey, collapsed ? "1" : "0");
  }, [collapsed, fullKey]);

  return (
    <div className="card !p-0 overflow-hidden">
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        className="w-full flex items-center justify-between gap-3 px-5 py-3.5 text-left hover:bg-slate-800/30 transition-colors"
        aria-expanded={!collapsed}
      >
        <div className="min-w-0">
          <div className="font-semibold text-slate-200 truncate">{title}</div>
          {subtitle && <div className="text-xs text-slate-500 mt-0.5 truncate">{subtitle}</div>}
        </div>
        <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
          {action}
          <span
            onClick={() => setCollapsed((c) => !c)}
            className="cursor-pointer w-6 h-6 flex items-center justify-center rounded-md text-slate-500 hover:text-slate-200 hover:bg-slate-700/50 transition-colors"
            title={collapsed ? "Expand" : "Collapse"}
          >
            <svg
              width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
              strokeLinecap="round" strokeLinejoin="round"
              style={{ transform: collapsed ? "rotate(-90deg)" : "rotate(0deg)", transition: "transform 150ms ease" }}
            >
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </span>
        </div>
      </button>
      {!collapsed && <div className="px-5 pb-5 pt-1">{children}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Decision pipeline -- shared "Normalized Model -> OPA -> Batfish -> Risk ->
// Decision -> Evidence" stepper used by the Validation list and Scan Result
// page, so the two surfaces (list + detail) tell a consistent visual story
// about how a scan's outcome was derived.
// ---------------------------------------------------------------------------

export type PipelineTone = "pass" | "fail" | "warn" | "na" | "pending";

export interface PipelineStepData {
  label: string;
  value: string;
  tone: PipelineTone;
  sublabel?: string;
}

const PIPELINE_TONE_STYLES: Record<PipelineTone, { dot: string; text: string; ring: string }> = {
  pass: { dot: "bg-emerald-500", text: "text-emerald-600", ring: "ring-emerald-500/30" },
  fail: { dot: "bg-red-500", text: "text-red-600", ring: "ring-red-500/30" },
  warn: { dot: "bg-amber-500", text: "text-amber-600", ring: "ring-amber-500/30" },
  na: { dot: "bg-slate-500", text: "text-slate-500", ring: "ring-slate-500/20" },
  pending: { dot: "bg-slate-400", text: "text-slate-400", ring: "ring-slate-400/20" },
};

export function opaTone(v?: string | null): PipelineTone {
  if (v === "PASS") return "pass";
  if (v === "BLOCK" || v === "FAIL") return "fail";
  if (!v) return "na";
  return "warn";
}
export function batfishTone(v?: string | null): PipelineTone {
  if (v === "BATFISH_PASS") return "pass";
  if (v === "BATFISH_FAIL") return "fail";
  if (v === "BATFISH_ERROR") return "fail";
  if (!v || v === "NOT_INTEGRATED" || v === "BATFISH_UNSUPPORTED" || v === "BATFISH_UNAVAILABLE") return "na";
  return "warn";
}
export function riskTone(v?: string | null): PipelineTone {
  if (v === "LOW") return "pass";
  if (v === "CRITICAL" || v === "HIGH") return "fail";
  if (!v) return "na";
  return "warn";
}
export function decisionTone(v?: string | null): PipelineTone {
  if (v === "PASS") return "pass";
  if (v === "BLOCK") return "fail";
  if (!v) return "pending";
  return "warn";
}

/**
 * Compact, connected step indicator: a row of labeled dots joined by a
 * line, each colored by outcome. Used both inline in a list row (dense)
 * and as the header strip of a result page (roomier, via `size="lg"`).
 */
export function DecisionPipeline({ steps, size = "md" }: { steps: PipelineStepData[]; size?: "sm" | "md" | "lg" }) {
  const dotSize = size === "lg" ? "w-3.5 h-3.5" : size === "sm" ? "w-2 h-2" : "w-2.5 h-2.5";
  const gap = size === "lg" ? "gap-1.5" : "gap-1";
  const labelSize = size === "lg" ? "text-xs" : "text-[10px]";
  return (
    <div className="flex items-center w-full">
      {steps.map((step, i) => {
        const style = PIPELINE_TONE_STYLES[step.tone];
        return (
          <div key={step.label} className={`flex items-center ${i < steps.length - 1 ? "flex-1" : ""}`}>
            <div className={`flex flex-col items-center ${gap} shrink-0`} title={step.sublabel ? `${step.value} — ${step.sublabel}` : step.value}>
              <span className={`rounded-full ${dotSize} ${style.dot} ring-4 ${style.ring}`} />
              <span className={`${labelSize} font-semibold uppercase tracking-wide text-slate-500 whitespace-nowrap`}>{step.label}</span>
              <span className={`${labelSize} font-medium ${style.text} whitespace-nowrap`}>{step.value}</span>
            </div>
            {i < steps.length - 1 && (
              <div className={`flex-1 h-px mx-2 ${step.tone === "pending" ? "bg-slate-800" : "bg-slate-700"}`} style={{ marginBottom: size === "lg" ? 20 : 14 }} />
            )}
          </div>
        );
      })}
    </div>
  );
}