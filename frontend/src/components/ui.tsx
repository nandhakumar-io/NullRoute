import { ReactNode } from "react";

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

export function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    CRITICAL: "badge-critical",
    HIGH: "badge-high",
    MEDIUM: "badge-medium",
    LOW: "badge-low",
  };
  return <span className={`badge ${cls[severity] || "badge-na"}`}>{severity}</span>;
}

export function ResultBadge({ result }: { result: string }) {
  const cls: Record<string, string> = {
    PASS: "badge-pass",
    FAIL: "badge-fail",
    NOT_APPLICABLE: "badge-na",
  };
  return <span className={`badge ${cls[result] || "badge-na"}`}>{result.replace("_", " ")}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: "badge-pass",
    failed: "badge-fail",
    uploaded: "badge-na",
    parsed: "badge-medium",
    normalized: "badge-medium",
  };
  return <span className={`badge ${map[status] || "badge-na"}`}>{status}</span>;
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
