export function apiErrorMessage(e: any, fallback: string): string {
  const detail = e?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (e?.response?.status === 403) return "You don't have permission to do that (admin or security_analyst role required).";
  if (e?.response?.status === 401) return "Your session has expired — please sign in again.";
  return fallback;
}

export const STATUS_STYLE: Record<string, string> = {
  COMPLETED: "bg-emerald-500/20 text-emerald-400",
  PRODUCTION: "bg-emerald-500/20 text-emerald-400",
  FINALIZED: "bg-emerald-500/20 text-emerald-400",
  APPROVED: "bg-cyan-500/20 text-cyan-400",
  FAILED: "bg-red-500/20 text-red-400",
  REJECTED: "bg-red-500/20 text-red-400",
  CANCELLED: "bg-slate-500/20 text-slate-300",
  ARCHIVED: "bg-slate-500/20 text-slate-300",
  DRAFT: "bg-amber-500/20 text-amber-400",
  QUEUED: "bg-amber-500/20 text-amber-400",
  RUNNING: "bg-blue-500/20 text-blue-400",
  CANDIDATE: "bg-slate-500/20 text-slate-300",
};

export const statusClass = (s: string) => STATUS_STYLE[s] || "bg-slate-500/20 text-slate-300";
