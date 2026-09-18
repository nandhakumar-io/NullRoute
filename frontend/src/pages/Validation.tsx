import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, Scan, Device } from "../api";
import {
  PageHeader, Loading, EmptyState, StatCard, DecisionPipeline,
  opaTone, batfishTone, riskTone, decisionTone, PipelineStepData,
} from "../components/ui";

const DECISION_OPTIONS = ["ALL", "PASS", "REVIEW", "BLOCK", "PENDING"];
type SortMode = "priority" | "recent";
const DECISION_PRIORITY: Record<string, number> = { BLOCK: 0, REVIEW: 1, PASS: 3 };

function DecisionPill({ decision }: { decision: string | null | undefined }) {
  const cls =
    decision === "PASS" ? "badge-pass" : decision === "BLOCK" ? "badge-fail" : "badge-medium";
  return <span className={`badge ${cls} text-sm px-3 py-1`}>{decision || "PENDING"}</span>;
}

function buildSteps(s: Scan): PipelineStepData[] {
  return [
    {
      label: "Normalized",
      value: s.status === "failed" ? "FAILED" : "MODELED",
      tone: s.status === "failed" ? "fail" : "pass",
      sublabel: "Vendor config -> common security model",
    },
    { label: "OPA", value: (s.opa_decision || "PENDING").replace(/_/g, " "), tone: opaTone(s.opa_decision), sublabel: "Deterministic policy engine" },
    { label: "Batfish", value: (s.batfish_status || "N/A").replace(/_/g, " "), tone: batfishTone(s.batfish_status), sublabel: "Network behavior verification" },
    { label: "Risk", value: s.risk_level || "N/A", tone: riskTone(s.risk_level), sublabel: s.risk_score != null ? `score ${s.risk_score}` : undefined },
    { label: "Decision", value: s.final_decision || "PENDING", tone: decisionTone(s.final_decision), sublabel: s.final_reason || undefined },
  ];
}

export default function Validation() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [devices, setDevices] = useState<Record<string, Device>>({});
  const [loading, setLoading] = useState(true);
  const [decisionFilter, setDecisionFilter] = useState("ALL");
  const [frameworkFilter, setFrameworkFilter] = useState("ALL");
  const [sortMode, setSortMode] = useState<SortMode>("priority");
  const [search, setSearch] = useState("");

  useEffect(() => {
    Promise.all([
      endpoints.scans(),
      endpoints.devices({ limit: 500 }).catch(() => null),
    ]).then(([scanRes, deviceRes]) => {
      setScans(scanRes.data);
      if (deviceRes) {
        const items = ((deviceRes.data as any).items ?? deviceRes.data) as Device[];
        const map: Record<string, Device> = {};
        (Array.isArray(items) ? items : []).forEach((d) => { map[d.id] = d; });
        setDevices(map);
      }
    }).finally(() => setLoading(false));
  }, []);

  const frameworks = useMemo(
    () => Array.from(new Set(scans.map((s) => s.framework).filter(Boolean))).sort(),
    [scans]
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const rows = scans
      .filter((s) => {
        if (decisionFilter === "ALL") return true;
        if (decisionFilter === "PENDING") return !s.final_decision;
        return s.final_decision === decisionFilter;
      })
      .filter((s) => frameworkFilter === "ALL" || s.framework === frameworkFilter)
      .filter((s) => {
        if (!q) return true;
        const device = devices[s.device_id];
        return (
          s.id.toLowerCase().includes(q) ||
          s.framework?.toLowerCase().includes(q) ||
          device?.hostname?.toLowerCase().includes(q) ||
          device?.management_address?.toLowerCase().includes(q)
        );
      });
    if (sortMode === "priority") {
      // Stable sort: BLOCK, then REVIEW, then PENDING, then PASS last —
      // the point of a validation queue is to surface what needs a human
      // first, not to make them scroll past a wall of PASS rows to find
      // the one BLOCK. Ties keep their original (most-recent-first) order.
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
    PASS: scans.filter((s) => s.final_decision === "PASS").length,
    REVIEW: scans.filter((s) => s.final_decision === "REVIEW").length,
    BLOCK: scans.filter((s) => s.final_decision === "BLOCK").length,
    PENDING: scans.filter((s) => !s.final_decision).length,
  };

  const statCardCls = (active: boolean) =>
    `text-left transition-all ${active ? "ring-2 ring-cyan-600 rounded-xl" : "hover:opacity-80"}`;

  return (
    <div className="pb-10">
      <PageHeader
        title="Validation"
        subtitle="Correlated decision per scan — OPA (deterministic policy) × Batfish (network behavior) × Risk, per the correlation precedence rules. The LLM never determines this outcome."
      />

      <div className="px-8 grid grid-cols-2 md:grid-cols-4 gap-4 mb-2">
        <button className={statCardCls(decisionFilter === "PASS")} onClick={() => setDecisionFilter(decisionFilter === "PASS" ? "ALL" : "PASS")}>
          <StatCard label="Passed" value={counts.PASS} tone="good" />
        </button>
        <button className={statCardCls(decisionFilter === "REVIEW")} onClick={() => setDecisionFilter(decisionFilter === "REVIEW" ? "ALL" : "REVIEW")}>
          <StatCard label="Needs Review" value={counts.REVIEW} tone="medium" />
        </button>
        <button className={statCardCls(decisionFilter === "BLOCK")} onClick={() => setDecisionFilter(decisionFilter === "BLOCK" ? "ALL" : "BLOCK")}>
          <StatCard label="Blocked" value={counts.BLOCK} tone="critical" />
        </button>
        <button className={statCardCls(decisionFilter === "PENDING")} onClick={() => setDecisionFilter(decisionFilter === "PENDING" ? "ALL" : "PENDING")}>
          <StatCard label="Pending" value={counts.PENDING} tone="default" />
        </button>
      </div>
      <div className="px-8 mb-6 text-xs text-slate-500">
        Click a card to filter by that decision · showing the {scans.length} most recent scans
      </div>

      <div className="px-8 pb-8 space-y-4">
        <div className="flex gap-3 items-center flex-wrap justify-between">
          <div className="flex gap-3 items-center flex-wrap">
            <select className="select text-sm" value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
              {DECISION_OPTIONS.map((d) => (
                <option key={d} value={d}>{d === "ALL" ? "All decisions" : d === "PENDING" ? "Pending" : d}</option>
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
              placeholder="Search by device, scan ID, or framework…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <span className="text-xs text-slate-500">{filtered.length} of {scans.length} scans</span>
        </div>

        {filtered.length === 0 && <EmptyState message="No scans match this filter." />}

        {filtered.map((s) => {
          const device = devices[s.device_id];
          const needsRemediation = s.final_decision === "BLOCK" || s.final_decision === "REVIEW";
          return (
            <Link
              key={s.id}
              to={needsRemediation ? `/scans/${s.id}#remediation` : `/scans/${s.id}`}
              className="card block p-5 hover:border-cyan-700/60 hover:shadow-cyan-900/10 transition-all"
            >
              <div className="flex items-start justify-between gap-6 flex-wrap mb-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="font-semibold text-lg text-slate-200">
                      {device?.hostname || device?.management_address || `Device ${s.device_id.slice(0, 8)}`}
                    </span>
                    <DecisionPill decision={s.final_decision} />
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
                <div className="shrink-0 text-right">
                  <div className="text-4xl font-bold text-slate-100">
                    {s.compliance_score != null ? `${s.compliance_score}%` : "—"}
                  </div>
                  <div className="text-xs uppercase tracking-wide text-slate-500">compliance</div>
                </div>
              </div>

              {/* Decision + compliance score above already tell you pass/fail
                  at a glance -- this strip used to repeat both as a second
                  pair of "Normalized" / "Decision" chips directly above the
                  pipeline dots that show the same two values a third time.
                  Cut straight to the pipeline; it's the one place that adds
                  information (OPA/Batfish/Risk), not just re-states it. */}
              <DecisionPipeline size="sm" steps={buildSteps(s)} />

              {needsRemediation && (
                <div className="flex items-center justify-between gap-3 mt-4 pt-3 border-t border-soc-border">
                  <span className="text-xs text-amber-400">
                    AI remediation is available for this scan's failing controls — review the synthesized
                    commands, create a Change Request, then approve it there before it can deploy
                    (human approval is always required; nothing auto-deploys on its own).
                  </span>
                  <span className="btn-secondary text-xs whitespace-nowrap">Open Remediation →</span>
                </div>
              )}

              {s.final_reason && (
                <div className="text-sm text-slate-400 mt-4 pt-3 border-t border-soc-border">{s.final_reason}</div>
              )}
            </Link>
          );
        })}
      </div>
    </div>
  );
}