import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { endpoints, Scan } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

const DECISION_OPTIONS = ["ALL", "PASS", "REVIEW", "BLOCK"];

function DecisionPill({ decision }: { decision: string | null | undefined }) {
  const cls =
    decision === "PASS" ? "badge-pass" : decision === "BLOCK" ? "badge-fail" : "badge-medium";
  return <span className={`badge ${cls}`}>{decision || "PENDING"}</span>;
}

function EnginePill({ label, value, tone }: { label: string; value: string | null | undefined; tone: string }) {
  return (
    <div>
      <div className="text-xs text-slate-500">{label}</div>
      <span className={`badge ${tone}`}>{(value || "—").replace(/_/g, " ")}</span>
    </div>
  );
}

function opaTone(v?: string | null) {
  if (v === "PASS") return "badge-pass";
  if (v === "BLOCK" || v === "FAIL") return "badge-fail";
  if (!v) return "badge-na";
  return "badge-medium";
}

function batfishTone(v?: string | null) {
  if (v === "BATFISH_PASS") return "badge-pass";
  if (v === "BATFISH_FAIL") return "badge-fail";
  if (!v || v === "NOT_INTEGRATED") return "badge-na";
  return "badge-medium";
}

function riskTone(v?: string | null) {
  if (v === "LOW") return "badge-pass";
  if (v === "CRITICAL" || v === "HIGH") return "badge-fail";
  if (!v) return "badge-na";
  return "badge-medium";
}

export default function Validation() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [decisionFilter, setDecisionFilter] = useState("ALL");

  useEffect(() => {
    endpoints
      .scans()
      .then((r) => setScans(r.data))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Loading />;

  const filtered = scans.filter((s) => decisionFilter === "ALL" || s.final_decision === decisionFilter);

  return (
    <div>
      <PageHeader
        title="Validation"
        subtitle="Correlated decision per scan — OPA (deterministic policy) × Batfish (network behavior) × Risk, per the correlation precedence rules. The LLM never determines this outcome."
      />
      <div className="px-8 pb-8 space-y-4">
        <div className="flex gap-3 items-center flex-wrap">
          <select className="select" value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
            {DECISION_OPTIONS.map((d) => (
              <option key={d} value={d}>
                {d === "ALL" ? "All decisions" : d}
              </option>
            ))}
          </select>
          <span className="text-xs text-slate-500">
            {filtered.length} of {scans.length} scans
          </span>
        </div>

        {filtered.length === 0 && <EmptyState message="No scans to validate yet." />}

        {filtered.map((s) => (
          <Link key={s.id} to={`/scans/${s.id}`} className="card block hover:border-cyan-800/60 transition-colors">
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs text-slate-400">{s.id}</span>
                  <DecisionPill decision={s.final_decision} />
                </div>
                <div className="text-xs text-slate-500 mt-1">{s.framework} · {new Date(s.created_at).toLocaleString()}</div>
                {s.final_reason && <div className="text-xs text-slate-400 mt-1">{s.final_reason}</div>}
              </div>
              <div className="flex gap-6">
                <EnginePill label="OPA" value={s.opa_decision} tone={opaTone(s.opa_decision)} />
                <EnginePill label="Batfish" value={s.batfish_status} tone={batfishTone(s.batfish_status)} />
                <EnginePill label="Risk" value={s.risk_level} tone={riskTone(s.risk_level)} />
              </div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
