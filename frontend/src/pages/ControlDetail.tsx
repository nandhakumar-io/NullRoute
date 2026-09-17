import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { endpoints, UnifiedControl, VendorConfigPattern } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";
import { WhyPanel, TraceabilityChain, WhyRow, TraceStage } from "../components/WhyPanel";

const STATUS_TONE: Record<string, string> = {
  pending_review: "bg-amber-500/20 text-amber-400",
  approved: "bg-emerald-500/20 text-emerald-400",
};

/**
 * Control Detail (Phase 2 spec, section 8).
 *
 * Reuses the existing GET /api/controls/{id} (which already returns
 * framework_mappings + config_concepts) and GET /api/controls/{id}/patterns
 * — no new backend endpoints needed. Gives the Unified Control Library its
 * own traceability chain, mirroring Finding Detail: source text -> config
 * concepts / vendor patterns -> the control itself -> framework mappings ->
 * compiled/approval status.
 */
export default function ControlDetail() {
  const { controlId } = useParams();
  const [control, setControl] = useState<UnifiedControl | null>(null);
  const [patterns, setPatterns] = useState<VendorConfigPattern[] | null>(null);
  const [error, setError] = useState(false);
  const [compiling, setCompiling] = useState(false);
  const [compileMsg, setCompileMsg] = useState<string | null>(null);

  function load() {
    if (!controlId) return;
    setError(false);
    endpoints
      .control(controlId)
      .then((r) => setControl(r.data))
      .catch(() => setError(true));
    endpoints
      .controlPatterns(controlId)
      .then((r) => setPatterns(r.data.patterns))
      .catch(() => setPatterns([]));
  }

  useEffect(() => {
    setControl(null);
    setPatterns(null);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [controlId]);

  async function compile() {
    if (!controlId) return;
    setCompiling(true);
    setCompileMsg(null);
    try {
      const r = await endpoints.compileControl(controlId);
      const compiled = (r.data as any)?.compiled ?? [];
      setCompileMsg(compiled.length ? `Compiled for ${compiled.map((c: any) => c.vendor).join(", ")}` : "Compiled");
    } catch (err: any) {
      setCompileMsg(err?.response?.data?.detail || "Compilation failed");
    } finally {
      setCompiling(false);
    }
  }

  if (error) return <EmptyState message="Control not found." />;
  if (!control) return <Loading />;

  const patternsByVendor = (patterns || []).reduce<Record<string, VendorConfigPattern[]>>((acc, p) => {
    (acc[p.vendor] = acc[p.vendor] || []).push(p);
    return acc;
  }, {});

  const stages: TraceStage[] = [
    { label: "Source Text", value: control.source_text || control.source_document || "—", tone: "neutral" },
    {
      label: "Config Concepts",
      value:
        control.config_concepts && control.config_concepts.length > 0
          ? control.config_concepts.map((c) => c.concept_name).join(", ")
          : "No concepts tagged yet",
      tone: control.config_concepts && control.config_concepts.length > 0 ? "neutral" : "unknown",
    },
    {
      label: "Vendor Patterns",
      value:
        patterns && patterns.length > 0
          ? Object.entries(patternsByVendor)
              .map(([v, ps]) => `${v}: ${ps.length}`)
              .join(", ")
          : "No patterns tagged yet",
      tone: patterns && patterns.length > 0 ? "neutral" : "unknown",
    },
    {
      label: "Unified Control",
      value: `${control.name}${control.domain ? ` (${control.domain})` : ""}`,
      tone: control.status === "approved" ? "pass" : "review",
    },
    {
      label: "Framework Mappings",
      value:
        control.framework_mappings && control.framework_mappings.length > 0
          ? control.framework_mappings.map((m) => `${m.framework}: ${m.external_id}`).join(", ")
          : "No framework mappings yet",
      tone: control.framework_mappings && control.framework_mappings.length > 0 ? "neutral" : "unknown",
    },
  ];

  const whyRows: WhyRow[] = [
    { label: "Source document", value: control.source_document || "—" },
    { label: "Source text", value: control.source_text || "—", mono: true },
    { label: "Normalized description", value: control.normalized_description || "—" },
    { label: "Domain", value: control.domain || "—" },
    { label: "Created by", value: control.created_by || "—" },
    {
      label: "Status",
      value: control.status.replace(/_/g, " "),
      tone: control.status === "approved" ? "pass" : "review",
    },
    { label: "Approved by", value: control.approved_by || "—" },
    {
      label: "Approved at",
      value: control.approved_at ? new Date(control.approved_at).toLocaleString() : "—",
    },
  ];

  return (
    <div>
      <PageHeader
        title={control.name}
        subtitle={control.objective || "Unified control"}
        action={
          <div className="flex gap-2">
            <Link className="btn-secondary text-sm" to="/control-library">
              Back to Library
            </Link>
            {control.status === "approved" && (
              <button onClick={compile} disabled={compiling} className="btn-primary text-sm">
                {compiling ? "Compiling…" : "Compile Policy"}
              </button>
            )}
          </div>
        }
      />

      <div className="px-8 pb-8 space-y-6">
        <div className="card grid grid-cols-2 md:grid-cols-4 gap-4 p-4 text-sm">
          <Fact label="Control ID" value={control.id} mono />
          <Fact label="Domain" value={control.domain || "—"} />
          <Fact
            label="Status"
            value={
              <span className={`px-2 py-0.5 rounded text-xs ${STATUS_TONE[control.status] || "bg-slate-500/20 text-slate-300"}`}>
                {control.status.replace(/_/g, " ")}
              </span>
            }
          />
          <Fact label="Framework Mappings" value={control.framework_mappings?.length ?? 0} />
        </div>

        {compileMsg && (
          <div className="bg-slate-800/50 border border-soc-border rounded px-4 py-3 text-sm text-slate-300">
            {compileMsg}
          </div>
        )}

        <div>
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-3">Traceability</h3>
          <div className="max-w-xl">
            <TraceabilityChain stages={stages} />
          </div>
        </div>

        <div>
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-3">Explanation</h3>
          <WhyPanel title="Why this control?" rows={whyRows} defaultOpen />
        </div>

        <div className="card p-4">
          <div className="text-xs font-semibold text-slate-500 uppercase mb-3">Vendor Config Patterns</div>
          {!patterns ? (
            <Loading />
          ) : patterns.length === 0 ? (
            <div className="text-sm text-slate-500">No patterns tagged yet for this control.</div>
          ) : (
            <div className="space-y-1.5">
              {patterns.map((p) => (
                <div key={p.id} className="text-xs font-mono flex items-center gap-3 bg-black/30 rounded px-2 py-1.5">
                  <span className="text-cyan-400 shrink-0">{p.vendor}</span>
                  <span className="text-emerald-300 truncate">{p.pattern}</span>
                  {p.example_snippet && <span className="text-slate-500 truncate">// {p.example_snippet}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Fact({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs font-semibold text-slate-500 uppercase mb-1">{label}</div>
      <div className={`text-slate-200 ${mono ? "font-mono text-xs break-all" : "text-sm"}`}>{value}</div>
    </div>
  );
}