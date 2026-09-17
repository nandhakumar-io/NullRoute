import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { endpoints, Finding, Device, ScanDetail } from "../api";
import { PageHeader, Loading, EmptyState, SeverityBadge, ResultBadge } from "../components/ui";
import { WhyPanel, TraceabilityChain, WhyRow, TraceStage } from "../components/WhyPanel";

/** Distinct badge so reviewers know, at a glance, whether the LLM touched
 * this finding's evidence at all. 'parser' rows never went near the AI
 * pipeline; 'ai' rows carry a confidence score from the RAG/LLM
 * interpretation and are the ones worth double-checking. */
function ProvenanceBadge({ source, confidence }: { source?: string | null; confidence?: number | null }) {
  if (source === "ai") {
    return (
      <span className="badge badge-ai-interpreted">
        AI Interpreted{confidence != null ? ` · ${Math.round(confidence * 100)}% confidence` : ""}
      </span>
    );
  }
  if (source === "parser") {
    return <span className="badge badge-deterministic">Deterministic</span>;
  }
  return null;
}

/**
 * Finding Detail (Phase 1 spec, sections 6-8).
 *
 * Reuses the existing GET /api/findings/{id} endpoint, plus the existing
 * scan and device endpoints to resolve the device this finding belongs to
 * (findings only carry scan_id — no new backend fields are introduced).
 */
export default function FindingDetail() {
  const { findingId } = useParams();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [device, setDevice] = useState<Device | null>(null);
  const [error, setError] = useState(false);
  const [traceOpen, setTraceOpen] = useState(false);
  const [cliRemediation, setCliRemediation] = useState<any | null>(null);
  const [cliLoading, setCliLoading] = useState(false);

  useEffect(() => {
    if (!findingId) return;
    setFinding(null);
    setScan(null);
    setDevice(null);
    setError(false);
    setCliRemediation(null);
    endpoints
      .finding(findingId)
      .then((r) => setFinding(r.data))
      .catch(() => setError(true));
  }, [findingId]);

  useEffect(() => {
    if (!finding?.scan_id) return;
    endpoints
      .scan(finding.scan_id)
      .then((r) => {
        setScan(r.data);
        if (r.data.device_id) {
          endpoints.device(r.data.device_id).then((d) => setDevice(d.data)).catch(() => {});
        }
      })
      .catch(() => {});
  }, [finding?.scan_id]);

  // Vendor-specific CLI remediation, when a validated template (or AI
  // synthesis) exists for this control. Previously this page only ever
  // showed the finding's prose `remediation` text -- the "how to" -- and
  // never called the same scan-level remediation endpoint ScanDetail uses
  // to surface the actual command(s) to run, so a per-finding deep link
  // (e.g. from Findings/Alerts) always looked less complete than opening
  // the parent scan.
  useEffect(() => {
    if (!finding || finding.result !== "FAIL" || !finding.scan_id) return;
    setCliLoading(true);
    endpoints
      .aiRemediation(finding.scan_id)
      .then((r) => setCliRemediation(r.data))
      .catch(() => setCliRemediation(null))
      .finally(() => setCliLoading(false));
  }, [finding?.id, finding?.scan_id, finding?.result]);

  if (error) return <EmptyState message="Finding not found." />;
  if (!finding) return <Loading />;

  const resultTone =
    finding.result === "PASS"
      ? "pass"
      : finding.result === "FAIL"
      ? "fail"
      : finding.result === "UNVERIFIED"
      ? "unknown"
      : "review";

  const stages: TraceStage[] = [
    { label: "Raw Configuration Line", value: finding.evidence_line, tone: "neutral" },
    ...(finding.source === "ai"
      ? [{
          label: "AI Confidence",
          value: finding.confidence != null ? `${Math.round(finding.confidence * 100)}%` : "—",
          tone: (finding.confidence != null && finding.confidence < 0.75 ? "review" : "neutral") as any,
        }]
      : []),
    { label: "Normalized Parameter", value: `${finding.parameter} = ${finding.actual_value ?? "—"}`, tone: "neutral" },
    { label: "Security Control", value: `${finding.control_id} — ${finding.title}`, tone: "neutral" },
    { label: "OPA Policy (deterministic, authoritative)", value: finding.policy_version || "—", tone: "neutral" },
    { label: "OPA Result", value: finding.presentation_result || finding.result, tone: resultTone as any },
  ];

  const whyRows: WhyRow[] = [
    { label: "Raw evidence", value: finding.evidence_line, mono: true },
    { label: "Normalized value", value: `${finding.parameter} = ${finding.actual_value ?? "—"}`, mono: true },
    { label: "Expected value", value: finding.expected_value, mono: true },
    { label: "Control", value: `${finding.control_id} (${finding.framework})` },
    { label: "OPA policy version", value: finding.policy_version || "—", mono: true },
    {
      label: "Decision",
      value: finding.presentation_result || finding.result,
      tone: resultTone as any,
    },
    { label: "OPA reason", value: finding.reason || "No reason string returned." },
  ];

  return (
    <div>
      <PageHeader
        title={`Finding ${finding.id.slice(0, 8)}`}
        subtitle={finding.title}
        action={
          <div className="flex gap-2">
            {finding.scan_id && (
              <Link className="btn-secondary text-sm" to={`/scans/${finding.scan_id}`}>
                View Scan
              </Link>
            )}
            {device && (
              <Link className="btn-secondary text-sm" to={`/devices/${device.id}`}>
                View Device
              </Link>
            )}
          </div>
        }
      />

      <div className="px-8 pb-8 space-y-6">
        {/* Header facts */}
        <div className="card grid grid-cols-2 md:grid-cols-4 gap-4 p-4 text-sm">
          <Fact label="Finding ID" value={finding.id} mono />
          <Fact
            label="Device"
            value={
              device ? (
                <Link className="text-cyan-400 hover:underline" to={`/devices/${device.id}`}>
                  {device.hostname || device.name || device.management_address || device.id.slice(0, 8)}
                </Link>
              ) : (
                "—"
              )
            }
          />
          <Fact label="Vendor" value={finding.vendor || device?.vendor || "—"} />
          <Fact label="Framework" value={finding.framework} />
          <Fact label="Control" value={finding.control_id} mono />
          <Fact label="Severity" value={<SeverityBadge severity={finding.severity} />} />
          <Fact label="Status" value={<ResultBadge result={finding.presentation_result || finding.result} />} />
          <Fact label="Scan" value={finding.scan_id ? finding.scan_id.slice(0, 8) : "—"} mono />
          {finding.source && (
            <Fact label="Evidence Source" value={<ProvenanceBadge source={finding.source} confidence={finding.confidence} />} />
          )}
        </div>

        {finding.result === "UNVERIFIED" && (
          <div className="bg-amber-950/30 border border-amber-800/50 rounded px-4 py-3 flex items-center justify-between gap-3">
            <span className="text-amber-300 text-sm">
              This value came from AI/RAG normalization and hasn't been human-approved yet — it cannot be
              certified PASS or FAIL until reviewed.
            </span>
            <Link className="btn-secondary text-xs whitespace-nowrap" to="/training">
              Review in Training Center
            </Link>
          </div>
        )}

        {/* Evidence Trace: the trust-boundary view. Explicit, reviewer-facing
            proof of exactly which stages were touched by AI (purple/gold
            badge) vs a deterministic engine (blue/gray badge), and nothing
            is asserted about compliance here — that's OPA's row alone. */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">Traceability</h3>
            <button
              type="button"
              onClick={() => setTraceOpen((o) => !o)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-soc-panel border border-soc-border text-slate-300 hover:bg-slate-800/60"
            >
              <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-cyan-950 text-cyan-400 text-[10px] font-bold border border-cyan-800">
                ⤷
              </span>
              {traceOpen ? "Hide Evidence Trace" : "Evidence Trace"}
            </button>
          </div>
          {traceOpen && (
            <div className="card p-4 space-y-3">
              <div className="flex items-center gap-2 flex-wrap text-xs text-slate-500">
                <span>Raw line</span>
                <span>➔</span>
                {finding.source === "ai" ? (
                  <span className="badge badge-ai-interpreted">
                    AI Confidence: {finding.confidence != null ? `${Math.round(finding.confidence * 100)}%` : "—"}
                  </span>
                ) : (
                  <span className="badge badge-deterministic">Deterministic parser</span>
                )}
                <span>➔</span>
                <span>Normalized parameter</span>
                <span>➔</span>
                <span className="badge badge-na">OPA (deterministic, authoritative)</span>
              </div>
              <div className="max-w-xl">
                <TraceabilityChain stages={stages} />
              </div>
              <p className="text-[11px] text-slate-500">
                {finding.source === "ai"
                  ? "This evidence line's meaning was interpreted by the AI/RAG pipeline, not matched by the deterministic vendor parser. The compliance result above still comes only from OPA evaluating the normalized value — AI never sets PASS/FAIL."
                  : "This evidence line was matched by the deterministic vendor parser — no AI/LLM was involved in producing this mapping."}
              </p>
            </div>
          )}
        </div>

        {/* Why? */}
        <div>
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-3">Explanation</h3>
          <WhyPanel title="Why did this control fail?" rows={whyRows} defaultOpen />
        </div>

        {(() => {
          const r = cliRemediation?.remediations?.find((x: any) => x.finding_id === finding.id);
          const hasCli = !!r?.cli_steps?.length;
          const guidance = r?.guidance || finding.remediation;
          if (!hasCli && !guidance && !cliLoading) return null;
          const isTemplate = !!r?.reference;
          return (
            <div className="card p-4">
              <div className="text-xs font-semibold text-slate-500 uppercase mb-1">Remediation</div>
              {cliLoading && !r && (
                <div className="text-xs text-slate-500">Checking for a validated CLI template…</div>
              )}
              {hasCli && (
                <div className="mb-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-sm font-semibold text-emerald-500">
                      {isTemplate ? "Validated CLI Remediation" : "AI Generated CLI Remediation"}
                    </div>
                    {r.requires_site_values && (
                      <span className="badge badge-medium text-[10px]">has placeholders</span>
                    )}
                  </div>
                  {r.description && <div className="text-sm text-slate-400 mb-2">{r.description}</div>}
                  <div className="space-y-0.5">
                    {r.cli_steps.map((step: string | Record<string, string>, idx: number) => {
                      const txt = typeof step === "string" ? step : step ? Object.keys(step)[0] : String(step);
                      return (
                        <div key={idx} className="font-mono text-sm text-emerald-300 whitespace-pre-wrap">
                          {txt}
                        </div>
                      );
                    })}
                  </div>
                  {r.save_commands?.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-slate-800/60 space-y-0.5">
                      {r.save_commands.map((c: string, idx: number) => (
                        <div key={idx} className="font-mono text-sm text-cyan-300/80 whitespace-pre-wrap">
                          # {c}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {guidance && (
                <div className={`text-slate-300 text-sm whitespace-pre-wrap ${hasCli ? "border-t border-soc-border pt-3" : ""}`}>
                  {guidance}
                </div>
              )}
              {r?.note && <div className="text-[11px] text-amber-500/80 mt-2">{r.note}</div>}
            </div>
          );
        })()}
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