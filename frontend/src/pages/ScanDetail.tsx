import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { endpoints, ScanDetail as ScanDetailType, EvidenceRecord, ScanAIAnalysis, DeviceVulnerabilityMatch } from "../api";
import {
  PageHeader, Loading, ScoreRing, SeverityBadge, ResultBadge, StatusBadge, EmptyState,
  DecisionPipeline, opaTone, batfishTone, riskTone, decisionTone, PipelineStepData,
} from "../components/ui";
import { WhyPanel } from "../components/WhyPanel";

const STAGES = ["uploaded", "parsed", "normalized", "opa_evaluating", "batfish_evaluating", "correlating", "completed", "ai_ready"];

const BATFISH_TONE: Record<string, string> = {
  BATFISH_PASS: "badge-pass",
  BATFISH_FAIL: "badge-fail",
  BATFISH_UNSUPPORTED: "badge-medium",
  BATFISH_UNAVAILABLE: "badge-na",
  BATFISH_ERROR: "badge-fail",
  NOT_INTEGRATED: "badge-na",
};

const FABRIC_TONE: Record<string, string> = {
  ANCHORED: "badge-pass",
  FABRIC_UNAVAILABLE: "badge-fail",
  NOT_ANCHORED: "badge-na",
};

const AI_DECISION_TONE: Record<string, string> = {
  KNOWN_CANDIDATE: "badge-pass",
  REQUIRES_REVIEW: "badge-medium",
  UNKNOWN: "badge-na",
};

export default function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [creatingCr, setCreatingCr] = useState(false);
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRecord | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<ScanAIAnalysis | null>(null);
  const [remediations, setRemediations] = useState<any>(null);
  const [rerunning, setRerunning] = useState(false);

  const [currentSnapshot, setCurrentSnapshot] = useState<any>(null);
  const [deviceHasBaseline, setDeviceHasBaseline] = useState(false);
  const [approving, setApproving] = useState(false);

  const [activeTab, setActiveTab] = useState<"overview" | "matrix" | "vulns">("overview");
  const [complianceMatrix, setComplianceMatrix] = useState<Array<Record<string, any>> | null>(null);
  const [vulnMatches, setVulnMatches] = useState<DeviceVulnerabilityMatch[] | null>(null);
  const [correlating, setCorrelating] = useState(false);

  useEffect(() => {
    let isActive = true;
    let timeoutId: number;

    async function tick() {
      if (!isActive || !scanId) return;
      try {
        const scanRes = await endpoints.scan(scanId);
        if (!isActive) return;
        setScan(scanRes.data);

        const pipelineDone = ["completed", "review", "blocked"].includes(scanRes.data.status);

        const snaps = await endpoints.deviceSnapshots(scanRes.data.device_id);
        if (isActive) {
          setCurrentSnapshot(snaps.data.snapshots.find((s: any) => s.scan_id === scanId));
          setDeviceHasBaseline(snaps.data.snapshots.some((s: any) => s.is_approved_baseline));
        }

        const ev = await endpoints.evidenceList(scanId);
        if (isActive) setEvidence(ev.data[0] ?? null);

        const ai = await endpoints.aiAnalysis(scanId);
        if (isActive) setAiAnalysis(ai.data);

        if (pipelineDone) {
          try {
            const rem = await endpoints.aiRemediation(scanId);
            if (isActive) setRemediations(rem.data);
          } catch (e) {
            if (isActive) setRemediations(null);
          }
        } else {
          timeoutId = window.setTimeout(tick, 3000);
        }
      } catch (err) {
        if (isActive) timeoutId = window.setTimeout(tick, 3000);
      }
    }

    tick();
    return () => {
      isActive = false;
      window.clearTimeout(timeoutId);
    };
  }, [scanId]);

  useEffect(() => {
    if (!scanId) return;
    if (activeTab === "matrix" && complianceMatrix === null) {
      endpoints.reportJson(scanId).then((r) => setComplianceMatrix(r.data.compliance_matrix || []));
    }
    if (activeTab === "vulns" && scan?.device_id) {
      endpoints.deviceVulns(scan.device_id).then((r) => setVulnMatches(r.data.matches));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, scanId, scan?.device_id]);

  if (!scan) return <Loading />;

  const pipelineCompleted = ["completed", "review", "blocked"].includes(scan.status);
  const aiReady = aiAnalysis !== null && aiAnalysis.count >= 0 && pipelineCompleted;
  // If pipeline is done, wait for AI analysis before fully lighting up 'completed'
  let currentStageIdx = -1;
  if (scan.status !== "failed") {
    const pIdx = STAGES.indexOf(pipelineCompleted ? "completed" : scan.status);
    currentStageIdx = aiReady ? pIdx + 1 : pIdx;
  }

  async function handleCreateChangeRequest() {
    if (!scan || !remediations?.remediations?.length) return;
    const withCli = remediations.remediations.filter((r: any) => r.cli_steps?.length);
    if (withCli.length === 0) return;
    setCreatingCr(true);
    try {
      const lines: string[] = [];
      for (const r of withCli) {
        lines.push(`! ${r.control_id}: ${r.title}`);
        for (const step of r.cli_steps) {
          lines.push(typeof step === "string" ? step : Object.keys(step)[0]);
        }
        if (r.save_commands?.length) lines.push(...r.save_commands);
        lines.push("");
      }
      await endpoints.createChangeRequest(scan.device_id, lines.join("\n"));
      navigate("/review-queue");
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Failed to create Change Request");
    } finally {
      setCreatingCr(false);
    }
  }

  async function handleRerun() {
    if (!scanId) return;
    setRerunning(true);
    try {
      await endpoints.rerunScan(scanId);
      window.location.reload();
    } finally {
      setRerunning(false);
    }
  }



  async function runVulnCorrelation() {
    if (!scan?.device_id) return;
    setCorrelating(true);
    try {
      await endpoints.correlateDeviceVulns(scan.device_id);
      const r = await endpoints.deviceVulns(scan.device_id);
      setVulnMatches(r.data.matches);
    } finally {
      setCorrelating(false);
    }
  }

  async function handleApproveBaseline() {
    if (!scan || !currentSnapshot) return;
    const reason = window.prompt("Reason for approving this snapshot as the golden baseline (optional):") || undefined;
    setApproving(true);
    try {
      await endpoints.approveBaseline(scan.device_id, currentSnapshot.snapshot_id, reason);
      window.location.reload();
    } finally {
      setApproving(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Scan Detail"
        subtitle={`Scan ${scan.id}`}
        action={
          <button onClick={handleRerun} disabled={rerunning} className="btn-secondary text-base">
            {rerunning ? "Re-running…" : "Re-run evaluation"}
          </button>
        }
      />

      {currentSnapshot && !deviceHasBaseline && !currentSnapshot.is_approved_baseline && scan.status === "completed" && (
        <div className="mx-8 mb-6 bg-cyan-950/40 border border-cyan-800 rounded-xl px-5 py-4 flex items-center justify-between">
          <div>
            <div className="text-cyan-300 font-semibold mb-1">Golden Baseline Required</div>
            <div className="text-base text-slate-400">
              This device currently has no authoritative configuration signature.
              Setting this configuration as the baseline enables automatic drift detection and real-time alerts.
            </div>
          </div>
          <button
            onClick={handleApproveBaseline}
            disabled={approving}
            className="btn-primary text-base whitespace-nowrap ml-4 shrink-0"
          >
            {approving ? "Approving..." : "Set as Golden Baseline"}
          </button>
        </div>
      )}

      {currentSnapshot && currentSnapshot.is_approved_baseline && (
        <div className="mx-8 mb-6 bg-emerald-950/30 border border-emerald-900 rounded-xl px-5 py-3">
          <div className="text-emerald-400 font-semibold text-base">Valid Golden Baseline</div>
          <div className="text-base text-slate-400">This configuration represents the authoritative baseline for drift monitoring.</div>
        </div>
      )}

      <div className="px-8 pb-4 border-b border-soc-border mb-6 flex gap-6">
        <button
          onClick={() => setActiveTab("overview")}
          className={`pb-2 font-medium ${activeTab === "overview" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Overview
        </button>
        <button
          onClick={() => setActiveTab("matrix")}
          className={`pb-2 font-medium ${activeTab === "matrix" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Compliance Matrix
        </button>
        <button
          onClick={() => setActiveTab("vulns")}
          className={`pb-2 font-medium ${activeTab === "vulns" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Vulnerabilities
        </button>
      </div>

      {activeTab === "matrix" && (
        <div className="px-8 pb-8">
          {!complianceMatrix ? (
            <Loading />
          ) : complianceMatrix.length === 0 ? (
            <EmptyState message="No compliance matrix data. Map findings to Unified Controls with framework mappings to populate this view." />
          ) : (
            <div className="overflow-hidden rounded-lg border border-soc-border">
              <table className="w-full text-left text-base text-slate-400">
                <thead className="bg-soc-panel border-b border-soc-border uppercase text-base">
                  <tr>
                    <th className="px-4 py-3">Control</th>
                    <th className="px-4 py-3">Result</th>
                    <th className="px-4 py-3">NIST-800-53</th>
                    <th className="px-4 py-3">CIS</th>
                    <th className="px-4 py-3">ISO-27001</th>
                    <th className="px-4 py-3">DISA-STIG</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border">
                  {complianceMatrix.map((row, i) => (
                    <tr key={i} className="hover:bg-soc-panel">
                      <td className="px-4 py-3 font-mono text-base text-slate-300">{row.control_id}</td>
                      <td className="px-4 py-3"><ResultBadge result={row.result} /></td>
                      <td className="px-4 py-3 font-mono text-base">{row["NIST-800-53"]}</td>
                      <td className="px-4 py-3 font-mono text-base">{row["CIS"]}</td>
                      <td className="px-4 py-3 font-mono text-base">{row["ISO-27001"]}</td>
                      <td className="px-4 py-3 font-mono text-base">{row["DISA-STIG"]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === "vulns" && (
        <div className="px-8 pb-8">
          <div className="flex justify-end mb-3">
            <button onClick={runVulnCorrelation} disabled={correlating} className="btn-secondary text-base">
              {correlating ? "Correlating…" : "Run Correlation"}
            </button>
          </div>
          {!vulnMatches ? (
            <Loading />
          ) : vulnMatches.length === 0 ? (
            <EmptyState message="No vulnerability matches for this device yet. Run correlation to check against the CVE catalog." />
          ) : (
            <div className="space-y-2">
              {vulnMatches.map((m) => (
                <div key={m.id} className="card">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-cyan-400">{m.cve_id}</span>
                    {m.vulnerability?.severity && <SeverityBadge severity={m.vulnerability.severity} />}
                    {m.vulnerability?.kev_flag && (
                      <span className="px-2 py-0.5 rounded text-base bg-red-500/20 text-red-400">KEV</span>
                    )}
                    <span className="px-2 py-0.5 rounded text-base bg-slate-500/20 text-slate-300">{m.status.replace(/_/g, " ")}</span>
                  </div>
                  <div className="text-base text-slate-500 mt-1">
                    matched via {m.matched_via}
                    {m.risk_priority_score != null && ` · risk priority: ${m.risk_priority_score.toFixed(1)}`}
                    {m.linked_control_id && ` · linked control: ${m.linked_control_id}`}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "overview" && (
        <>
          <div className="px-8 grid grid-cols-1 lg:grid-cols-5 gap-4 mb-6">
            <div className="card lg:col-span-5">
              <div className="font-semibold text-slate-200 mb-1">Decision Pipeline</div>
              <div className="text-base text-slate-500 mb-5">How this scan's outcome was derived — deterministic, evidence-backed, never LLM-decided.</div>
              <DecisionPipeline
                size="lg"
                steps={[
                  { label: "Normalized", value: scan.baseline_json ? "Modeled" : "Pending", tone: scan.baseline_json ? "pass" : "pending", sublabel: "Vendor config -> common security model" },
                  { label: "OPA", value: (scan.opa_decision || "PENDING").replace(/_/g, " "), tone: opaTone(scan.opa_decision), sublabel: scan.opa_policy_version ? `policy v${scan.opa_policy_version}` : undefined },
                  { label: "Batfish", value: (scan.batfish_status || "N/A").replace(/_/g, " "), tone: batfishTone(scan.batfish_status), sublabel: "Network behavior verification" },
                  { label: "Risk", value: scan.risk_level || "N/A", tone: riskTone(scan.risk_level), sublabel: scan.risk_score != null ? `score ${scan.risk_score}` : undefined },
                  { label: "Decision", value: scan.final_decision || "PENDING", tone: decisionTone(scan.final_decision), sublabel: scan.final_reason || undefined },
                  { label: "Evidence", value: evidence ? (evidence.fabric_status || "RECORDED").replace(/_/g, " ") : "PENDING", tone: evidence ? (evidence.fabric_status === "ANCHORED" ? "pass" : "warn") : "pending", sublabel: evidence?.evidence_hash ? `hash ${evidence.evidence_hash.slice(0, 12)}…` : undefined },
                ] as PipelineStepData[]}
              />
            </div>
          </div>

          <div className="px-8 grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
            <div className="card lg:col-span-2">
              <div className="font-semibold text-slate-200 mb-4">Processing Pipeline</div>
              <div className="flex items-center">
                {STAGES.map((stage, i) => (
                  <div key={stage} className="flex items-center flex-1">
                    <div
                      className={`w-8 h-8 rounded-full flex items-center justify-center text-base font-bold shrink-0 ${i <= currentStageIdx ? "bg-cyan-600 text-white" : "bg-slate-800 text-slate-500"
                        }`}
                    >
                      {i + 1}
                    </div>
                    {i < STAGES.length - 1 && (
                      <div className={`flex-1 h-0.5 ${i < currentStageIdx ? "bg-cyan-600" : "bg-slate-800"}`} />
                    )}
                  </div>
                ))}
              </div>
              <div className="flex justify-between text-base text-slate-500 mt-2">
                {STAGES.map((s) => <span key={s} className="capitalize">{s}</span>)}
              </div>
              <div className="mt-4">
                <StatusBadge status={scan.status} />
                {scan.error && <div className="text-red-400 text-base mt-2">{scan.error}</div>}
              </div>
            </div>
            <div className="card flex flex-col items-center justify-center">
              <ScoreRing score={scan.compliance_score ?? 0} />
              <div className="text-base text-slate-500 mt-2">Compliance Score</div>
            </div>
          </div>

          <div className="px-8 grid grid-cols-1 lg:grid-cols-5 gap-4 mb-6">
            <div className="card">
              <div className="text-base uppercase tracking-wide text-slate-500 font-semibold">OPA Policy Decision</div>
              <div className="text-xl font-bold text-slate-100 mt-2">{scan.opa_decision || "—"}</div>
              <div className="text-base text-slate-500 mt-1">{scan.opa_policy_version ? `Policy v${scan.opa_policy_version}` : ""}</div>
              <Link to={`/scans/${scan.id}/opa`} className="text-base text-cyan-400 hover:underline mt-2 inline-block">
                View policy evaluation →
              </Link>
            </div>
            <div className="card">
              <div className="text-base uppercase tracking-wide text-slate-500 font-semibold">Batfish Behavior</div>
              <div className="mt-2">
                <span className={`badge ${BATFISH_TONE[scan.batfish_status || ""] || "badge-na"}`}>
                  {(scan.batfish_status || "NOT_INTEGRATED").replace(/_/g, " ")}
                </span>
              </div>
              <Link to={`/scans/${scan.id}/batfish`} className="text-base text-cyan-400 hover:underline mt-2 inline-block">
                View behavioral analysis →
              </Link>
            </div>
            <div className="card">
              <div className="text-base uppercase tracking-wide text-slate-500 font-semibold">AI Classification</div>
              {aiAnalysis && aiAnalysis.count > 0 ? (
                <>
                  <div className="text-xl font-bold text-slate-100 mt-2">
                    {aiAnalysis.count} interpreted
                  </div>
                  <div className="text-base text-slate-500 mt-1">
                    {aiAnalysis.requires_review_count} need review
                  </div>
                </>
              ) : (
                <div className="text-base text-slate-500 mt-2">No AI interpretations for this scan.</div>
              )}
            </div>
            <div className="card">
              <div className="text-base uppercase tracking-wide text-slate-500 font-semibold">Risk</div>
              <div className="text-xl font-bold text-slate-100 mt-2">
                {scan.risk_level || "—"} {scan.risk_score != null ? `(${scan.risk_score})` : ""}
              </div>
              <div className="text-base text-slate-500 mt-1">Final decision: {scan.final_decision || "—"}</div>
            </div>
            <div className="card">
              <div className="text-base uppercase tracking-wide text-slate-500 font-semibold">Evidence / Fabric Anchor</div>
              {evidence ? (
                <>
                  <div className="mt-2">
                    <span className={`badge ${FABRIC_TONE[evidence.fabric_status || ""] || "badge-na"}`}>
                      {(evidence.fabric_status || "NOT_ANCHORED").replace(/_/g, " ")}
                    </span>
                  </div>
                  <div className="text-base font-mono text-slate-500 mt-1 truncate">
                    hash: {evidence.evidence_hash}
                    {evidence.fabric_tx_id ? ` · tx: ${evidence.fabric_tx_id}` : ""}
                  </div>
                </>
              ) : (
                <div className="text-base text-slate-500 mt-2">No evidence generated yet.</div>
              )}
              <Link to="/evidence" className="text-base text-cyan-400 hover:underline mt-2 inline-block">
                View in Evidence Ledger →
              </Link>
            </div>
          </div>

          {aiAnalysis && aiAnalysis.count > 0 && (
            <div className="px-8 mb-6">
              <div className="card">
                <div className="font-semibold text-slate-200 mb-3">
                  AI Interpretations ({aiAnalysis.count}) — never a compliance decision, advisory only
                  {aiAnalysis.requires_review_count > 0 && (
                    <span className="ml-2 badge badge-medium">{aiAnalysis.requires_review_count} need review</span>
                  )}
                </div>
                <div className="space-y-3 max-h-96 overflow-auto">
                  {aiAnalysis.analyses.map((a) => (
                    <div key={a.id}>
                      <div className="flex items-center justify-between mb-1.5 px-1">
                        <span className="font-mono text-base text-slate-400">{a.intent}</span>
                        <span className={`badge ${AI_DECISION_TONE[a.decision] || "badge-na"}`}>
                          {a.decision.replace(/_/g, " ")}
                        </span>
                      </div>
                      <WhyPanel
                        title={a.requires_review ? "Why is review required?" : "Why?"}
                        rows={[
                          { label: "Classifier confidence", value: `${(a.classifier_confidence * 100).toFixed(0)}%` },
                          { label: "Semantic similarity", value: a.semantic_similarity.toFixed(2) },
                          { label: "Nearest intent", value: a.nearest_intent || "—" },
                          { label: "Nearest vendor", value: a.nearest_vendor || "—" },
                          {
                            label: "Model agreement",
                            value: a.models_agree ? "Yes" : "No — models disagree",
                            tone: a.models_agree ? "pass" : "review",
                          },
                          {
                            label: "Decision",
                            value: a.decision.replace(/_/g, " "),
                            tone: a.decision === "UNKNOWN" ? "unknown" : a.requires_review ? "review" : "pass",
                          },
                          {
                            label: "Review required",
                            value: a.requires_review ? "Yes" : "No",
                            tone: a.requires_review ? "review" : "pass",
                          },
                          { label: "Reason", value: a.reason || "—" },
                          { label: "Model version", value: a.model_version || "—", mono: true },
                          {
                            label: "Inference latency",
                            value: a.inference_latency_ms != null ? `${a.inference_latency_ms.toFixed(1)} ms` : "—",
                          },
                        ]}
                      />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          <div className="px-8 grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="card">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <div className="font-semibold text-slate-200">Normalized Security Model</div>
                  <div className="text-base text-slate-500 mt-0.5">Vendor-neutral facts extracted from the raw config — this is what OPA and Batfish actually evaluate.</div>
                </div>
                {scan.baseline_json && (
                  <button
                    onClick={() => navigator.clipboard?.writeText(JSON.stringify(scan.baseline_json, null, 2))}
                    className="btn-secondary text-base px-2.5 py-1 shrink-0"
                    title="Copy JSON"
                  >
                    Copy
                  </button>
                )}
              </div>
              {scan.baseline_json ? (
                <pre className="bg-slate-950/90 rounded-lg p-3 text-base text-emerald-400 overflow-auto max-h-96 border border-soc-border">
                  {JSON.stringify(scan.baseline_json, null, 2)}
                </pre>
              ) : (
                <div className="text-base text-slate-500 border border-dashed border-soc-border rounded-lg py-10 text-center">
                  Normalization hasn't completed for this scan yet.
                </div>
              )}
            </div>

            <div className="card">
              <div className="flex items-center justify-between mb-3">
                <div className="font-semibold text-slate-200">Findings</div>
                <div className="flex items-center gap-3">
                  {remediations?.remediations?.some((r: any) => r.cli_steps?.length > 0) && (
                    <button
                      onClick={handleCreateChangeRequest}
                      disabled={creatingCr}
                      className="btn-primary text-xs px-3 py-1.5 disabled:opacity-50"
                      title="Bundle the synthesized CLI remediation into a Change Request and open the review queue"
                    >
                      {creatingCr ? "Creating…" : "Create Change Request →"}
                    </button>
                  )}
                  <span className="text-base text-slate-500">{scan.findings.length} total</span>
                </div>
              </div>
              <div className="space-y-2 max-h-96 overflow-auto">
                {scan.findings.length === 0 && (
                  <div className="text-base text-slate-500 border border-dashed border-soc-border rounded-lg py-10 text-center">
                    No findings recorded for this scan.
                  </div>
                )}
                {scan.findings.map((f) => (
                  <div key={f.id} className="border border-soc-border rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-base text-slate-400">{f.control_id}</span>
                      <div className="flex gap-2">
                        <SeverityBadge severity={f.severity} />
                        <ResultBadge result={f.result} />
                      </div>
                    </div>
                    <div className="text-base text-slate-300">{f.title}</div>
                    <div className="text-base text-slate-500 mt-1">
                      Expected: <span className="text-slate-300">{f.expected_value}</span> · Actual:{" "}
                      <span className="text-slate-300">{f.actual_value}</span>
                    </div>
                    {f.evidence_line && (
                      <div className="text-base font-mono text-cyan-400/80 mt-1 truncate">{f.evidence_line}</div>
                    )}
                    {(() => {
                      const r = remediations?.remediations?.find((x: any) => x.finding_id === f.id);
                      if (!r || !r.cli_steps?.length) return null;
                      const isTemplate = !!r.reference;
                      return (
                        <div className="mt-3 bg-slate-900/50 rounded p-2 border border-slate-800">
                          <div className="flex items-center justify-between mb-2">
                            <div className="text-base font-semibold text-emerald-500">
                              {isTemplate ? "Validated CLI Remediation" : "AI Generated CLI Remediation"}
                            </div>
                            {r.requires_site_values && (
                              <span className="badge badge-medium text-[10px]">has placeholders</span>
                            )}
                          </div>
                          {r.description && (
                            <div className="text-sm text-slate-400 mb-2">{r.description}</div>
                          )}
                          <div className="space-y-0.5">
                            {r.cli_steps.map((step: string | Record<string, string>, idx: number) => {
                              const txt = typeof step === "string" ? step : step ? Object.keys(step)[0] : String(step);
                              return <div key={idx} className="font-mono text-sm text-emerald-300 whitespace-pre-wrap">{txt}</div>;
                            })}
                          </div>
                          {r.save_commands?.length > 0 && (
                            <div className="mt-2 pt-2 border-t border-slate-800/60 space-y-0.5">
                              {r.save_commands.map((c: string, idx: number) => (
                                <div key={idx} className="font-mono text-sm text-cyan-300/80 whitespace-pre-wrap"># {c}</div>
                              ))}
                            </div>
                          )}
                          {r.guidance && (
                            <div className="text-sm text-slate-400 mt-2 border-t border-slate-800 pt-2">{r.guidance}</div>
                          )}
                          <div className="text-[11px] text-amber-500/80 mt-2">{r.note || "Requires human review before deployment."}</div>
                        </div>
                      );
                    })()}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="px-8 mt-4 pb-8 flex gap-2">
            <a className="btn-secondary text-base" href={endpoints.reportUrl(scan.id, "pdf")}>Download PDF</a>
            <a className="btn-secondary text-base" href={endpoints.reportUrl(scan.id, "json")}>Download JSON</a>
            <a className="btn-secondary text-base" href={endpoints.reportUrl(scan.id, "csv")}>Download CSV</a>
          </div>
        </>
      )}
    </div>
  );
}