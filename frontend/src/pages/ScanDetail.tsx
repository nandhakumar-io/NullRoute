import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { endpoints, ScanDetail as ScanDetailType, EvidenceRecord, ScanAIAnalysis } from "../api";
import { PageHeader, Loading, ScoreRing, SeverityBadge, ResultBadge, StatusBadge } from "../components/ui";

const STAGES = ["uploaded", "parsed", "normalized", "opa_evaluating", "batfish_evaluating", "correlating", "completed"];

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
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRecord | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<ScanAIAnalysis | null>(null);
  const [rerunning, setRerunning] = useState(false);

  function load() {
    if (scanId) {
      endpoints.scan(scanId).then((r) => setScan(r.data));
      endpoints.evidenceList(scanId).then((r) => setEvidence(r.data[0] ?? null));
      endpoints.aiAnalysis(scanId).then((r) => setAiAnalysis(r.data));
    }
  }

  useEffect(load, [scanId]);

  if (!scan) return <Loading />;

  const currentStageIdx = scan.status === "failed"
    ? -1
    : STAGES.indexOf(["completed", "review", "blocked"].includes(scan.status) ? "completed" : scan.status);

  async function handleRerun() {
    if (!scanId) return;
    setRerunning(true);
    try {
      await endpoints.rerunScan(scanId);
      load();
    } finally {
      setRerunning(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Scan Detail"
        subtitle={`Scan ${scan.id}`}
        action={
          <button onClick={handleRerun} disabled={rerunning} className="btn-secondary text-sm">
            {rerunning ? "Re-running…" : "Re-run evaluation"}
          </button>
        }
      />

      <div className="px-8 grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="card lg:col-span-2">
          <div className="font-semibold text-slate-200 mb-4">Pipeline Progress</div>
          <div className="flex items-center">
            {STAGES.map((stage, i) => (
              <div key={stage} className="flex items-center flex-1">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                    i <= currentStageIdx ? "bg-cyan-600 text-white" : "bg-slate-800 text-slate-500"
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
          <div className="flex justify-between text-xs text-slate-500 mt-2">
            {STAGES.map((s) => <span key={s} className="capitalize">{s}</span>)}
          </div>
          <div className="mt-4">
            <StatusBadge status={scan.status} />
            {scan.error && <div className="text-red-400 text-sm mt-2">{scan.error}</div>}
          </div>
        </div>
        <div className="card flex flex-col items-center justify-center">
          <ScoreRing score={scan.compliance_score ?? 0} />
          <div className="text-xs text-slate-500 mt-2">Compliance Score</div>
        </div>
      </div>

      <div className="px-8 grid grid-cols-1 lg:grid-cols-5 gap-4 mb-6">
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">OPA Policy Decision</div>
          <div className="text-lg font-bold text-slate-100 mt-2">{scan.opa_decision || "—"}</div>
          <div className="text-xs text-slate-500 mt-1">{scan.opa_policy_version ? `Policy v${scan.opa_policy_version}` : ""}</div>
          <Link to={`/scans/${scan.id}/opa`} className="text-xs text-cyan-400 hover:underline mt-2 inline-block">
            View policy evaluation →
          </Link>
        </div>
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Batfish Behavior</div>
          <div className="mt-2">
            <span className={`badge ${BATFISH_TONE[scan.batfish_status || ""] || "badge-na"}`}>
              {(scan.batfish_status || "NOT_INTEGRATED").replace(/_/g, " ")}
            </span>
          </div>
          <Link to={`/scans/${scan.id}/batfish`} className="text-xs text-cyan-400 hover:underline mt-2 inline-block">
            View behavioral analysis →
          </Link>
        </div>
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">AI Classification</div>
          {aiAnalysis && aiAnalysis.count > 0 ? (
            <>
              <div className="text-lg font-bold text-slate-100 mt-2">
                {aiAnalysis.count} interpreted
              </div>
              <div className="text-xs text-slate-500 mt-1">
                {aiAnalysis.requires_review_count} need review
              </div>
            </>
          ) : (
            <div className="text-sm text-slate-500 mt-2">No AI interpretations for this scan.</div>
          )}
        </div>
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Risk</div>
          <div className="text-lg font-bold text-slate-100 mt-2">
            {scan.risk_level || "—"} {scan.risk_score != null ? `(${scan.risk_score})` : ""}
          </div>
          <div className="text-xs text-slate-500 mt-1">Final decision: {scan.final_decision || "—"}</div>
        </div>
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">Evidence / Fabric Anchor</div>
          {evidence ? (
            <>
              <div className="mt-2">
                <span className={`badge ${FABRIC_TONE[evidence.fabric_status || ""] || "badge-na"}`}>
                  {(evidence.fabric_status || "NOT_ANCHORED").replace(/_/g, " ")}
                </span>
              </div>
              <div className="text-xs font-mono text-slate-500 mt-1 truncate">
                hash: {evidence.evidence_hash}
                {evidence.fabric_tx_id ? ` · tx: ${evidence.fabric_tx_id}` : ""}
              </div>
            </>
          ) : (
            <div className="text-sm text-slate-500 mt-2">No evidence generated yet.</div>
          )}
          <Link to="/evidence" className="text-xs text-cyan-400 hover:underline mt-2 inline-block">
            View in Evidence Ledger →
          </Link>
        </div>
      </div>

      {aiAnalysis && aiAnalysis.count > 0 && (
        <div className="px-8 mb-6">
          <div className="card">
            <div className="font-semibold text-slate-200 mb-3">
              AI Interpretations ({aiAnalysis.count}) — never a compliance decision, advisory only
            </div>
            <div className="space-y-2 max-h-72 overflow-auto">
              {aiAnalysis.analyses.map((a) => (
                <div key={a.id} className="border border-soc-border rounded-lg p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs text-slate-400">{a.intent}</span>
                    <span className={`badge ${AI_DECISION_TONE[a.decision] || "badge-na"}`}>
                      {a.decision.replace(/_/g, " ")}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    classifier confidence: {a.classifier_confidence.toFixed(2)} · semantic similarity:{" "}
                    {a.semantic_similarity.toFixed(2)} · nearest: {a.nearest_intent || "—"}
                    {a.nearest_vendor ? ` (${a.nearest_vendor})` : ""} · models agree: {a.models_agree ? "yes" : "no"}
                  </div>
                  {a.reason && <div className="text-xs text-slate-400 mt-1">{a.reason}</div>}
                  <div className="text-xs text-slate-600 mt-1">
                    model: {a.model_version || "—"} · latency: {a.inference_latency_ms?.toFixed(1) ?? "—"} ms
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="px-8 grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Normalized Security Baseline</div>
          <pre className="bg-black/40 rounded-lg p-3 text-xs text-emerald-300 overflow-auto max-h-96">
            {scan.baseline_json ? JSON.stringify(scan.baseline_json, null, 2) : "Not yet normalized."}
          </pre>
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Findings ({scan.findings.length})</div>
          <div className="space-y-2 max-h-96 overflow-auto">
            {scan.findings.map((f) => (
              <div key={f.id} className="border border-soc-border rounded-lg p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs text-slate-400">{f.control_id}</span>
                  <div className="flex gap-2">
                    <SeverityBadge severity={f.severity} />
                    <ResultBadge result={f.result} />
                  </div>
                </div>
                <div className="text-sm text-slate-300">{f.title}</div>
                <div className="text-xs text-slate-500 mt-1">
                  Expected: <span className="text-slate-300">{f.expected_value}</span> · Actual:{" "}
                  <span className="text-slate-300">{f.actual_value}</span>
                </div>
                {f.evidence_line && (
                  <div className="text-xs font-mono text-cyan-400/80 mt-1 truncate">{f.evidence_line}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="px-8 mt-4 pb-8 flex gap-2">
        <a className="btn-secondary text-sm" href={endpoints.reportUrl(scan.id, "pdf")}>Download PDF</a>
        <a className="btn-secondary text-sm" href={endpoints.reportUrl(scan.id, "json")}>Download JSON</a>
        <a className="btn-secondary text-sm" href={endpoints.reportUrl(scan.id, "csv")}>Download CSV</a>
      </div>
    </div>
  );
}
