import { useEffect, useRef, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { endpoints, ScanDetail as ScanDetailType, EvidenceRecord, ScanAIAnalysis, DeviceVulnerabilityMatch, ChangeRequest, DeploymentRecord } from "../api";
import { useToast } from "../lib/toast";
import { useConfirm } from "../lib/confirm";
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
  const toast = useToast();
  const confirm = useConfirm();
  const [deleting, setDeleting] = useState(false);
  const [creatingCr, setCreatingCr] = useState(false);
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRecord | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<ScanAIAnalysis | null>(null);
  const [remediations, setRemediations] = useState<any>(undefined);
  const [rerunning, setRerunning] = useState(false);
  const [pipelineActionPending, setPipelineActionPending] = useState<"pause" | "stop" | "resume" | null>(null);

  const [currentSnapshot, setCurrentSnapshot] = useState<any>(null);
  const [deviceHasBaseline, setDeviceHasBaseline] = useState(false);
  const [approving, setApproving] = useState(false);

  const [activeTab, setActiveTab] = useState<"overview" | "matrix" | "vulns">("overview");
  const [complianceMatrix, setComplianceMatrix] = useState<Array<Record<string, any>> | null>(null);
  const [vulnMatches, setVulnMatches] = useState<DeviceVulnerabilityMatch[] | null>(null);
  const [correlating, setCorrelating] = useState(false);

  // Approval & Deployment / Post-Validation state -- a scan's own findings
  // can lead to a remediation Change Request for the same device (see
  // "Create Change Request" below). There's no scan_id FK on ChangeRequest
  // (it's device-scoped, same as everywhere else this platform correlates
  // scan -> device -> change), so "the deployment this scan's findings led
  // to" is approximated as the most recent change request for this scan's
  // device -- same join the Change Requests page's own `?device=` deep link
  // already relies on.
  const [latestChangeRequest, setLatestChangeRequest] = useState<ChangeRequest | null | undefined>(undefined);
  const [latestDeployment, setLatestDeployment] = useState<DeploymentRecord | null>(null);

  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    let isActive = true;
    let timeoutId: number;
    let consecutiveErrors = 0;
    const MAX_RETRIES = 5;

    async function tick() {
      if (!isActive || !scanId) return;
      try {
        // The scan itself is the one call everything else depends on, so it
        // goes first and its errors are handled specially (a 404 here means
        // the scan genuinely doesn't exist -- retrying forever every 3s just
        // hammers the backend and leaves the page stuck on a spinner, which
        // is what made a bad/expired scan id look like "the app is frozen").
        const scanRes = await endpoints.scan(scanId);
        if (!isActive) return;
        consecutiveErrors = 0;
        setLoadError(null);
        setScan(scanRes.data);

        // "failed" belongs here too now that the pipeline genuinely runs in
        // the background: a scan can reach it mid-poll (it used to run
        // synchronously inside the upload request, so by the time this page
        // ever saw the scan it was already in a terminal state). Without
        // this, a failed scan polled forever since pipelineDone never went
        // true.
        const pipelineDone = ["completed", "review", "blocked", "failed"].includes(scanRes.data.status);

        // The rest of these are independent of one another -- fetch them in
        // parallel instead of one after another. Chaining 4-6 sequential
        // round trips behind every 3s poll is what made this page feel slow
        // to load and slow to update.
        const [snapsRes, evRes, aiRes, crRes] = await Promise.allSettled([
          endpoints.deviceSnapshots(scanRes.data.device_id),
          endpoints.evidenceList(scanId),
          endpoints.aiAnalysis(scanId),
          endpoints.changeRequests({ device_id: scanRes.data.device_id }),
        ]);
        if (!isActive) return;

        if (snapsRes.status === "fulfilled") {
          setCurrentSnapshot(snapsRes.value.data.snapshots.find((s: any) => s.scan_id === scanId));
          setDeviceHasBaseline(snapsRes.value.data.snapshots.some((s: any) => s.is_approved_baseline));
        }
        if (evRes.status === "fulfilled") setEvidence(evRes.value.data[0] ?? null);
        if (aiRes.status === "fulfilled") setAiAnalysis(aiRes.value.data);

        // Latest change request for this device (see state comment above) --
        // fetched every tick (not gated on pipelineDone) since approval/
        // deployment can progress well after the scan pipeline itself is done.
        if (crRes.status === "fulfilled") {
          const latest = (crRes.value.data.change_requests || [])
            .slice()
            .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0];
          setLatestChangeRequest(latest || null);
          if (latest && (latest.status === "APPROVED" || latest.status === "DEPLOYED" || latest.status === "FAILED")) {
            try {
              const depRes = await endpoints.changeRequestDeployments(latest.id);
              const deployments = depRes.data.deployments || [];
              const mostRecent = deployments
                .slice()
                .sort((a, b) => new Date(b.started_at || 0).getTime() - new Date(a.started_at || 0).getTime())[0];
              if (isActive) setLatestDeployment(mostRecent || null);
            } catch {
              if (isActive) setLatestDeployment(null);
            }
          } else {
            setLatestDeployment(null);
          }
        } else {
          setLatestChangeRequest(null);
        }

        if (pipelineDone) {
          try {
            const rem = await endpoints.aiRemediation(scanId);
            if (isActive) setRemediations(rem.data);
          } catch (e) {
            if (isActive) setRemediations(null);
          }
        } else if (isActive) {
          timeoutId = window.setTimeout(tick, 3000);
        }
      } catch (err: any) {
        if (!isActive) return;
        const status = err?.response?.status;
        if (status === 404) {
          // Scan genuinely doesn't exist (bad/expired id, or the id we
          // navigated to was never a real scan) -- stop polling instead of
          // retrying forever every 3s.
          setLoadError("Scan not found. It may have been removed, or the link is invalid.");
          return;
        }
        consecutiveErrors += 1;
        if (consecutiveErrors > MAX_RETRIES) {
          setLoadError("Couldn't reach the server after several attempts. Check your connection and refresh to try again.");
          return;
        }
        // Back off instead of hammering the backend every 3s on repeated failures.
        timeoutId = window.setTimeout(tick, 3000 * consecutiveErrors);
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

  // Deep-link support: the Validation page's "Open Remediation" link
  // points here with a #remediation hash so an operator lands directly on
  // the Findings/remediation card instead of having to scroll and hunt
  // for it on a long scan page.
  useEffect(() => {
    if (window.location.hash !== "#remediation") return;
    const el = document.getElementById("remediation");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [scan, remediations]);

  const pipelineCompleted = !!scan && ["completed", "review", "blocked"].includes(scan.status);
  // A pipeline is live if the scan hasn't reached any terminal state. NB: a
  // *finished* scan keeps control_state="RUNNING", so control_state alone
  // can't tell "running" from "done" -- that is why Delete used to be
  // disabled for every completed scan.
  const scanLive =
    !!scan && !["completed", "review", "blocked", "failed", "stopped"].includes(scan.status) && scan.control_state !== "STOPPED";
  const aiReady = aiAnalysis !== null && aiAnalysis.count >= 0 && pipelineCompleted;
  // If pipeline is done, wait for AI analysis before fully lighting up 'completed'
  let currentStageIdx = -1;
  if (scan && scan.status !== "failed") {
    const pIdx = STAGES.indexOf(pipelineCompleted ? "completed" : scan.status);
    currentStageIdx = aiReady ? pIdx + 1 : pIdx;
  }

  // --- Animated, step-by-step reveal -----------------------------------
  // Without this, a fast/small scan finishes all 8 processing stages and
  // all 6 decision-pipeline steps between one poll and the next, so the
  // UI would jump straight from "just started" to "everything done" in a
  // single re-render. These two trackers chase the real, backend-confirmed
  // progress (stageRevealRef never runs ahead of currentStageIdx, and the
  // decision pipeline never reveals before the pipeline has actually
  // completed) but always step through it visibly, one stage/step at a
  // time, instead of snapping.
  const stageRevealRef = useRef(0);
  const [stageReveal, setStageReveal] = useState(0);
  useEffect(() => {
    const target = currentStageIdx + 1;
    if (stageRevealRef.current >= target) return;
    const id = window.setInterval(() => {
      stageRevealRef.current += 1;
      setStageReveal(stageRevealRef.current);
      if (stageRevealRef.current >= target) window.clearInterval(id);
    }, 280);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentStageIdx]);

  const DECISION_STEP_COUNT = 6; // Normalized, OPA, Batfish, Risk, Decision, Evidence
  const [decisionReveal, setDecisionReveal] = useState(0);
  useEffect(() => {
    if (!pipelineCompleted) {
      setDecisionReveal(0);
      return;
    }
    let i = 0;
    const id = window.setInterval(() => {
      i += 1;
      setDecisionReveal(i);
      if (i >= DECISION_STEP_COUNT) window.clearInterval(id);
    }, 320);
    return () => window.clearInterval(id);
  }, [pipelineCompleted]);

  // --- Post-decision lifecycle reveal ------------------------------------
  // Everything after the Decision Pipeline (Pre-Deployment Risk, Approval,
  // Deployment, Post-Deployment Validation, Report Generation, Blockchain
  // Integrity) used to render the instant its underlying data showed up --
  // which, on a scan that already has an approved/deployed change request,
  // meant every one of those cards popped in at once. This walks through
  // them one card at a time (same "chase real progress, never snap" idea as
  // stageReveal/decisionReveal above), only starting once the Decision
  // Pipeline has finished its own reveal.
  const SECTION_COUNT = 6; // Risk, Approval, Deployment, Post-Validation, Report, Blockchain
  const [sectionReveal, setSectionReveal] = useState(0);
  useEffect(() => {
    if (decisionReveal < DECISION_STEP_COUNT) {
      setSectionReveal(0);
      return;
    }
    let i = 0;
    const id = window.setInterval(() => {
      i += 1;
      setSectionReveal(i);
      if (i >= SECTION_COUNT) window.clearInterval(id);
    }, 360);
    return () => window.clearInterval(id);
  }, [decisionReveal]);

  const sectionCls = (idx: number) =>
    `transition-all duration-500 ${sectionReveal > idx ? "opacity-100 translate-y-0" : "opacity-0 translate-y-3 pointer-events-none"}`;

  if (!scan) {
    if (loadError) {
      return (
        <EmptyState message={loadError} />
      );
    }
    return <Loading />;
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

  async function handleDelete() {
    if (!scan) return;
    const ok = await confirm(
      "This permanently deletes the scan and its findings, OPA/Batfish results, and AI analysis. Evidence records and device snapshots are kept but detached from it. This can't be undone." +
        (scanLive ? "\n\nThe running pipeline will be stopped first." : ""),
      { title: "Delete this scan", confirmLabel: "Delete", danger: true }
    );
    if (!ok) return;
    setDeleting(true);
    try {
      await endpoints.deleteScan(scan.id, scanLive);
      toast.success("Scan deleted.");
      navigate("/validation");
    } catch (e: any) {
      const detail = e?.response?.data?.detail;
      if (e?.response?.status === 409 && typeof detail === "string" && detail.includes("golden baseline")) {
        const forceOk = await confirm(detail, { title: "Delete anyway?", confirmLabel: "Delete anyway", danger: true });
        if (forceOk) {
          try {
            await endpoints.deleteScan(scan.id, true);
            toast.success("Scan deleted.");
            navigate("/validation");
            return;
          } catch (e2: any) {
            toast.error(e2?.response?.data?.detail || "Failed to delete the scan");
          }
        }
      } else {
        toast.error(detail || "Failed to delete the scan");
      }
    } finally {
      setDeleting(false);
    }
  }

  async function handlePipelineAction(action: "pause" | "stop" | "resume") {
    if (!scanId) return;
    setPipelineActionPending(action);
    try {
      // Stop is a force stop: the server cancels the pipeline and persists
      // STOPPED before responding, so there is no "Stopping…" limbo to poll.
      const res =
        action === "pause" ? await endpoints.pauseScan(scanId)
        : action === "stop" ? await endpoints.stopScan(scanId, true)
        : await endpoints.resumeScan(scanId);
      // Apply the server's response straight away instead of a full page
      // reload -- a reload re-fetches every asset and re-runs every effect
      // on the page just to show a control_state change, which is what made
      // clicking Pause/Stop feel like it "did nothing" for a second or two.
      setScan(res.data);
      // A request (PAUSE_REQUESTED/STOP_REQUESTED) only takes effect once
      // the in-flight pipeline reaches its next checkpoint, which can land
      // just after this response comes back. Poll a couple of times, a
      // second apart, so the badge above flips to PAUSED/STOPPED as soon as
      // it actually happens rather than waiting for the next 3s tick.
      for (let i = 0; i < 3; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        try {
          const fresh = await endpoints.scan(scanId);
          setScan(fresh.data);
          if (fresh.data.control_state !== "PAUSE_REQUESTED" && fresh.data.control_state !== "STOP_REQUESTED") break;
        } catch {
          break;
        }
      }
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || `Failed to ${action} the pipeline`);
    } finally {
      setPipelineActionPending(null);
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

  function exportAiAnalysisCsv() {
    if (!aiAnalysis || aiAnalysis.analyses.length === 0) return;
    const header = ["Raw Command Hash", "Intent", "Classifier Confidence", "Semantic Similarity", "Decision", "Requires Review", "Nearest Intent", "Nearest Vendor", "Models Agree", "Reason"];
    const rows = aiAnalysis.analyses.map(a => [
      a.raw_command_hash,
      a.intent,
      a.classifier_confidence.toFixed(4),
      a.semantic_similarity.toFixed(4),
      a.decision,
      a.requires_review ? "Yes" : "No",
      a.nearest_intent || "",
      a.nearest_vendor || "",
      a.models_agree ? "Yes" : "No",
      (a.reason || "").replace(/"/g, '""')
    ]);

    const csvContent = [header]
      .concat(rows)
      .map(row => row.map(cell => `"${cell}"`).join(","))
      .join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `scan_${scanId}_ai_analysis.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  return (
    <div>
      <PageHeader
        title="Scan Detail"
        subtitle={`Scan ${scan.id}`}
        action={
          <div className="flex items-center gap-2">
            {scanLive && (!scan.control_state || scan.control_state === "RUNNING") && (
              <button
                onClick={() => handlePipelineAction("pause")}
                disabled={pipelineActionPending !== null}
                className="btn-secondary text-base"
                title="Pause at the next stage checkpoint (normalize/opa/batfish/finalize)"
              >
                {pipelineActionPending === "pause" ? "Pausing…" : "Pause pipeline"}
              </button>
            )}
            {(scanLive || scan.control_state === "PAUSED") && (
              <button
                onClick={() => handlePipelineAction("stop")}
                disabled={pipelineActionPending !== null || scan.control_state === "STOP_REQUESTED"}
                className="btn-secondary text-base"
                title="Stop immediately — progress already saved is kept and it can be resumed later"
              >
                {pipelineActionPending === "stop" ? "Stopping…" : "Stop pipeline"}
              </button>
            )}
            {["PAUSED", "STOPPED"].includes(scan.control_state || "") && (
              <button
                onClick={() => handlePipelineAction("resume")}
                disabled={pipelineActionPending !== null}
                className="btn-primary text-base"
                title={`Resume from: ${scan.pipeline_stage || "start"}`}
              >
                {pipelineActionPending === "resume" ? "Resuming…" : `Resume from ${scan.pipeline_stage || "start"}`}
              </button>
            )}
            <button onClick={handleRerun} disabled={rerunning} className="btn-secondary text-base">
              {rerunning ? "Re-running…" : "Re-run evaluation"}
            </button>
            <button
              onClick={handleDelete}
              disabled={deleting || pipelineActionPending !== null}
              className="btn-secondary text-base border-red-800/60 text-red-400 hover:bg-red-500/10"
              title={scanLive ? "Stop the running pipeline and permanently delete this scan" : "Permanently delete this scan"}
            >
              {deleting ? "Deleting…" : "Delete scan"}
            </button>
          </div>
        }
      />

      {["PAUSE_REQUESTED", "PAUSED", "STOP_REQUESTED", "STOPPED"].includes(scan.control_state || "") && (
        <div className="card mb-3 border-amber-800/60 bg-amber-950/20 text-base text-amber-300">
          {scan.control_state === "PAUSE_REQUESTED" && "Pause requested — will pause at the next stage checkpoint."}
          {scan.control_state === "PAUSED" && `Paused at stage: ${scan.pipeline_stage || "unknown"}. Resume to continue from here, or Stop to end it instead.`}
          {scan.control_state === "STOP_REQUESTED" && "Stopping…"}
          {scan.control_state === "STOPPED" && `Stopped at stage: ${scan.pipeline_stage || "unknown"}. Resume to pick up from here.`}
        </div>
      )}

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
          {/* 1. Pipeline Flow — animated, step-by-step (never snaps straight to
              "all done"): the numbered stage tracker only lights up one stage
              at a time, chasing real backend progress via stageReveal. */}
          <div className="px-8 grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
            <div className="card lg:col-span-2">
              <div className="font-semibold text-slate-200 mb-1">1 · Pipeline Flow</div>
              <div className="text-base text-slate-500 mb-4">Ingestion → parsing → normalization → policy evaluation, one stage at a time.</div>
              <div className="flex items-center">
                {STAGES.map((stage, i) => {
                  const isDone = i < stageReveal;
                  const isCurrent = i === stageReveal - 1 && !pipelineCompleted;
                  return (
                    <div key={stage} className="flex items-center flex-1">
                      <div
                        className={`w-8 h-8 rounded-full flex items-center justify-center text-base font-bold shrink-0 transition-all duration-500 ${
                          isDone ? "bg-cyan-600 text-white scale-100" : "bg-slate-800 text-slate-500 scale-95"
                        } ${isCurrent ? "ring-4 ring-cyan-500/30 animate-pulse" : ""}`}
                      >
                        {i + 1}
                      </div>
                      {i < STAGES.length - 1 && (
                        <div className={`flex-1 h-0.5 transition-colors duration-500 ${i < stageReveal - 1 ? "bg-cyan-600" : "bg-slate-800"}`} />
                      )}
                    </div>
                  );
                })}
              </div>
              <div className="flex justify-between text-base text-slate-500 mt-2">
                {STAGES.map((s, i) => (
                  <span key={s} className={`capitalize transition-colors duration-500 ${i < stageReveal ? "text-slate-300" : "text-slate-600"}`}>{s}</span>
                ))}
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

          {/* 2. Decision Pipeline — same progressive reveal, gated on the
              processing pipeline having actually finished (never reveals a
              step before the backend has a real value for it). */}
          <div className="px-8 grid grid-cols-1 gap-4 mb-6">
            <div className="card">
              <div className="font-semibold text-slate-200 mb-1">2 · Decision Pipeline</div>
              <div className="text-base text-slate-500 mb-5">How this scan's outcome was derived — deterministic, evidence-backed, never LLM-decided.</div>
              <DecisionPipeline
                size="lg"
                revealedCount={decisionReveal}
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

          {/* 2b. Pipeline Stage Timing — waterfall bar chart from scan.stage_timings.
                Only rendered when the backend has collected at least one stage duration
                (i.e. for scans run after the stage_timings column was added). */}
          {scan.stage_timings && Object.keys(scan.stage_timings).length > 0 && (() => {
            const STAGE_COLORS: Record<string, string> = {
              start:    "bg-cyan-600",
              normalize:"bg-violet-500",
              opa:      "bg-emerald-500",
              batfish:  "bg-amber-500",
              finalize: "bg-orange-500",
              done:     "bg-slate-500",
            };
            const STAGE_LABELS: Record<string, string> = {
              start:    "Vendor detect & parse",
              normalize:"AI/RAG normalization",
              opa:      "OPA evaluation",
              batfish:  "Batfish analysis",
              finalize: "Risk, correlation & evidence",
              done:     "Done",
            };
            const ORDER = ["start", "normalize", "opa", "batfish", "finalize", "done"];
            type TimingEntry = { started_at?: string; completed_at?: string; duration_ms?: number };
            const timings = scan.stage_timings as Record<string, TimingEntry>;
            const rows = ORDER.filter(k => timings[k]?.duration_ms != null).map(k => ({
              key: k,
              label: STAGE_LABELS[k] || k,
              color: STAGE_COLORS[k] || "bg-slate-600",
              ms: timings[k].duration_ms as number,
            }));
            if (rows.length === 0) return null;
            const totalMs = rows.reduce((s, r) => s + r.ms, 0);
            const maxMs = Math.max(...rows.map(r => r.ms));
            const fmtMs = (ms: number) => ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
            const bottleneck = rows.find(r => r.ms === maxMs);
            return (
              <div className="px-8 mb-6">
                <div className="card">
                  <div className="flex items-center justify-between mb-1">
                    <div className="font-semibold text-slate-200">2b · Pipeline Stage Timing</div>
                    <div className="text-base text-slate-500">Total: <span className="text-slate-300 font-mono">{fmtMs(totalMs)}</span></div>
                  </div>
                  <div className="text-base text-slate-500 mb-4">
                    How long each stage took — identify bottlenecks at a glance.
                    {bottleneck && (
                      <span className="ml-2 px-2 py-0.5 rounded text-base bg-amber-500/15 text-amber-300 font-medium">
                        ⚡ Bottleneck: {bottleneck.label} ({fmtMs(bottleneck.ms)})
                      </span>
                    )}
                  </div>
                  <div className="space-y-2.5">
                    {rows.map(row => {
                      const pct = totalMs > 0 ? (row.ms / totalMs) * 100 : 0;
                      const isBottleneck = row.ms === maxMs;
                      return (
                        <div key={row.key}>
                          <div className="flex items-center justify-between mb-1">
                            <span className={`text-base font-medium ${isBottleneck ? "text-amber-300" : "text-slate-300"}`}>
                              {row.label}
                            </span>
                            <span className={`text-base font-mono ${isBottleneck ? "text-amber-300 font-semibold" : "text-slate-400"}`}>
                              {fmtMs(row.ms)}
                              <span className="text-slate-600 ml-1">({pct.toFixed(0)}%)</span>
                            </span>
                          </div>
                          <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all duration-700 ${row.color} ${isBottleneck ? "ring-1 ring-amber-400/40" : ""}`}
                              style={{ width: `${Math.max(pct, 1)}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            );
          })()}


          {/* Pipeline detail: what fed the Decision Pipeline above. */}
          <div className="px-8 grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
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
          </div>

          {/* 3. Pre-Deployment Risk — the risk verdict this scan produced,
              called out cleanly before anything about approving or deploying
              a fix for it. */}
          <div className={`px-8 mb-6 ${sectionCls(0)}`}>
            <div className={`card border ${
              riskTone(scan.risk_level) === "fail" ? "border-red-900/60 bg-red-950/10"
              : riskTone(scan.risk_level) === "warn" ? "border-amber-900/60 bg-amber-950/10"
              : "border-soc-border"
            }`}>
              <div className="font-semibold text-slate-200 mb-1">3 · Pre-Deployment Risk</div>
              <div className="text-base text-slate-500 mb-4">
                The risk verdict this scan produced — computed before any remediation is proposed, approved, or deployed.
              </div>
              <div className="flex flex-wrap items-center gap-6">
                <div>
                  <div className="text-3xl font-bold text-slate-100">
                    {scan.risk_level || "—"} {scan.risk_score != null && <span className="text-lg text-slate-500">({scan.risk_score})</span>}
                  </div>
                  <div className="text-base text-slate-500 mt-1">Risk level</div>
                </div>
                <div className="h-10 w-px bg-soc-border hidden sm:block" />
                <div>
                  <div className="text-3xl font-bold text-slate-100">{scan.final_decision || "PENDING"}</div>
                  <div className="text-base text-slate-500 mt-1">Correlated decision</div>
                </div>
                <div className="h-10 w-px bg-soc-border hidden sm:block" />
                <div>
                  <div className="text-3xl font-bold text-slate-100">
                    {scan.findings.filter((f) => f.result === "FAIL").length}
                    <span className="text-lg text-slate-500"> / {scan.findings.length}</span>
                  </div>
                  <div className="text-base text-slate-500 mt-1">Findings failing</div>
                </div>
              </div>
              {scan.final_reason && (
                <div className="text-base text-slate-400 mt-4 pt-3 border-t border-soc-border">{scan.final_reason}</div>
              )}
            </div>
          </div>

          {/* 4. Approval — has a human signed off on the proposed fix yet?
              Kept as its own clean stage, separate from whether it has
              actually been pushed to the device (see 5, below). Change
              requests are device-scoped, not scan-scoped, so this is the
              same device join the Change Requests page's own deep link
              already uses. */}
          <div className={`px-8 mb-6 ${sectionCls(1)}`}>
            <div className="card">
              <div className="font-semibold text-slate-200 mb-1">4 · Approval</div>
              <div className="text-base text-slate-500 mb-4">
                A human must approve before anything deploys — the AI only ever synthesizes syntax.
              </div>
              {latestChangeRequest === undefined ? (
                <Loading />
              ) : latestChangeRequest === null ? (
                <div className="text-base text-slate-500 border border-dashed border-soc-border rounded-lg py-6 text-center">
                  No change request has been created for this device yet.
                  {scan.findings.some((f) => f.result === "FAIL") && (
                    <> Use <span className="text-slate-300">Create Change Request</span> below to propose a fix.</>
                  )}
                </div>
              ) : (
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`badge ${
                        latestChangeRequest.status === "APPROVED" || latestChangeRequest.status === "DEPLOYED" ? "badge-pass"
                        : latestChangeRequest.status === "REJECTED" || latestChangeRequest.status === "FAILED" ? "badge-fail"
                        : "badge-medium"
                      }`}>
                        {latestChangeRequest.status.replace(/_/g, " ")}
                      </span>
                      {latestChangeRequest.source === "ai_suggestion" && <span className="badge badge-medium">AI-suggested</span>}
                      <span className="text-base text-slate-500">Risk: {latestChangeRequest.risk_level || "—"}</span>
                    </div>
                    <div className="text-base text-slate-500 mt-1.5">
                      Created {new Date(latestChangeRequest.created_at).toLocaleString()}
                      {latestChangeRequest.created_by && ` by ${latestChangeRequest.created_by}`}
                      {latestChangeRequest.approved_by && (
                        <> · approved by {latestChangeRequest.approved_by}
                          {latestChangeRequest.approved_at && ` at ${new Date(latestChangeRequest.approved_at).toLocaleString()}`}
                        </>
                      )}
                    </div>
                  </div>
                  <Link to={`/review-queue?device=${scan.device_id}`} className="btn-secondary text-base whitespace-nowrap">
                    {latestChangeRequest.status === "PENDING_APPROVAL" ? "Review & Approve →" : "Open in Review Queue →"}
                  </Link>
                </div>
              )}
            </div>
          </div>

          {/* 5. Deployment — whether the approved change has actually been
              pushed to the device yet. Separate from Approval (4) above:
              an approved change request can sit for a while before a
              deployment attempt runs against it. */}
          <div className={`px-8 mb-6 ${sectionCls(2)}`}>
            <div className="card">
              <div className="font-semibold text-slate-200 mb-1">5 · Deployment</div>
              <div className="text-base text-slate-500 mb-4">
                Pushes the approved configuration change to the device over its management transport.
              </div>
              {!latestDeployment ? (
                <div className="text-base text-slate-500 border border-dashed border-soc-border rounded-lg py-6 text-center">
                  {latestChangeRequest?.status === "APPROVED"
                    ? "Approved and ready — no deployment attempt has run yet."
                    : "Nothing to deploy for this device yet."}
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-6">
                  <div>
                    <span className={`badge ${
                      latestDeployment.status === "DEPLOYED" || latestDeployment.status === "VERIFIED" ? "badge-pass"
                      : latestDeployment.status === "DRIFTED" || latestDeployment.status === "FAILED" ? "badge-fail"
                      : "badge-medium"
                    }`}>
                      {latestDeployment.status}
                    </span>
                    <div className="text-base text-slate-500 mt-1">via {latestDeployment.transport || "—"}</div>
                  </div>
                  <div className="text-base text-slate-400">
                    started: <span className="text-slate-300">{latestDeployment.started_at ? new Date(latestDeployment.started_at).toLocaleString() : "—"}</span>
                  </div>
                  {latestChangeRequest && (
                    <Link to={`/review-queue?device=${scan.device_id}`} className="text-base text-cyan-400 hover:underline ml-auto">
                      Full deployment history →
                    </Link>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* 6. Post-Deployment Validation — what happened after deploy:
              config actually landed, and (when available) supplemental
              pyATS/Genie verification. Never authoritative for compliance
              on its own — OPA/Batfish/risk already decided that above. */}
          <div className={`px-8 mb-6 ${sectionCls(3)}`}>
            <div className="card">
              <div className="font-semibold text-slate-200 mb-1">6 · Post-Deployment Validation</div>
              <div className="text-base text-slate-500 mb-4">
                Confirms the deployed configuration matches what was approved, and that the device still verifies afterward.
              </div>
              {!latestDeployment ? (
                <div className="text-base text-slate-500 border border-dashed border-soc-border rounded-lg py-6 text-center">
                  {latestChangeRequest?.status === "APPROVED"
                    ? "Approved and ready — no deployment attempt has run yet."
                    : "Nothing deployed for this device yet."}
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-6">
                  <div>
                    <span className={`badge ${
                      latestDeployment.status === "DEPLOYED" || latestDeployment.status === "VERIFIED" ? "badge-pass"
                      : latestDeployment.status === "DRIFTED" || latestDeployment.status === "FAILED" ? "badge-fail"
                      : "badge-medium"
                    }`}>
                      {latestDeployment.status}
                    </span>
                    <div className="text-base text-slate-500 mt-1">via {latestDeployment.transport || "—"}</div>
                  </div>
                  <div className="text-base text-slate-400">
                    post-hash: <span className="font-mono text-slate-300">{(latestDeployment.post_config_hash || "—").slice(0, 12)}</span>
                    <br />
                    post-verification:{" "}
                    <span className={latestDeployment.post_verification_passed ? "text-emerald-400" : latestDeployment.post_verification_passed === false ? "text-red-400" : "text-slate-500"}>
                      {latestDeployment.post_verification_passed === null ? "—" : latestDeployment.post_verification_passed ? "passed" : "FAILED"}
                    </span>
                  </div>
                  {latestDeployment.verification_engine && (
                    <div className="text-base text-slate-400">
                      supplemental ({latestDeployment.verification_engine}):{" "}
                      <span className={latestDeployment.verification_result === "PYATS_OK" ? "text-emerald-400" : "text-amber-400"}>
                        {latestDeployment.verification_result || "—"}
                      </span>
                    </div>
                  )}
                  {latestChangeRequest && (
                    <Link to={`/review-queue?device=${scan.device_id}`} className="text-base text-cyan-400 hover:underline ml-auto">
                      Full deployment history →
                    </Link>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* 7. Report Generation — the compliance report artifacts for this
              scan are ready as soon as the pipeline itself finished; called
              out as its own stage rather than only appearing as unlabeled
              download links at the bottom of the page. */}
          <div className={`px-8 mb-6 ${sectionCls(4)}`}>
            <div className="card">
              <div className="font-semibold text-slate-200 mb-1">7 · Report Generation</div>
              <div className="text-base text-slate-500 mb-4">
                Compliance report rendered from this scan's findings, decision, and evidence — available once the pipeline completes.
              </div>
              {!pipelineCompleted ? (
                <div className="text-base text-slate-500 border border-dashed border-soc-border rounded-lg py-6 text-center">
                  Waiting on pipeline completion before the report can be rendered.
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-4">
                  <span className="badge badge-pass">Generated</span>
                  <button className="btn-secondary text-base" onClick={() => endpoints.downloadReport(scan.id, "pdf")}>Download PDF</button>
                  <button className="btn-secondary text-base" onClick={() => endpoints.downloadReport(scan.id, "json")}>Download JSON</button>
                  <button className="btn-secondary text-base" onClick={() => endpoints.downloadReport(scan.id, "csv")}>Download CSV</button>
                </div>
              )}
            </div>
          </div>

          {/* 8. Blockchain Integrity — the tamper-evident anchor for this
              scan's evidence record. Distinct, dedicated stage rather than
              only a terse "Evidence" dot buried inside the Decision
              Pipeline strip above. */}
          <div className={`px-8 mb-6 ${sectionCls(5)}`}>
            <div className="card">
              <div className="font-semibold text-slate-200 mb-1">8 · Blockchain Integrity</div>
              <div className="text-base text-slate-500 mb-4">
                This scan's evidence record, hashed and anchored to the Hyperledger Fabric ledger for tamper-evident audit.
              </div>
              {!evidence ? (
                <div className="text-base text-slate-500 border border-dashed border-soc-border rounded-lg py-6 text-center">
                  No evidence record has been anchored for this scan yet.
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-6">
                  <span className={`badge ${evidence.fabric_status === "ANCHORED" ? "badge-pass" : evidence.fabric_status === "FABRIC_UNAVAILABLE" ? "badge-fail" : "badge-medium"}`}>
                    {(evidence.fabric_status || "RECORDED").replace(/_/g, " ")}
                  </span>
                  <div className="text-base text-slate-400">
                    evidence hash: <span className="font-mono text-slate-300">{evidence.evidence_hash ? `${evidence.evidence_hash.slice(0, 16)}…` : "—"}</span>
                  </div>
                  {evidence.fabric_tx_id && (
                    <div className="text-base text-slate-400">
                      tx: <span className="font-mono text-slate-300">{evidence.fabric_tx_id.slice(0, 16)}…</span>
                    </div>
                  )}
                  {evidence.fabric_block_number != null && (
                    <div className="text-base text-slate-400">
                      block: <span className="font-mono text-slate-300">{evidence.fabric_block_number}</span>
                    </div>
                  )}
                  <Link to="/evidence" className="text-base text-cyan-400 hover:underline ml-auto">
                    Open Evidence Ledger →
                  </Link>
                </div>
              )}
            </div>
          </div>

          {aiAnalysis && aiAnalysis.count > 0 && (
            <div className="px-8 mb-6">
              <div className="card">
                <div className="flex items-center justify-between mb-3">
                  <div className="font-semibold text-slate-200">
                    AI Interpretations ({aiAnalysis.count}) — never a compliance decision, advisory only
                    {aiAnalysis.requires_review_count > 0 && (
                      <span className="ml-2 badge badge-medium">{aiAnalysis.requires_review_count} need review</span>
                    )}
                  </div>
                  <button
                    onClick={exportAiAnalysisCsv}
                    className="btn-secondary text-base px-3 py-1 shrink-0"
                    title="Export AI interpretations (hashes and scores) to CSV for training/dataset compilation"
                  >
                    Export CSV
                  </button>
                </div>
                <div className="space-y-3 max-h-96 overflow-auto">
                  {aiAnalysis.analyses.map((a) => (
                    <div key={a.id}>
                      <div className="flex flex-col mb-1.5 px-1">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-base text-slate-400">Classified as: {a.intent}</span>
                          <span className={`badge ${AI_DECISION_TONE[a.decision] || "badge-na"}`}>
                            {a.decision.replace(/_/g, " ")}
                          </span>
                        </div>
                        {a.raw_command ? (
                          <div className="text-sm font-mono text-slate-300 bg-soc-bg border border-soc-border rounded p-2 mb-2 overflow-x-auto whitespace-pre">
                            {a.raw_command}
                          </div>
                        ) : (
                          <div className="text-sm text-slate-500 italic mb-2">Command hash: {a.raw_command_hash}</div>
                        )}
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

            {remediations?.device_vulnerabilities?.length > 0 && (
              <div className="card border-red-900/50 bg-red-950/10">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-red-400 text-sm">⚠</span>
                  <div className="font-semibold text-red-300 text-sm">
                    {remediations.device_vulnerabilities.length} actively-exploited vulnerabilit
                    {remediations.device_vulnerabilities.length === 1 ? "y" : "ies"} on this device
                  </div>
                </div>
                <div className="text-xs text-slate-400 mb-2">
                  Confirmed under active exploitation per CISA's Known Exploited Vulnerabilities
                  catalog — separate from the compliance findings below, and not fixed by any
                  network config change.
                </div>
                <div className="space-y-1.5">
                  {remediations.device_vulnerabilities.map((v: any) => (
                    <div key={v.cve_id} className="text-xs bg-slate-900/40 rounded px-2 py-1.5">
                      <span className="font-mono text-red-300">{v.cve_id}</span>
                      {v.cvss_score != null && (
                        <span className="text-slate-500"> · CVSS {v.cvss_score}</span>
                      )}
                      {v.remediation_advice && (
                        <span className="text-slate-400"> — {v.remediation_advice}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div id="remediation" className="card scroll-mt-24">
              <div className="flex items-center justify-between mb-3">
                <div className="font-semibold text-slate-200">Findings &amp; Remediation</div>
                <div className="flex items-center gap-3">
                  {remediations?.remediations?.some((r: any) => r.cli_steps?.length > 0) && (
                    <button
                      onClick={handleCreateChangeRequest}
                      disabled={creatingCr}
                      className="btn-primary text-xs px-3 py-1.5 disabled:opacity-50"
                      title="Bundle the synthesized CLI remediation into a Change Request — it still needs a Security Analyst or Admin to click Approve there before anything deploys."
                    >
                      {creatingCr ? "Creating…" : "Create Change Request →"}
                    </button>
                  )}
                  <span className="text-base text-slate-500">{scan.findings.length} total</span>
                </div>
              </div>
              {remediations === undefined && pipelineCompleted && (
                <div className="text-sm text-cyan-400 mb-3 border border-cyan-900/60 bg-cyan-950/20 rounded-lg px-3 py-2 flex items-center gap-2">
                  <span className="animate-pulse">●</span> Synthesizing AI remediation commands and control guidance...
                </div>
              )}
              {remediations === null && (
                <div className="text-sm text-amber-400 mb-3 border border-amber-900/60 bg-amber-950/20 rounded-lg px-3 py-2">
                  AI remediation suggestions could not be generated for this scan (the AI service may be
                  unreachable). Findings and their prose remediation guidance are still shown below; you can
                  still draft a Change Request manually from a finding's guidance text.
                </div>
              )}
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
                      // Previously this bailed out entirely (`return null`) for any
                      // finding without cli_steps -- which is every finding whose
                      // control has no validated CLI template and no successful AI
                      // synthesis (the common case, since the template library only
                      // covers a handful of control IDs). That silently dropped the
                      // finding's own prose `guidance` too, so most FAIL findings
                      // showed no remediation section at all. Now: show the CLI
                      // block when we have one, otherwise fall back to whatever
                      // guidance we do have (from the AI response, or the finding's
                      // own stored remediation text) rather than showing nothing.
                      const hasCli = !!r?.cli_steps?.length;
                      const guidance = r?.guidance || f.remediation;
                      if (!hasCli && !guidance) return null;
                      const isTemplate = !!r?.reference;
                      return (
                        <div className="mt-3 bg-slate-900/50 rounded p-2 border border-slate-800">
                          {hasCli && (
                            <>
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
                                  // Firmware advisories are deterministic facts from the
                                  // vulnerability DB, not commands to paste in -- style them
                                  // distinctly so they're never mistaken for the network fix.
                                  const isAdvisory = txt.startsWith("! [FIRMWARE ADVISORY]");
                                  return (
                                    <div
                                      key={idx}
                                      className={`font-mono text-sm whitespace-pre-wrap ${
                                        isAdvisory ? "text-amber-300/90 mt-1.5" : "text-emerald-300"
                                      }`}
                                    >
                                      {txt}
                                    </div>
                                  );
                                })}
                              </div>
                              {r.save_commands?.length > 0 && (
                                <div className="mt-2 pt-2 border-t border-slate-800/60 space-y-0.5">
                                  {r.save_commands.map((c: string, idx: number) => (
                                    <div key={idx} className="font-mono text-sm text-cyan-300/80 whitespace-pre-wrap"># {c}</div>
                                  ))}
                                </div>
                              )}
                            </>
                          )}
                          {!hasCli && (
                            <div className="text-base font-semibold text-amber-500 mb-2">
                              No validated CLI template for this control/vendor pair
                            </div>
                          )}
                          {guidance && (
                            <div className={`text-sm text-slate-400 ${hasCli ? "mt-2 border-t border-slate-800 pt-2" : ""}`}>{guidance}</div>
                          )}
                          <div className="text-[11px] text-amber-500/80 mt-2">{r?.note || "Requires human review before deployment."}</div>
                        </div>
                      );
                    })()}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="px-8 mt-4 pb-8 text-base text-slate-500">
            Report downloads are available above in <span className="text-slate-300">7 · Report Generation</span> once the pipeline completes.
          </div>
        </>
      )}
    </div>
  );
}