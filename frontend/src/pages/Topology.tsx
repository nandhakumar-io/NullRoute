import { useEffect, useState, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  endpoints,
  Topology as TopologyData,
  NetworkInterface,
  ChangeRequest,
  BlastRadius,
  BlastRadiusSection,
  BlastRadiusNodeState,
} from "../api";
import { PageHeader, Loading, EmptyState, SeverityBadge } from "../components/ui";
import ForceGraph2D from "react-force-graph-2d";

/** Node ring colours for each projected post-deployment state. */
const STATE_STYLE: Record<
  BlastRadiusNodeState,
  { ring: string; label: string; pulse: boolean }
> = {
  isolated: { ring: "#ef4444", label: "Projected isolated / unreachable", pulse: true },
  violating: { ring: "#f59e0b", label: "Projected compliance violation", pulse: true },
  exposed: { ring: "#f59e0b", label: "New vulnerability exposure", pulse: false },
  unknown: { ring: "#64748b", label: "Not analyzed", pulse: false },
  ok: { ring: "#10b981", label: "No projected impact", pulse: false },
};

function SectionBlock({
  title,
  hint,
  section,
}: {
  title: string;
  hint: string;
  section: BlastRadiusSection | undefined;
}) {
  if (!section) return null;

  // "We didn't look" and "we looked and found nothing" are different
  // answers. Rendering NOT_ANALYZED as a clean green tick is how a
  // reviewer approves a change that locks them out.
  if (section.status === "NOT_ANALYZED") {
    return (
      <div className="rounded-lg border border-slate-600/50 bg-slate-800/30 p-3">
        <div className="text-xs font-semibold text-slate-300">{title}</div>
        <div className="mt-1.5 flex items-start gap-2">
          <span className="text-amber-400 text-xs mt-px">⚠</span>
          <div className="text-xs text-slate-400">
            <span className="text-amber-400 font-medium">Not analyzed.</span>{" "}
            {section.reason}
          </div>
        </div>
      </div>
    );
  }

  if (section.items.length === 0) {
    return (
      <div className="rounded-lg border border-emerald-800/40 bg-emerald-950/20 p-3">
        <div className="text-xs font-semibold text-slate-300">{title}</div>
        <div className="mt-1 text-xs text-emerald-400">No impact detected.</div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-soc-border bg-soc-panel/50 p-3">
      <div className="flex items-center justify-between">
        <div className="text-xs font-semibold text-slate-300">{title}</div>
        <span className="text-[10px] text-slate-500">{section.items.length}</span>
      </div>
      <div className="text-[10px] text-slate-500 mt-0.5">{hint}</div>
      <div className="mt-2 space-y-2">
        {section.items.map((item, i) => (
          <div key={i} className="rounded border border-soc-border/70 bg-slate-900/50 p-2">
            <div className="flex items-start gap-2">
              <SeverityBadge severity={item.severity as any} />
              <div className="min-w-0 flex-1">
                <div className="text-xs text-slate-200 break-words">{item.label}</div>
                {item.before && item.after && (
                  <div className="mt-0.5 text-[10px] font-mono text-slate-400">
                    {item.before} → <span className="text-red-400">{item.after}</span>
                  </div>
                )}
                {item.config_line && (
                  <div className="mt-1 text-[10px] font-mono text-slate-400 break-all">
                    <span className={item.change === "removed" ? "text-red-400" : "text-amber-400"}>
                      {item.change === "removed" ? "− " : "+ "}
                    </span>
                    {item.config_line}
                  </div>
                )}
                {item.why && <div className="mt-1 text-[10px] text-slate-500">{item.why}</div>}
                {(item.control_id || item.source) && (
                  <div className="mt-1 flex gap-1.5 text-[10px] text-slate-600">
                    {item.control_id && <span className="font-mono">{item.control_id}</span>}
                    {item.source && <span>· via {item.source}</span>}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function BlastRadiusPanel({
  blast,
  loading,
  error,
  onClose,
}: {
  blast: BlastRadius | null;
  loading: boolean;
  error: string | null;
  onClose: () => void;
}) {
  return (
    <div className="w-96 shrink-0 border-l border-soc-border bg-slate-900/80 backdrop-blur-md overflow-y-auto">
      <div className="sticky top-0 z-10 flex items-center justify-between px-4 py-3 border-b border-soc-border bg-slate-900/90 backdrop-blur">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">Blast Radius</h3>
          <p className="text-[10px] text-slate-500">Projected impact of the selected change</p>
        </div>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-200 text-sm px-1">
          ✕
        </button>
      </div>

      <div className="p-4 space-y-3">
        {loading && <div className="text-xs text-slate-500">Loading projected impact…</div>}
        {error && <div className="text-xs text-red-400">{error}</div>}

        {blast && !loading && (
          <>
            <div className="rounded-lg border border-soc-border bg-soc-panel/60 p-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">
                  Decision
                </span>
                <span
                  className={`badge ${
                    blast.final_decision === "BLOCK"
                      ? "badge-fail"
                      : blast.final_decision === "REVIEW"
                        ? "badge-na"
                        : "badge-pass"
                  }`}
                >
                  {blast.final_decision || "—"}
                </span>
              </div>
              {blast.final_reason && (
                <div className="mt-1.5 text-[11px] text-slate-400">{blast.final_reason}</div>
              )}
              <div className="mt-2 flex gap-3 text-[10px] text-slate-500">
                <span>
                  Risk:{" "}
                  <span className="text-slate-300">
                    {blast.risk_level || "—"}
                    {blast.risk_score != null && ` (${blast.risk_score})`}
                  </span>
                </span>
                <span>
                  Device: <span className="text-slate-300">{blast.hostname || blast.device_id}</span>
                </span>
              </div>
            </div>

            {blast.summary.fully_unanalyzed ? (
              <div className="rounded-lg border border-amber-700/50 bg-amber-950/20 p-3">
                <div className="text-xs text-amber-300 font-medium">
                  No impact analysis available
                </div>
                <div className="mt-1 text-[11px] text-slate-400">
                  None of the three checks could run for this change request, so its blast radius
                  is <span className="text-amber-300">unknown</span> — not empty. Treat this as
                  unreviewed.
                </div>
              </div>
            ) : (
              <div className="flex gap-1.5 flex-wrap">
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) =>
                  blast.summary.severity_counts[s] ? (
                    <span key={s} className="flex items-center gap-1">
                      <SeverityBadge severity={s as any} />
                      <span className="text-[10px] text-slate-400">
                        ×{blast.summary.severity_counts[s]}
                      </span>
                    </span>
                  ) : null,
                )}
              </div>
            )}

            <SectionBlock
              title="1 · New Vulnerability Exposure"
              hint="Dangerous protocols enabled, or protective controls removed (config diff)."
              section={blast.vulnerability_exposure}
            />
            <SectionBlock
              title="2 · Compliance Violations"
              hint="OPA and Batfish verdicts recorded at validation time."
              section={blast.compliance_violations}
            />
            <SectionBlock
              title="3 · Reachability Severance"
              hint="Flows reachable before this change but not after (Batfish dataplane)."
              section={blast.reachability_severance}
            />
          </>
        )}
      </div>
    </div>
  );
}

function BuildTopologyPanel({ onBuilt }: { onBuilt: () => void }) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [groupName, setGroupName] = useState("Demo Network Block");
  const [status, setStatus] = useState<"idle" | "uploading" | "grouping" | "scanning" | "done" | "error">("idle");
  const [log, setLog] = useState<string[]>([]);
  const [result, setResult] = useState<any>(null);

  function addLog(line: string) {
    setLog((l) => [...l, line]);
  }

  async function buildAndScan() {
    if (files.length === 0) return;
    setLog([]);
    setResult(null);
    try {
      setStatus("uploading");
      addLog(`Uploading ${files.length} configuration file(s)…`);
      const uploadRes = await endpoints.bulkUploadConfigs(files);
      const deviceIds = uploadRes.data.map((s) => s.device_id);
      addLog(`Created ${deviceIds.length} device(s) from uploaded configs.`);

      setStatus("grouping");
      const groupRes = await endpoints.createTopologyGroup({
        name: groupName || "Demo Network Block",
        description: "Auto-built from uploaded configs for a Batfish demo run.",
        device_ids: deviceIds,
      });
      addLog(`Created network group "${groupRes.data.name}" with ${deviceIds.length} member device(s).`);

      setStatus("scanning");
      addLog("Running Batfish analysis over the group snapshot…");
      const scanRes = await endpoints.scanTopologyGroup(groupRes.data.id);
      setResult(scanRes.data);
      addLog(`Batfish scan complete — status: ${scanRes.data.status}.`);

      setStatus("done");
      setFiles([]);
      if (fileInputRef.current) fileInputRef.current.value = "";
      onBuilt();
    } catch (e: any) {
      addLog(e?.response?.data?.detail || "Failed to build/scan the topology.");
      setStatus("error");
    }
  }

  const busy = status === "uploading" || status === "grouping" || status === "scanning";

  return (
    <div className="card mb-4">
      <div className="font-semibold text-slate-200 mb-1">Build a Batfish Topology from Configs</div>
      <div className="text-xs text-slate-500 mb-3">
        Upload two or more vendor configs (see <code className="font-mono">sample_configs/</code> for
        ready-made multi-vendor examples) to create devices, group them into one Batfish snapshot, and
        run the built-in segmentation checks — no live device access required.
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".cfg,.conf,.txt,.xml,.json"
          onChange={(e) => setFiles(Array.from(e.target.files || []))}
          className="text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:bg-cyan-950 file:text-cyan-300 file:text-xs"
        />
        <input
          className="input text-sm w-56"
          placeholder="Network group name"
          value={groupName}
          onChange={(e) => setGroupName(e.target.value)}
        />
        <button
          onClick={buildAndScan}
          disabled={files.length === 0 || busy}
          className="btn-primary text-sm disabled:opacity-40"
        >
          {busy ? "Working…" : `Build + Scan (${files.length} file${files.length === 1 ? "" : "s"})`}
        </button>
      </div>
      {log.length > 0 && (
        <div className="mt-3 space-y-1 font-mono text-xs text-slate-400 border-t border-soc-border pt-2">
          {log.map((line, i) => <div key={i}>› {line}</div>)}
        </div>
      )}
      {result && (
        <div className="mt-2 text-xs text-slate-400">
          Scanned {result.scanned_devices?.length ?? 0} device(s)
          {result.skipped_devices?.length > 0 && `, skipped ${result.skipped_devices.length}`} ·{" "}
          {result.reachability_checks?.length ?? 0} segmentation check(s) evaluated.
        </div>
      )}
    </div>
  );
}

export default function Topology() {
  const navigate = useNavigate();
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [nodeInterfaces, setNodeInterfaces] = useState<NetworkInterface[] | null>(null);
  const [discovering, setDiscovering] = useState(false);
  const [discoverMsg, setDiscoverMsg] = useState<string | null>(null);
  const [isDark, setIsDark] = useState(() => document.documentElement.classList.contains("dark"));

  // --- Pre/Post deployment evaluation -------------------------------------
  const [view, setView] = useState<"pre" | "post">("pre");
  const [changeRequests, setChangeRequests] = useState<ChangeRequest[] | null>(null);
  const [selectedCrId, setSelectedCrId] = useState<string>("");
  const [blast, setBlast] = useState<BlastRadius | null>(null);
  const [blastLoading, setBlastLoading] = useState(false);
  const [blastError, setBlastError] = useState<string | null>(null);
  const [showPanel, setShowPanel] = useState(true);
  // Drives the pulsing ring animation on at-risk nodes.
  const [pulse, setPulse] = useState(0);

  function refresh() {
    endpoints.topology().then((r) => setTopology(r.data));
  }

  useEffect(() => {
    refresh();
    // The graph is drawn on a <canvas>, which CSS can't repaint the way it
    // does the rest of the page's Tailwind classes -- watch the `dark`
    // class on <html> (toggled by the app's theme switcher) so the canvas
    // background/text actually follow light/dark mode too.
    const observer = new MutationObserver(() => setIsDark(document.documentElement.classList.contains("dark")));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!selectedNode) { setNodeInterfaces(null); return; }
    endpoints.deviceInterfaces(selectedNode.id).then((r) => setNodeInterfaces(r.data)).catch(() => setNodeInterfaces([]));
  }, [selectedNode]);

  // Change requests that are still pending a decision are the ones worth
  // evaluating on the canvas -- an already-deployed CR has no "projected"
  // state left to show.
  useEffect(() => {
    if (view !== "post" || changeRequests !== null) return;
    endpoints
      .changeRequests({ status: "PENDING_APPROVAL" })
      .then((r) => {
        setChangeRequests(r.data.change_requests);
        if (r.data.change_requests.length > 0) setSelectedCrId(r.data.change_requests[0].id);
      })
      .catch(() => setChangeRequests([]));
  }, [view, changeRequests]);

  useEffect(() => {
    if (view !== "post" || !selectedCrId) { setBlast(null); return; }
    setBlastLoading(true);
    setBlastError(null);
    endpoints
      .changeRequestBlastRadius(selectedCrId)
      .then((r) => setBlast(r.data))
      .catch((e: any) =>
        setBlastError(e?.response?.data?.detail || "Could not load the projected impact."),
      )
      .finally(() => setBlastLoading(false));
  }, [view, selectedCrId]);

  // Pulse ticker. Only runs while there's something at risk to pulse, so the
  // canvas isn't repainting 8x/sec for no reason.
  const hasPulsingNodes = useMemo(
    () =>
      view === "post" &&
      (blast?.node_states || []).some((n) => STATE_STYLE[n.state]?.pulse),
    [view, blast],
  );
  useEffect(() => {
    if (!hasPulsingNodes) return;
    const id = setInterval(() => setPulse((p) => p + 1), 120);
    return () => clearInterval(id);
  }, [hasPulsingNodes]);

  // nodeStateMap must be declared before any early returns
  const nodeStateMap = useMemo(() => {
    const map = new Map<string, BlastRadiusNodeState>();
    if (view !== "post" || !blast) return map;
    for (const ns of blast.node_states) {
      if (ns.device_id) map.set(ns.device_id, ns.state);
      if (ns.hostname) map.set(`host:${ns.hostname}`, ns.state);
    }
    return map;
  }, [view, blast]);

  if (!topology) return <Loading />;

  const { nodes, links } = topology;

  const graphData = {
    nodes: nodes.map(n => ({ ...n, val: 5 })),
    links: links.map(l => ({ ...l, source: l.source_device_id, target: l.target_device_id })),
  };

  const handleNodeClick = (node: any) => {
    setSelectedNode(node);
    setDiscoverMsg(null);
  };

  async function discoverNeighbors(deviceId: string) {
    setDiscovering(true);
    setDiscoverMsg(null);
    try {
      const res = await endpoints.gatewayGetNeighbors(deviceId);
      const count = res.data.normalized_data?.neighbor_count ?? res.data.normalized_data?.neighbors?.length ?? 0;
      const stored = res.data.links_stored ?? 0;
      setDiscoverMsg(
        count === 0
          ? "No LLDP neighbors reported by this device (LLDP may be disabled, or SNMP access isn't configured)."
          : `Found ${count} neighbor(s), matched ${stored} to known device(s) and saved as real links.`
      );
      refresh();
    } catch (e: any) {
      setDiscoverMsg(e?.response?.data?.detail?.error_message || e?.response?.data?.detail || "Neighbor discovery failed — check the device's SNMP credentials.");
    } finally {
      setDiscovering(false);
    }
  }

  const bg = isDark ? "#0f172a" : "#f5f6f9";
  const nodeChipBg = isDark ? "rgba(15, 23, 42, 0.85)" : "rgba(255, 255, 255, 0.92)";
  const nodeTextFallback = isDark ? "#e2e8f0" : "#171b26";
  const linkColorObserved = isDark ? "#22d3ee" : "#28406f";
  const linkColorInferred = isDark ? "#475569" : "#b7bdcc";

  function stateForNode(node: any): BlastRadiusNodeState | null {
    if (view !== "post" || !blast) return null;
    return (
      nodeStateMap.get(node.id) ??
      (node.hostname ? nodeStateMap.get(`host:${node.hostname}`) : undefined) ??
      "ok"
    );
  }

  const drawNode = (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const label = node.hostname || "Unknown";
    const fontSize = 12 / globalScale;
    ctx.font = `${fontSize}px Sans-Serif`;
    const textWidth = ctx.measureText(label).width;
    const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

    // Vendor specific colors
    let color = "#3b82f6"; // Default Blue (Cisco/Network)
    if (node.vendor === "AWS" || node.vendor === "GCP" || node.vendor === "Azure") {
      color = "#eab308"; // Cloud yellow
    } else if (node.vendor === "Unknown") {
      color = "#ef4444"; // Red for unknown/k8s
    }

    // --- Projected post-deployment risk ring ---
    const riskState = stateForNode(node);
    const style = riskState ? STATE_STYLE[riskState] : null;
    if (style && riskState !== "ok") {
      const baseR = Math.max(bckgDimensions[0], bckgDimensions[1]) / 1.6 + 4 / globalScale;
      // Pulse between 0 and 1 using the ticker; static states sit mid-range.
      const phase = style.pulse ? (Math.sin(pulse / 3) + 1) / 2 : 0.5;

      if (style.pulse) {
        // Outer halo that breathes outward.
        ctx.beginPath();
        ctx.arc(node.x, node.y, baseR + phase * (7 / globalScale), 0, 2 * Math.PI);
        ctx.fillStyle = `${style.ring}${Math.round((0.28 - phase * 0.2) * 255)
          .toString(16)
          .padStart(2, "0")}`;
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, baseR, 0, 2 * Math.PI);
      ctx.strokeStyle = style.ring;
      ctx.lineWidth = (style.pulse ? 1.6 + phase * 1.4 : 1.4) / globalScale;
      ctx.stroke();
    }

    ctx.fillStyle = nodeChipBg;
    ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, bckgDimensions[0], bckgDimensions[1]);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = color || nodeTextFallback;
    ctx.fillText(label, node.x, node.y);

    // Draw icon indicator above text
    ctx.beginPath();
    ctx.arc(node.x, node.y - 6, 3, 0, 2 * Math.PI, false);
    ctx.fillStyle = style && riskState !== "ok" ? style.ring : color;
    ctx.fill();
  };

  return (
    <div className="h-full flex flex-col min-h-screen">
      <PageHeader
        title="Topology"
        subtitle={
          topology.has_interface_data
            ? `${topology.observed_link_count ?? 0} SNMP/LLDP-observed link(s), ${topology.inferred_link_count ?? 0} subnet-inferred`
            : "Devices and adjacencies, derived from collected interface data (Phase 9)"
        }
      />
      <div className="flex-1 px-8 pb-8 relative">
        <BuildTopologyPanel onBuilt={refresh} />
        {nodes.length === 0 ? (
          <EmptyState message="No devices yet. Upload configs above, or collect a configuration first." />
        ) : !topology.has_interface_data ? (
          <EmptyState message="Devices exist but no interface data has been extracted yet. Run a scan (or collect a config via the gateway) so vendor interfaces/VLANs can be parsed, then reload this page." />
        ) : (
          <>
            {/* Pre/Post deployment state switch */}
            <div className="flex items-center gap-3 mb-3 flex-wrap">
              <div className="inline-flex rounded-lg border border-soc-border bg-soc-panel/60 backdrop-blur p-0.5">
                {(
                  [
                    ["pre", "Pre-Deployment State"],
                    ["post", "Simulated Post-Deployment"],
                  ] as const
                ).map(([key, label]) => (
                  <button
                    key={key}
                    onClick={() => setView(key)}
                    className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
                      view === key
                        ? "bg-cyan-600/90 text-white shadow-[0_0_16px_rgba(6,182,212,0.25)]"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {view === "post" && (
                <>
                  {changeRequests === null ? (
                    <span className="text-xs text-slate-500">Loading change requests…</span>
                  ) : changeRequests.length === 0 ? (
                    <span className="text-xs text-amber-400">
                      No change requests are pending approval — nothing to project.
                    </span>
                  ) : (
                    <select
                      className="bg-soc-panel border border-soc-border rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-600"
                      value={selectedCrId}
                      onChange={(e) => {
                        setSelectedCrId(e.target.value);
                        setShowPanel(true);
                      }}
                    >
                      {changeRequests.map((cr) => (
                        <option key={cr.id} value={cr.id}>
                          {cr.id.slice(0, 8)} · {cr.final_decision || cr.status}
                          {cr.risk_level ? ` · ${cr.risk_level}` : ""}
                        </option>
                      ))}
                    </select>
                  )}
                  {blast && !showPanel && (
                    <button
                      onClick={() => setShowPanel(true)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
                    >
                      Show blast radius
                    </button>
                  )}
                </>
              )}
            </div>

            <div className="flex items-center gap-3 mb-3 text-xs flex-wrap">
              <span className="flex items-center gap-1.5 text-slate-500">
                <span className="inline-block w-4 h-0.5" style={{ background: linkColorObserved }} /> SNMP/LLDP-observed
              </span>
              <span className="flex items-center gap-1.5 text-slate-500">
                <span className="inline-block w-4 h-0.5 border-t border-dashed" style={{ borderColor: linkColorInferred }} /> subnet-inferred
              </span>
              {view === "post" && blast && (
                <>
                  <span className="text-slate-700">|</span>
                  {(["isolated", "violating", "exposed", "unknown"] as const).map((s) => (
                    <span key={s} className="flex items-center gap-1.5 text-slate-500">
                      <span
                        className="inline-block w-2.5 h-2.5 rounded-full border-2"
                        style={{ borderColor: STATE_STYLE[s].ring }}
                      />
                      {STATE_STYLE[s].label}
                    </span>
                  ))}
                </>
              )}
            </div>
            <div className="h-[75vh] card p-0 border border-soc-border overflow-hidden rounded-xl flex">
              <div className="flex-1">
                <ForceGraph2D
                  graphData={graphData}
                  nodeCanvasObject={drawNode}
                  onNodeClick={handleNodeClick}
                  linkDirectionalArrowLength={3.5}
                  linkDirectionalArrowRelPos={1}
                  linkColor={(l: any) => (l.link_type === "lldp_observed" ? linkColorObserved : linkColorInferred)}
                  linkLineDash={(l: any) => (l.link_type === "lldp_observed" ? null : [2, 2])}
                  backgroundColor={bg}
                />
              </div>
              {selectedNode && (
                <div className="w-80 border-l border-soc-border bg-slate-900 p-4 transition-all overflow-y-auto">
                  <div className="flex justify-between items-center mb-4">
                    <h3 className="text-lg font-semibold text-slate-100">{selectedNode.hostname}</h3>
                    <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-200">x</button>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <span className="text-xs text-slate-400 uppercase">Vendor Platform</span>
                      <p className="text-sm text-slate-200">{selectedNode.vendor || "Unknown"}</p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-400 uppercase">Management Address</span>
                      <p className="text-sm text-slate-200 font-mono">{selectedNode.management_address || "—"}</p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-400 uppercase">Interfaces ({nodeInterfaces?.length ?? "…"})</span>
                      {nodeInterfaces === null ? (
                        <p className="text-xs text-slate-500 mt-1">Loading…</p>
                      ) : nodeInterfaces.length === 0 ? (
                        <p className="text-xs text-slate-500 mt-1 italic">No interfaces extracted from this device's config yet.</p>
                      ) : (
                        <div className="mt-1 space-y-1 max-h-48 overflow-y-auto">
                          {nodeInterfaces.map(i => (
                            <div key={i.id} className="text-xs bg-slate-800/60 rounded px-2 py-1">
                              <span className="font-mono text-cyan-400">{i.name}</span>
                              {i.ip_address && <span className="text-slate-400"> · {i.ip_address}{i.subnet_mask ? `/${i.subnet_mask}` : ""}</span>}
                              {i.admin_state && <span className={i.admin_state === "down" ? " text-red-400" : " text-emerald-400"}> · {i.admin_state}</span>}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div>
                      <span className="text-xs text-slate-400 uppercase">Actions</span>
                      <div className="mt-2 space-y-2">
                        <button
                          onClick={() => discoverNeighbors(selectedNode.id)}
                          disabled={discovering}
                          className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm rounded-md transition-colors disabled:opacity-50"
                        >
                          {discovering ? "Discovering…" : "📡 Discover Neighbors (SNMP/LLDP)"}
                        </button>
                        <button
                          onClick={() => navigate("/gns3-integration")}
                          className="w-full py-2 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded-md transition-colors"
                        >
                          Launch in GNS3 Lab
                        </button>
                      </div>
                      {discoverMsg && <p className="mt-2 text-xs text-slate-400">{discoverMsg}</p>}
                    </div>
                  </div>
                </div>
              )}
              {view === "post" && showPanel && selectedCrId && (
                <BlastRadiusPanel
                  blast={blast}
                  loading={blastLoading}
                  error={blastError}
                  onClose={() => setShowPanel(false)}
                />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}