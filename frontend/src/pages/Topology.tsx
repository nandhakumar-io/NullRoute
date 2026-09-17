import { useEffect, useState, useRef } from "react";
import { endpoints, Topology as TopologyData } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";
import ForceGraph2D from "react-force-graph-2d";

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
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  function refresh() {
    endpoints.topology().then((r) => setTopology(r.data));
  }

  useEffect(() => {
    refresh();
  }, []);

  if (!topology) return <Loading />;

  const { nodes, links } = topology;

  const graphData = {
    nodes: nodes.map(n => ({ ...n, val: 5 })),
    links: links.map(l => ({ ...l, source: l.source_device_id, target: l.target_device_id })),
  };

  const handleNodeClick = (node: any) => {
    setSelectedNode(node);
  };

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

    ctx.fillStyle = "rgba(15, 23, 42, 0.8)";
    ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, bckgDimensions[0], bckgDimensions[1]);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = color;
    ctx.fillText(label, node.x, node.y);
    
    // Draw icon indicator above text
    ctx.beginPath();
    ctx.arc(node.x, node.y - 6, 3, 0, 2 * Math.PI, false);
    ctx.fillStyle = color;
    ctx.fill();
  };

  return (
    <div className="h-full flex flex-col min-h-screen">
      <PageHeader
        title="Topology"
        subtitle="Devices and inferred adjacencies, derived from collected interface data (Phase 9)"
      />
      <div className="flex-1 px-8 pb-8 relative">
        <BuildTopologyPanel onBuilt={refresh} />
        {nodes.length === 0 ? (
          <EmptyState message="No devices yet. Upload configs above, or collect a configuration first." />
        ) : (
          <div className="h-[75vh] card p-0 border border-soc-border overflow-hidden rounded-xl bg-slate-900/50 flex">
            <div className="flex-1">
              <ForceGraph2D
                graphData={graphData}
                nodeCanvasObject={drawNode}
                onNodeClick={handleNodeClick}
                linkDirectionalArrowLength={3.5}
                linkDirectionalArrowRelPos={1}
                linkColor={() => "#475569"}
                backgroundColor="#0f172a"
              />
            </div>
            {selectedNode && (
              <div className="w-80 border-l border-soc-border bg-slate-900 p-4 transition-all overflow-y-auto">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-lg font-semibold text-slate-100">{selectedNode.hostname}</h3>
                  <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-white">x</button>
                </div>
                <div className="space-y-4">
                  <div>
                    <span className="text-xs text-slate-400 uppercase">Vendor Platform</span>
                    <p className="text-sm text-slate-200">{selectedNode.vendor}</p>
                  </div>
                  <div>
                    <span className="text-xs text-slate-400 uppercase">Integration Actions</span>
                    <div className="mt-2 space-y-2">
                       <button className="w-full py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md transition-colors">
                          Launch in GNS3 Lab
                       </button>
                       <button className="w-full py-2 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded-md transition-colors">
                          Mock Batfish Sandbox
                       </button>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}