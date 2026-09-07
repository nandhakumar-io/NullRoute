import { useEffect, useState, useRef } from "react";
import { endpoints, Topology as TopologyData } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";
import ForceGraph2D from "react-force-graph-2d";

export default function Topology() {
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  useEffect(() => {
    endpoints.topology().then((r) => setTopology(r.data));
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
        {nodes.length === 0 ? (
          <EmptyState message="No devices yet. Upload or collect a configuration first." />
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
