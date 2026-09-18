import { SnapshotDiff, BatfishFlowDiff } from "../api";
import { SeverityBadge } from "./ui";

// Renders the CURRENT-vs-PROPOSED Batfish snapshot diff attached to a
// ChangeRequest as a visual delta -- topology node changes, route count
// delta, differential reachability, and any per-control flow impact --
// instead of dumping the raw JSON on the reviewer.

function StatusLine({ status, detail }: { status: string; detail?: string | null }) {
  const tone =
    status === "COMPLETED" || status === "OK"
      ? "text-emerald-400"
      : status === "FAILED" || status === "ERROR"
      ? "text-red-400"
      : "text-amber-400";
  return (
    <div className="text-xs">
      <span className={`font-semibold ${tone}`}>{status.replace(/_/g, " ")}</span>
      {detail && <span className="text-slate-500 ml-2">{detail}</span>}
    </div>
  );
}

function NodeDeltaPanel({ delta }: { delta: NonNullable<SnapshotDiff["node_delta"]> }) {
  if (delta.added.length === 0 && delta.removed.length === 0) {
    return <div className="text-xs text-slate-500">No topology node changes.</div>;
  }
  return (
    <div className="grid grid-cols-2 gap-4">
      <div>
        <div className="text-xs uppercase tracking-wide text-emerald-500 font-semibold mb-1">
          Added ({delta.added.length})
        </div>
        {delta.added.length === 0 ? (
          <div className="text-xs text-slate-600">—</div>
        ) : (
          <ul className="space-y-0.5">
            {delta.added.map((n) => (
              <li key={n} className="text-xs font-mono text-emerald-300">+ {n}</li>
            ))}
          </ul>
        )}
      </div>
      <div>
        <div className="text-xs uppercase tracking-wide text-red-500 font-semibold mb-1">
          Removed ({delta.removed.length})
        </div>
        {delta.removed.length === 0 ? (
          <div className="text-xs text-slate-600">—</div>
        ) : (
          <ul className="space-y-0.5">
            {delta.removed.map((n) => (
              <li key={n} className="text-xs font-mono text-red-300">− {n}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function RouteDeltaPanel({ delta }: { delta: NonNullable<SnapshotDiff["route_delta"]> }) {
  const sign = delta.count_delta > 0 ? "+" : "";
  const tone = delta.count_delta === 0 ? "text-slate-300" : delta.count_delta > 0 ? "text-emerald-400" : "text-red-400";
  return (
    <div className="flex items-center gap-6 text-sm">
      <div>
        <div className="text-xs text-slate-500">Current routes</div>
        <div className="font-mono text-slate-200">{delta.current_count}</div>
      </div>
      <div className="text-slate-600">→</div>
      <div>
        <div className="text-xs text-slate-500">Proposed routes</div>
        <div className="font-mono text-slate-200">{delta.proposed_count}</div>
      </div>
      <div>
        <div className="text-xs text-slate-500">Delta</div>
        <div className={`font-mono font-semibold ${tone}`}>{sign}{delta.count_delta}</div>
      </div>
    </div>
  );
}

function FlowDiffRow({ f }: { f: BatfishFlowDiff }) {
  const stateBadge = (v: "REACHABLE" | "BLOCKED" | "UNKNOWN") =>
    v === "REACHABLE" ? "badge-pass" : v === "BLOCKED" ? "badge-fail" : "badge-na";
  const resultTone =
    f.result === "CRITICAL NETWORK IMPACT" ? "text-red-400" : f.result === "NETWORK IMPACT" ? "text-amber-400" : "text-slate-500";
  return (
    <tr className={f.changed ? "bg-amber-950/10" : undefined}>
      <td className="px-3 py-2 text-xs text-slate-300">{f.title}</td>
      <td className="px-3 py-2 text-xs font-mono text-slate-400">{f.source_zone} → {f.destination_zone}</td>
      <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
      <td className="px-3 py-2"><span className={`badge ${stateBadge(f.before)}`}>{f.before}</span></td>
      <td className="px-3 py-2"><span className={`badge ${stateBadge(f.after)}`}>{f.after}</span></td>
      <td className={`px-3 py-2 text-xs font-semibold ${resultTone}`}>{f.result}</td>
    </tr>
  );
}

export default function BatfishDeltaView({ diff }: { diff: SnapshotDiff }) {
  if (diff.status !== "COMPLETED" && diff.status !== "OK") {
    return (
      <div className="card">
        <StatusLine status={diff.status} detail={diff.detail} />
      </div>
    );
  }

  const changedFlows = (diff.flow_diffs || []).filter((f) => f.changed);
  const criticalCount = changedFlows.filter((f) => f.result === "CRITICAL NETWORK IMPACT").length;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <StatusLine status={diff.status} detail={diff.network_name ? `network: ${diff.network_name}` : undefined} />
        {criticalCount > 0 && (
          <span className="badge badge-critical">{criticalCount} critical network impact{criticalCount === 1 ? "" : "s"}</span>
        )}
      </div>

      {diff.node_delta && (
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-3">Topology Changes</div>
          <NodeDeltaPanel delta={diff.node_delta} />
        </div>
      )}

      {diff.route_delta && (
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-3">Route Table Impact</div>
          <RouteDeltaPanel delta={diff.route_delta} />
        </div>
      )}

      {diff.differential_reachability && (
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">Differential Reachability</div>
          <StatusLine status={diff.differential_reachability.status} detail={diff.differential_reachability.detail} />
          {typeof diff.differential_reachability.changed_flow_count === "number" && (
            <div className="text-xs text-slate-400 mt-1">
              {diff.differential_reachability.changed_flow_count} flow(s) changed reachability
              {diff.differential_reachability.method ? ` (via ${diff.differential_reachability.method})` : ""}
            </div>
          )}
        </div>
      )}

      {diff.flow_diffs && diff.flow_diffs.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-soc-border">
          <table className="w-full text-left text-sm text-slate-400">
            <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
              <tr>
                <th className="px-3 py-2">Control</th>
                <th className="px-3 py-2">Flow</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Before</th>
                <th className="px-3 py-2">After</th>
                <th className="px-3 py-2">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {diff.flow_diffs.map((f) => (
                <FlowDiffRow key={f.control_id} f={f} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!diff.node_delta && !diff.route_delta && !diff.differential_reachability && (!diff.flow_diffs || diff.flow_diffs.length === 0) && (
        <div className="text-xs text-slate-500">Batfish diff completed with no reportable deltas.</div>
      )}
    </div>
  );
}