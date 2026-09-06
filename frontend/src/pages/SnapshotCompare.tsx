import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { endpoints, ConfigSnapshotDetail, SecurityDriftFinding } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

const DRIFT_TYPE_STYLE: Record<string, string> = {
  SECURITY_DEGRADATION: "badge-critical",
  SECURITY_IMPROVEMENT: "badge-low",
  COMPLIANCE_IMPACT: "badge-high",
  CONFIGURATION_CHANGE: "badge-na",
  UNKNOWN_IMPACT: "badge-medium",
  NO_CHANGE: "badge-na",
};

/** Flattens a nested object into dotted-path -> value pairs, the same shape
 * SecurityBaselineModel.flatten() produces server-side, so the raw-JSON
 * fallback diff (used only if a normalized drift-history row doesn't cover
 * a parameter) lines up with the same dotted paths. */
function flatten(obj: unknown, prefix = "", out: Record<string, unknown> = {}): Record<string, unknown> {
  if (obj !== null && typeof obj === "object" && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      flatten(v, prefix ? `${prefix}.${k}` : k, out);
    }
  } else {
    out[prefix] = obj;
  }
  return out;
}

export default function SnapshotCompare() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const [params] = useSearchParams();
  const snapshotA = params.get("a");
  const snapshotB = params.get("b");

  const [a, setA] = useState<ConfigSnapshotDetail | null>(null);
  const [b, setB] = useState<ConfigSnapshotDetail | null>(null);
  const [driftFindings, setDriftFindings] = useState<SecurityDriftFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!deviceId || !snapshotA || !snapshotB) return;
    setLoading(true);
    setError(null);
    Promise.all([
      endpoints.deviceSnapshot(deviceId, snapshotA),
      endpoints.deviceSnapshot(deviceId, snapshotB),
      endpoints.deviceDriftHistory(deviceId),
    ])
      .then(([ra, rb, rd]) => {
        setA(ra.data);
        setB(rb.data);
        // Keep only findings for exactly this snapshot pair, in either
        // direction (the compare UI doesn't force chronological order).
        setDriftFindings(
          rd.data.findings.filter(
            (f) =>
              (f.previous_scan_id === ra.data.scan_id && f.current_scan_id === rb.data.scan_id) ||
              (f.previous_scan_id === rb.data.scan_id && f.current_scan_id === ra.data.scan_id),
          ),
        );
      })
      .catch(() => setError("Could not load one or both snapshots."))
      .finally(() => setLoading(false));
  }, [deviceId, snapshotA, snapshotB]);

  if (!snapshotA || !snapshotB) {
    return <EmptyState message="Select two snapshots from the device's Configuration History to compare." />;
  }
  if (loading) return <Loading />;
  if (error || !a || !b) return <EmptyState message={error || "Snapshot not found."} />;

  // Raw config diff at the parameter level, using the same dotted-path
  // baseline shape the backend's SecurityBaselineModel.flatten() uses --
  // this is a client-side convenience view; the authoritative
  // classification/severity/OPA-correlation for the SAME pair (when it
  // exists) comes from driftFindings above.
  const flatA = flatten(a.baseline || {});
  const flatB = flatten(b.baseline || {});
  const allParams = Array.from(new Set([...Object.keys(flatA), ...Object.keys(flatB)])).sort();
  const changedParams = allParams.filter((p) => JSON.stringify(flatA[p]) !== JSON.stringify(flatB[p]));

  const findingByParam = new Map(driftFindings.map((f) => [f.baseline_parameter, f]));

  return (
    <div>
      <PageHeader
        title="Compare Snapshots"
        subtitle={deviceId ? <Link className="text-cyan-400 hover:underline text-xs" to={`/devices/${deviceId}`}>← back to device</Link> : undefined}
      />
      <div className="px-8 pb-8 space-y-6">
        <div className="grid grid-cols-2 gap-4">
          {[a, b].map((s, idx) => (
            <div key={s.snapshot_id} className="card">
              <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">
                Snapshot {idx === 0 ? "A" : "B"}
              </div>
              <div className="text-sm font-mono mt-1 text-slate-200">
                {s.collected_at ? new Date(s.collected_at).toLocaleString() : "—"}
              </div>
              <div className="text-xs font-mono mt-1 text-slate-500 truncate">{s.configuration_hash}</div>
              <div className="text-xs text-slate-500 mt-1">
                {s.compliance_score != null ? `${s.compliance_score}% compliant` : "no score"} ·{" "}
                {s.final_decision || "—"}
                {s.is_approved_baseline && " · APPROVED BASELINE"}
              </div>
            </div>
          ))}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Security Baseline Diff ({changedParams.length} changed)</div>
          {changedParams.length === 0 ? (
            <div className="text-sm text-slate-500">No parameter differences between these two snapshots.</div>
          ) : (
            <div className="space-y-2">
              {changedParams.map((p) => {
                const finding = findingByParam.get(p);
                const driftType = finding?.drift_type || "CONFIGURATION_CHANGE";
                return (
                  <div key={p} className="flex items-start justify-between border-b border-soc-border/50 pb-2 last:border-0 text-sm">
                    <div>
                      <div className="font-mono text-slate-300">{p}</div>
                      <div className="text-xs text-slate-500">
                        Previous: <span className="text-slate-400">{JSON.stringify(flatA[p])}</span>{"  "}
                        Current: <span className="text-slate-400">{JSON.stringify(flatB[p])}</span>
                      </div>
                      {finding?.compliance_controls?.length ? (
                        <div className="text-xs text-slate-500 mt-1">
                          Controls: {finding.compliance_controls.join(", ")}
                        </div>
                      ) : null}
                    </div>
                    <span className={`badge ${DRIFT_TYPE_STYLE[driftType] || "badge-na"}`}>
                      {finding?.severity ? `${finding.severity} · ` : ""}
                      {driftType.replace(/_/g, " ")}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="card">
          <div className="font-semibold text-slate-200 mb-3">Raw Configuration</div>
          <div className="text-xs text-slate-500 mb-2">
            Full raw text is stored in object storage; open each snapshot's underlying scan for the full config and line-level diff.
          </div>
          <div className="flex gap-4 text-sm">
            <Link className="text-cyan-400 hover:underline" to={`/scans/${a.scan_id}`}>
              View scan A
            </Link>
            <Link className="text-cyan-400 hover:underline" to={`/scans/${b.scan_id}`}>
              View scan B
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}