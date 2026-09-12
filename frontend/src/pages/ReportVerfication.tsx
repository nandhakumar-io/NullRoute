import { useEffect, useRef, useState } from "react";
import { endpoints, ReportVerifyResult, Scan } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

const STATUS_STYLE: Record<string, { badge: string; panel: string; label: string }> = {
  VERIFIED: {
    badge: "bg-emerald-500/20 text-emerald-400",
    panel: "bg-emerald-950/30 border-emerald-900",
    label: "Not Tampered — Verified",
  },
  TAMPERED: {
    badge: "bg-red-500/20 text-red-400",
    panel: "bg-red-950/30 border-red-900",
    label: "Tampered",
  },
  UNKNOWN_REPORT: {
    badge: "bg-amber-500/20 text-amber-400",
    panel: "bg-amber-950/30 border-amber-900",
    label: "Unknown Report",
  },
};

export default function ReportVerification() {
  const [file, setFile] = useState<File | null>(null);
  const [scanId, setScanId] = useState("");
  const [fmt, setFmt] = useState<"" | "pdf" | "json" | "csv">("");
  const [recentScans, setRecentScans] = useState<Scan[] | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<ReportVerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [recovering, setRecovering] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    endpoints.scans().then((r) => setRecentScans(r.data.slice(0, 25))).catch(() => setRecentScans([]));
  }, []);

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0] ?? null;
    setFile(f);
    setResult(null);
    setError(null);
    if (f) {
      const ext = f.name.toLowerCase().split(".").pop();
      if (ext === "pdf" || ext === "json" || ext === "csv") setFmt(ext);
    }
  }

  async function handleVerify() {
    if (!file) return;
    setVerifying(true);
    setError(null);
    setResult(null);
    try {
      const r = await endpoints.verifyReport(file, scanId || undefined, fmt || undefined);
      setResult(r.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Verification failed. Please try again.");
    } finally {
      setVerifying(false);
    }
  }

  async function handleRecover() {
    if (!result?.artifact) return;
    setRecovering(true);
    try {
      const resp = await endpoints.downloadOriginalReport(result.artifact.id);
      const source = resp.headers?.["x-report-source"] || resp.headers?.["X-Report-Source"];
      const blob = new Blob([resp.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `compliance-report-${result.scan_id?.slice(0, 8) || "original"}.${result.artifact.format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      if (source === "regenerated") {
        setError(
          "Note: the originally archived bytes were unavailable, so this file was freshly " +
          "regenerated from the scan's current data in the system — the compliance content is " +
          "authentic, but it may not be byte-identical to the file you originally downloaded " +
          "(e.g. a new timestamp)."
        );
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Could not recover the original report.");
    } finally {
      setRecovering(false);
    }
  }

  function reset() {
    setFile(null);
    setResult(null);
    setError(null);
    setScanId("");
    setFmt("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  const style = result ? STATUS_STYLE[result.status] : null;

  return (
    <div>
      <PageHeader
        title="Report Verification"
        subtitle="Upload a previously downloaded compliance report to confirm it hasn't been modified — checked against our archived copy and, where available, the Fabric-anchored evidence hash for that scan."
      />

      <div className="px-8 pb-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="card">
            <div className="font-semibold text-slate-200 mb-3">Upload Report</div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf,.json,.csv"
              onChange={handleFileChange}
              className="text-sm text-slate-300 mb-4"
            />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
              <div>
                <label className="block text-xs text-slate-500 mb-1">
                  Scan ID <span className="text-slate-600">(required for PDF/CSV, optional for JSON)</span>
                </label>
                <input
                  value={scanId}
                  onChange={(e) => setScanId(e.target.value)}
                  placeholder="e.g. 8f3a2c1e-…"
                  className="w-full bg-black/30 border border-soc-border rounded-lg px-3 py-2 text-sm font-mono text-slate-200"
                  list="recent-scan-ids"
                />
                <datalist id="recent-scan-ids">
                  {(recentScans || []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id} · {s.framework} · {new Date(s.created_at).toLocaleDateString()}
                    </option>
                  ))}
                </datalist>
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Format</label>
                <select
                  value={fmt}
                  onChange={(e) => setFmt(e.target.value as any)}
                  className="w-full bg-black/30 border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200"
                >
                  <option value="">Auto-detect from filename</option>
                  <option value="pdf">PDF</option>
                  <option value="json">JSON</option>
                  <option value="csv">CSV</option>
                </select>
              </div>
            </div>

            <div className="flex gap-2">
              <button onClick={handleVerify} disabled={!file || verifying} className="btn-primary text-sm">
                {verifying ? "Verifying…" : "Verify Report"}
              </button>
              {(file || result) && (
                <button onClick={reset} className="btn-secondary text-sm">Clear</button>
              )}
            </div>

            {error && <div className="text-xs text-amber-400 mt-3">{error}</div>}
          </div>

          {verifying && <Loading />}

          {result && style && (
            <div className={`card border ${style.panel}`}>
              <div className="flex items-center gap-3 mb-3">
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${style.badge}`}>
                  {style.label}
                </span>
                {result.artifact?.format && (
                  <span className="text-xs text-slate-500 uppercase">{result.artifact.format}</span>
                )}
              </div>
              <div className="text-sm text-slate-300">{result.message}</div>

              <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div>
                  <div className="text-slate-500 uppercase tracking-wide mb-1">Calculated Hash (uploaded file)</div>
                  <div className="font-mono text-slate-300 break-all">{result.calculated_hash}</div>
                </div>
                {result.artifact && (
                  <div>
                    <div className="text-slate-500 uppercase tracking-wide mb-1">Archived Hash (system of record)</div>
                    <div className="font-mono text-slate-300 break-all">{result.artifact.sha256}</div>
                  </div>
                )}
              </div>

              <div className="mt-4 flex items-center gap-2 text-xs">
                <span className="text-slate-500 uppercase tracking-wide">On-chain (Fabric) cross-check:</span>
                {result.fabric_checked ? (
                  <span className={result.fabric_match ? "text-emerald-400" : "text-red-400"}>
                    {result.fabric_match ? "Matches on-chain evidence hash" : "Does NOT match on-chain evidence hash"}
                  </span>
                ) : (
                  <span className="text-slate-500">
                    {result.fabric_status === "FABRIC_UNAVAILABLE"
                      ? "Fabric gateway unavailable — skipped"
                      : "Not applicable (Fabric anchoring not enabled for this scan)"}
                  </span>
                )}
              </div>

              {result.status === "TAMPERED" && (
                <div className="mt-5 pt-4 border-t border-red-900/50">
                  {result.downloadable ? (
                    <>
                      <div className="text-sm text-slate-300 mb-2">
                        The authentic report for this scan is still available in the system.
                      </div>
                      <button onClick={handleRecover} disabled={recovering} className="btn-primary text-sm">
                        {recovering ? "Recovering…" : "Download Authentic Report"}
                      </button>
                    </>
                  ) : (
                    <div className="text-sm text-amber-400">
                      The originally archived copy of this report is no longer available in storage, so it
                      cannot be recovered byte-for-byte. Re-generate a current report for this scan from the
                      Scan Detail page instead.
                    </div>
                  )}
                </div>
              )}

              {result.status === "UNKNOWN_REPORT" && (
                <div className="mt-4 text-xs text-slate-500">
                  Double-check the Scan ID, or re-download the report from the Scan Detail / Reports page so a
                  fresh archived copy exists to compare against.
                </div>
              )}
            </div>
          )}
        </div>

        <div className="card h-fit">
          <div className="font-semibold text-slate-200 mb-2 text-sm">How this works</div>
          <ol className="text-xs text-slate-400 space-y-2 list-decimal list-inside">
            <li>Every report generated by this system is archived (SHA-256 + object storage) at download time.</li>
            <li>When you upload a report here, we recompute its hash and compare it against that archive.</li>
            <li>
              If the scan's evidence is anchored on Hyperledger Fabric, we also re-verify against the
              immutable on-chain hash — catching tampering even if both the report and our own database
              copy were altered together.
            </li>
            <li>If tampering is detected and the original bytes are still archived, you can recover them here.</li>
          </ol>
        </div>
      </div>

      {recentScans && recentScans.length === 0 && (
        <div className="px-8 pb-8">
          <EmptyState message="No scans found yet — generate a report first from a completed scan." />
        </div>
      )}
    </div>
  );
}