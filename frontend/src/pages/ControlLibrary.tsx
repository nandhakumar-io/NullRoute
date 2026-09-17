import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  endpoints,
  UnifiedControl,
  ControlReview,
  VendorConfigPattern,
  DocumentIngestionJob,
} from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

const STATUS_TONE: Record<string, string> = {
  pending_review: "bg-amber-500/20 text-amber-400",
  approved: "bg-emerald-500/20 text-emerald-400",
};

function StatusPill({ status }: { status: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs ${STATUS_TONE[status] || "bg-slate-500/20 text-slate-300"}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

export default function ControlLibrary() {
  const [activeTab, setActiveTab] = useState<"library" | "ingestion">("library");

  return (
    <div>
      <PageHeader
        title="Unified Control Library"
        subtitle="Multi-framework control knowledge base (SCF/UCF/OSCAL-inspired) that enriches OPA policies with traceability."
      />

      <div className="px-8 pb-4 border-b border-soc-border mb-6 flex gap-6">
        <button
          onClick={() => setActiveTab("library")}
          className={`pb-2 font-medium ${activeTab === "library" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Control Library
        </button>
        <button
          onClick={() => setActiveTab("ingestion")}
          className={`pb-2 font-medium ${activeTab === "ingestion" ? "text-cyan-400 border-b-2 border-cyan-400" : "text-slate-400 hover:text-slate-200"}`}
        >
          Document Ingestion
        </button>
      </div>

      <div className="px-8 pb-8">
        {activeTab === "library" ? <ControlLibraryTab /> : <DocumentIngestionTab />}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Control Library tab
// ---------------------------------------------------------------------------

function ControlLibraryTab() {
  const [controls, setControls] = useState<UnifiedControl[] | null>(null);
  const [pendingReviews, setPendingReviews] = useState<ControlReview[] | null>(null);
  const [domainFilter, setDomainFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [patternsByControl, setPatternsByControl] = useState<Record<string, VendorConfigPattern[]>>({});
  const [compiling, setCompiling] = useState<string | null>(null);
  const [compileResult, setCompileResult] = useState<Record<string, string>>({});

  // Tag Pattern modal state
  const [tagModalControlId, setTagModalControlId] = useState<string | null>(null);
  const [tagConceptName, setTagConceptName] = useState("");
  const [tagVendor, setTagVendor] = useState("cisco");
  const [tagPattern, setTagPattern] = useState("");
  const [tagExampleLine, setTagExampleLine] = useState("");
  const [tagSaving, setTagSaving] = useState(false);

  function load() {
    endpoints
      .controls({ domain: domainFilter || undefined, status: statusFilter || undefined })
      .then((r) => setControls(r.data.controls));
    endpoints.pendingReviews().then((r) => setPendingReviews(r.data.reviews));
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domainFilter, statusFilter]);

  async function toggleExpand(control: UnifiedControl) {
    if (expandedId === control.id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(control.id);
    if (!patternsByControl[control.id]) {
      const r = await endpoints.controlPatterns(control.id);
      setPatternsByControl((prev) => ({ ...prev, [control.id]: r.data.patterns }));
    }
  }

  async function decide(review: ControlReview, decision: "approved" | "rejected") {
    await endpoints.decideReview(review.control_id, { decision });
    load();
  }

  async function compile(controlId: string) {
    setCompiling(controlId);
    setCompileResult((prev) => ({ ...prev, [controlId]: "" }));
    try {
      const r = await endpoints.compileControl(controlId);
      const compiled = (r.data as any)?.compiled ?? [];
      setCompileResult((prev) => ({
        ...prev,
        [controlId]: compiled.length
          ? `Compiled for ${compiled.map((c: any) => c.vendor).join(", ")}`
          : "Compiled",
      }));
    } catch (err: any) {
      setCompileResult((prev) => ({
        ...prev,
        [controlId]: err?.response?.data?.detail || "Compilation failed",
      }));
    } finally {
      setCompiling(null);
    }
  }

  function openTagModal(controlId: string) {
    setTagModalControlId(controlId);
    setTagConceptName("");
    setTagVendor("cisco");
    setTagPattern("");
    setTagExampleLine("");
  }

  async function saveTagPattern() {
    if (!tagModalControlId || !tagConceptName || !tagPattern) return;
    setTagSaving(true);
    try {
      await endpoints.addControlPattern(tagModalControlId, {
        concept_name: tagConceptName,
        vendor: tagVendor,
        pattern: tagPattern,
        example_snippet: tagExampleLine || undefined,
      });
      const r = await endpoints.controlPatterns(tagModalControlId);
      setPatternsByControl((prev) => ({ ...prev, [tagModalControlId]: r.data.patterns }));
      setTagModalControlId(null);
    } finally {
      setTagSaving(false);
    }
  }

  const filtered = (controls || []).filter((c) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return c.name.toLowerCase().includes(s) || (c.objective || "").toLowerCase().includes(s);
  });

  return (
    <div>
      {pendingReviews && pendingReviews.length > 0 && (
        <div className="mb-6 card border-amber-800/50">
          <div className="font-semibold text-amber-400 mb-3">
            Pending Reviews ({pendingReviews.length})
          </div>
          <div className="space-y-2">
            {pendingReviews.map((r) => (
              <div key={r.id} className="border border-soc-border rounded-lg p-3 flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-slate-500">{r.reviewer} · {r.created_at ? new Date(r.created_at).toLocaleString() : ""}</div>
                  {r.proposed_change && <div className="text-sm text-slate-300 mt-1">{r.proposed_change}</div>}
                  {r.original_text && (
                    <div className="text-xs text-slate-500 mt-1 line-clamp-2">{r.original_text}</div>
                  )}
                </div>
                <div className="flex gap-2 shrink-0">
                  <button onClick={() => decide(r, "approved")} className="btn-primary text-xs">Approve</button>
                  <button onClick={() => decide(r, "rejected")} className="btn-secondary text-xs">Reject</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mb-6 flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by name or objective…"
          className="flex-1 min-w-[220px] bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200"
        />
        <input
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
          placeholder="Filter by domain (e.g. logging)"
          className="w-56 bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200"
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="w-48 bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200"
        >
          <option value="">All statuses</option>
          <option value="pending_review">Pending review</option>
          <option value="approved">Approved</option>
        </select>
      </div>

      {!controls ? (
        <Loading />
      ) : filtered.length === 0 ? (
        <EmptyState message="No controls found. Ingest a document to extract controls, or adjust your filters." />
      ) : (
        <div className="space-y-3">
          {filtered.map((c) => (
            <div key={c.id} className="card">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0 cursor-pointer" onClick={() => toggleExpand(c)}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-slate-200">{c.name}</span>
                    <StatusPill status={c.status} />
                    {c.domain && <span className="text-xs text-slate-500 font-mono">{c.domain}</span>}
                  </div>
                  {c.objective && <div className="text-sm text-slate-400 mt-1">{c.objective}</div>}
                  {c.framework_mappings && c.framework_mappings.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {c.framework_mappings.map((m) => (
                        <span key={m.id} className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                          {m.framework}: {m.external_id}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex flex-col gap-2 shrink-0 w-40">
                  <Link to={`/control-library/${c.id}`} className="btn-secondary text-xs w-full text-center">
                    View Detail →
                  </Link>
                  <button onClick={() => openTagModal(c.id)} className="btn-secondary text-xs w-full">
                    Tag Pattern
                  </button>
                  {c.status === "approved" && (
                    <button
                      onClick={() => compile(c.id)}
                      disabled={compiling === c.id}
                      className="btn-primary text-xs w-full"
                    >
                      {compiling === c.id ? "Compiling…" : "Compile Policy"}
                    </button>
                  )}
                  {compileResult[c.id] && (
                    <div className="text-[11px] text-slate-400 text-center">{compileResult[c.id]}</div>
                  )}
                </div>
              </div>

              {expandedId === c.id && (
                <div className="mt-4 pt-4 border-t border-soc-border">
                  <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">
                    Vendor Config Patterns
                  </div>
                  {!patternsByControl[c.id] ? (
                    <Loading />
                  ) : patternsByControl[c.id].length === 0 ? (
                    <div className="text-xs text-slate-500">No patterns tagged yet for this control.</div>
                  ) : (
                    <div className="space-y-1.5">
                      {patternsByControl[c.id].map((p) => (
                        <div key={p.id} className="text-xs font-mono flex items-center gap-3 bg-black/30 rounded px-2 py-1.5">
                          <span className="text-cyan-400 shrink-0">{p.vendor}</span>
                          <span className="text-emerald-300 truncate">{p.pattern}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {c.normalized_description && (
                    <div className="mt-3">
                      <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-1">
                        Normalized Description
                      </div>
                      <div className="text-sm text-slate-400">{c.normalized_description}</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {tagModalControlId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
          <div className="bg-soc-panel border border-soc-border rounded-xl p-6 w-full max-w-md">
            <div className="font-semibold text-slate-200 mb-4">Tag Config Pattern</div>
            <label className="block text-xs text-slate-500 mb-1">Concept name</label>
            <input
              value={tagConceptName}
              onChange={(e) => setTagConceptName(e.target.value)}
              placeholder="e.g. mgmt_protocol, idle_timeout, logging_server"
              className="w-full bg-black/30 border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 mb-3"
            />
            <label className="block text-xs text-slate-500 mb-1">Vendor</label>
            <select
              value={tagVendor}
              onChange={(e) => setTagVendor(e.target.value)}
              className="w-full bg-black/30 border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 mb-3"
            >
              <option value="cisco">Cisco</option>
              <option value="juniper">Juniper</option>
              <option value="paloalto">Palo Alto</option>
              <option value="fortinet">Fortinet</option>
              <option value="arista">Arista</option>
            </select>
            <label className="block text-xs text-slate-500 mb-1">Pattern (regex)</label>
            <input
              value={tagPattern}
              onChange={(e) => setTagPattern(e.target.value)}
              placeholder="e.g. ^transport input ssh$"
              className="w-full bg-black/30 border border-soc-border rounded-lg px-3 py-2 text-sm font-mono text-emerald-300 mb-3"
            />
            <label className="block text-xs text-slate-500 mb-1">Example config line (optional)</label>
            <input
              value={tagExampleLine}
              onChange={(e) => setTagExampleLine(e.target.value)}
              placeholder="Paste the unrecognized config line here"
              className="w-full bg-black/30 border border-soc-border rounded-lg px-3 py-2 text-sm font-mono text-slate-300 mb-4"
            />
            <div className="flex justify-end gap-2">
              <button onClick={() => setTagModalControlId(null)} className="btn-secondary text-sm">Cancel</button>
              <button
                onClick={saveTagPattern}
                disabled={tagSaving || !tagConceptName || !tagPattern}
                className="btn-primary text-sm"
              >
                {tagSaving ? "Saving…" : "Save Pattern"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Document Ingestion tab
// ---------------------------------------------------------------------------

function DocumentIngestionTab() {
  const [jobs, setJobs] = useState<DocumentIngestionJob[]>([]);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

  function pollJob(jobId: string) {
    const interval = window.setInterval(async () => {
      try {
        const r = await endpoints.ingestionStatus(jobId);
        setJobs((prev) => {
          const idx = prev.findIndex((j) => j.id === jobId);
          const next = [...prev];
          if (idx >= 0) next[idx] = r.data;
          else next.unshift(r.data);
          return next;
        });
        if (["completed", "failed"].includes(r.data.status)) {
          window.clearInterval(interval);
        }
      } catch {
        window.clearInterval(interval);
      }
    }, 2500);
  }

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const r = await endpoints.ingestDocument(file);
      setJobs((prev) => [r.data, ...prev]);
      pollJob(r.data.id);
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  return (
    <div>
      <div className="card mb-6">
        <div className="font-semibold text-slate-200 mb-2">Upload a Framework Document</div>
        <div className="text-xs text-slate-500 mb-4">
          PDF, HTML, or XCCDF. Controls are extracted with the configured LLM and stored as pending-review
          UnifiedControl rows; if the LLM is unavailable, ingestion falls back to section-header-only chunking
          and flags the job with a warning rather than failing silently.
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept=".pdf,.html,.htm,.xml,.xccdf"
          onChange={handleUpload}
          disabled={uploading}
          className="text-sm text-slate-300"
        />
        {uploading && <div className="text-xs text-cyan-400 mt-2">Uploading…</div>}
      </div>

      {jobs.length === 0 ? (
        <EmptyState message="No document ingestion jobs yet. Upload a document above to get started." />
      ) : (
        <div className="overflow-hidden rounded-lg border border-soc-border">
          <table className="w-full text-left text-sm text-slate-400">
            <thead className="bg-soc-panel border-b border-soc-border uppercase text-xs">
              <tr>
                <th className="px-4 py-3">File</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">LLM Used</th>
                <th className="px-4 py-3">Sections</th>
                <th className="px-4 py-3">Controls Created</th>
                <th className="px-4 py-3">Warning</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {jobs.map((j) => (
                <tr key={j.id} className="hover:bg-soc-panel">
                  <td className="px-4 py-3 text-slate-200">{j.filename}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-0.5 rounded text-xs ${
                        j.status === "completed"
                          ? "bg-emerald-500/20 text-emerald-400"
                          : j.status === "failed"
                          ? "bg-red-500/20 text-red-400"
                          : "bg-amber-500/20 text-amber-400"
                      }`}
                    >
                      {j.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">{j.llm_used ? "Yes" : "No (fallback)"}</td>
                  <td className="px-4 py-3">{j.sections_found}</td>
                  <td className="px-4 py-3">{j.controls_created}</td>
                  <td className="px-4 py-3 text-amber-400 text-xs">{j.warning || j.error || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}