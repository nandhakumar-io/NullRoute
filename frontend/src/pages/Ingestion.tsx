import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { endpoints } from "../api";
import { PageHeader } from "../components/ui";

const FRAMEWORKS = ["ALL", "CIS", "NIST-800-53", "DISA-STIG", "ISO-27001"];

export default function Ingestion() {
  const [file, setFile] = useState<File | null>(null);
  const [framework, setFramework] = useState("ALL");
  const [hostname, setHostname] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [status, setStatus] = useState<"idle" | "uploading" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState("");
  const navigate = useNavigate();

  async function handleUpload() {
    if (!file) return;
    setStatus("uploading");
    try {
      const res = await endpoints.uploadConfig(file, framework, hostname || undefined);
      navigate(`/scans/${res.data.id}`);
    } catch (e: any) {
      setStatus("error");
      setErrorMsg(e?.response?.data?.detail || "Upload failed");
    }
  }

  return (
    <div>
      <PageHeader title="Configuration Ingestion" subtitle="Upload a device configuration to run the full detection → normalization → compliance pipeline" />
      <div className="px-8 max-w-2xl space-y-5">
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0]);
          }}
          className={`card border-2 border-dashed text-center py-12 cursor-pointer transition-colors ${
            dragOver ? "border-cyan-500 bg-cyan-950/20" : "border-soc-border"
          }`}
          onClick={() => document.getElementById("file-input")?.click()}
        >
          <input
            id="file-input"
            type="file"
            className="hidden"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
          {file ? (
            <div>
              <div className="text-slate-200 font-medium">{file.name}</div>
              <div className="text-slate-500 text-sm mt-1">{(file.size / 1024).toFixed(1)} KB — click to change</div>
            </div>
          ) : (
            <div>
              <div className="text-slate-300 font-medium">Drag & drop a configuration file here</div>
              <div className="text-slate-500 text-sm mt-1">or click to browse (.cfg, .txt, .json, .conf)</div>
            </div>
          )}
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">Hostname (optional override)</label>
          <input
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            placeholder="Auto-detected if left blank"
            className="w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600"
          />
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">Compliance framework</label>
          <select
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
            className="w-full bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600"
          >
            {FRAMEWORKS.map((f) => (
              <option key={f} value={f}>{f}</option>
            ))}
          </select>
        </div>

        <button
          onClick={handleUpload}
          disabled={!file || status === "uploading"}
          className="btn-primary disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {status === "uploading" ? "Running pipeline…" : "Upload & Scan"}
        </button>

        {status === "error" && <div className="text-red-400 text-sm">{errorMsg}</div>}

        <div className="text-xs text-slate-500 pt-4 border-t border-soc-border">
          Pipeline: vendor/OS detection → deterministic parsing → AI/RAG normalization of unknown syntax →
          Security Baseline Model → OPA/Rego + rule-engine compliance evaluation. The LLM never issues the
          final PASS/FAIL verdict.
        </div>
      </div>
    </div>
  );
}
