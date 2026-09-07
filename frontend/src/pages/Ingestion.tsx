import { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { endpoints, Device } from "../api";
import { PageHeader } from "../components/ui";

const FRAMEWORKS = ["ALL", "CIS", "NIST-800-53", "DISA-STIG", "ISO-27001"];

const PROTOCOL_INFO: { key: string; label: string; desc: string }[] = [
  { key: "ssh", label: "SSH (CLI)", desc: "Vendor CLI scrape over SSH — the default for most switches/routers/firewalls." },
  { key: "netconf", label: "NETCONF", desc: "XML/YANG config pull over NETCONF (port 830)." },
  { key: "restconf", label: "RESTCONF", desc: "REST/YANG config pull over HTTPS." },
  { key: "snmp", label: "SNMP", desc: "Read-only polling via community/v3 credentials for facts and interface state." },
  { key: "gnmi", label: "gNMI", desc: "Streaming gRPC telemetry/config for supporting platforms." },
];

type Mode = "upload" | "live";

function LiveCollectionPanel() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [protocol, setProtocol] = useState("");
  const [busy, setBusy] = useState<"test" | "collect" | "scan" | null>(null);
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    endpoints.devices({ limit: 500 }).then((r) => {
      const items = (r.data as any).items ?? r.data;
      setDevices(Array.isArray(items) ? items : []);
    }).catch(() => setDevices([]));
  }, []);

  const selected = devices?.find((d) => d.id === selectedId) || null;

  const run = async (action: "test" | "collect" | "scan") => {
    if (!selectedId) return;
    setBusy(action);
    setResult(null);
    try {
      if (action === "test") {
        const r = await endpoints.testDeviceConnection(selectedId, protocol || undefined);
        setResult({ success: r.data.success, message: r.data.success
          ? `Reachable via ${r.data.transport} (${r.data.duration_ms}ms)`
          : r.data.error || "Connection test failed" });
      } else if (action === "collect") {
        const r = await endpoints.collectDeviceConfig(selectedId, protocol || undefined);
        setResult({ success: r.data.success, message: r.data.success
          ? `Collected via ${r.data.transport} — config_hash ${r.data.config_hash?.slice(0, 12)}…`
          : r.data.error || "Collection failed" });
      } else {
        const r = await endpoints.collectAndScanDevice(selectedId, "ALL", protocol || undefined);
        navigate(`/scans/${r.data.id}`);
        return;
      }
    } catch (err: any) {
      setResult({ success: false, message: err?.response?.data?.detail || err?.response?.data?.error || "Request failed" });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {PROTOCOL_INFO.map((p) => (
          <div key={p.key} className="card py-3">
            <div className="text-sm font-semibold text-slate-200 uppercase">{p.label}</div>
            <div className="text-xs text-slate-500 mt-1">{p.desc}</div>
          </div>
        ))}
      </div>

      <div className="card space-y-4">
        <div className="text-sm font-semibold text-slate-200">Pull configuration from an inventory device</div>
        {devices && devices.length === 0 ? (
          <div className="text-sm text-slate-500">
            No devices in inventory yet. <Link to="/devices" className="text-cyan-400 hover:underline">Add one</Link> or run{" "}
            <Link to="/network-scans?tab=discovery" className="text-cyan-400 hover:underline">Network Discovery</Link> first.
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">Device</label>
                <select className="select w-full" value={selectedId} onChange={(e) => { setSelectedId(e.target.value); setResult(null); }}>
                  <option value="">-- Select a device --</option>
                  {devices?.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.hostname || d.name || d.management_address} {d.management_address ? `(${d.management_address})` : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">
                  Protocol {selected?.protocol ? `(device default: ${selected.protocol})` : ""}
                </label>
                <select className="select w-full" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                  <option value="">Use device default / auto-detect</option>
                  {PROTOCOL_INFO.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
                </select>
              </div>
            </div>

            <div className="flex flex-wrap gap-3">
              <button className="btn-secondary" disabled={!selectedId || !!busy} onClick={() => run("test")}>
                {busy === "test" ? "Testing…" : "Test Connection"}
              </button>
              <button className="btn-secondary" disabled={!selectedId || !!busy} onClick={() => run("collect")}>
                {busy === "collect" ? "Collecting…" : "Collect Configuration"}
              </button>
              <button className="btn-primary" disabled={!selectedId || !!busy} onClick={() => run("scan")}>
                {busy === "scan" ? "Running…" : "Collect & Run Compliance Scan"}
              </button>
            </div>

            {result && (
              <div className={`text-sm rounded-lg px-3 py-2 border ${result.success
                ? "text-emerald-300 bg-emerald-950/40 border-emerald-800"
                : "text-red-400 bg-red-950/40 border-red-800"}`}>
                {result.message}
              </div>
            )}
          </>
        )}
        <p className="text-xs text-slate-500 pt-2 border-t border-soc-border">
          Credentials for SSH/SNMP live collection are attached per-device on the{" "}
          <Link to="/devices" className="text-cyan-400 hover:underline">Devices</Link> page (Add/Edit Device →
          Authentication) and are stored in OpenBao Vault, never in the browser.
        </p>
      </div>
    </div>
  );
}

export default function Ingestion() {
  const [mode, setMode] = useState<Mode>("upload");
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
      <PageHeader
        title="Configuration Ingestion"
        subtitle="Every way a device's configuration gets into the pipeline: manual upload, or live pull over SSH / NETCONF / RESTCONF / SNMP / gNMI"
      />
      <div className="px-8 max-w-2xl">
        <div className="flex gap-1 border-b border-soc-border mb-5">
          <button
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              mode === "upload" ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
            onClick={() => setMode("upload")}
          >
            Upload Config File
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              mode === "live" ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
            onClick={() => setMode("live")}
          >
            Live Device Collection (SSH / NETCONF / RESTCONF / SNMP / gNMI)
          </button>
        </div>

        {mode === "upload" ? (
          <div className="space-y-5">
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
                accept=".cfg,.txt,.json,.conf"
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
          </div>
        ) : (
          <LiveCollectionPanel />
        )}

        <div className="text-xs text-slate-500 pt-6 mt-6 border-t border-soc-border">
          Pipeline: vendor/OS detection → deterministic parsing → AI/RAG normalization of unknown syntax →
          Security Baseline Model → OPA/Rego + rule-engine compliance evaluation. The LLM never issues the
          final PASS/FAIL verdict. Every ingestion path — upload or live pull — feeds this same pipeline, so a
          device collected via SSH/SNMP/NETCONF shows up on its Device Detail page exactly like an uploaded config.
        </div>
      </div>
    </div>
  );
}