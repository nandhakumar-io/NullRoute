import React, { useState, useEffect } from "react";
import { endpoints } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

export default function Gns3Integration() {
  const [servers, setServers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [newServer, setNewServer] = useState({ name: "", url: "http://localhost:3080", username: "", password: "" });
  
  const [selectedServer, setSelectedServer] = useState<string | null>(null);
  const [labs, setLabs] = useState<any[]>([]);
  const [loadingLabs, setLoadingLabs] = useState(false);
  const [importing, setImporting] = useState<string | null>(null); // lab_id

  function loadServers() {
    setLoading(true);
    endpoints.gns3Servers().then((r) => {
      setServers(r.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }

  useEffect(() => { loadServers(); }, []);

  async function handleAddServer(e: React.FormEvent) {
    e.preventDefault();
    try {
      await endpoints.addGns3Server(newServer);
      setShowAdd(false);
      setNewServer({ name: "", url: "http://localhost:3080", username: "", password: "" });
      loadServers();
    } catch (e: any) {
      alert("Failed to add server: " + e.message);
    }
  }

  async function handleSelectServer(id: string) {
    setSelectedServer(id);
    setLoadingLabs(true);
    try {
      const res = await endpoints.gns3Labs(id);
      setLabs(res.data);
    } catch {
      alert("Failed to load labs");
    } finally {
      setLoadingLabs(false);
    }
  }

  async function handleImportLab(labId: string) {
    if (!selectedServer) return;
    setImporting(labId);
    try {
      await endpoints.importGns3Lab(selectedServer, labId);
      alert("Topology devices successfully imported!");
    } catch {
      alert("Failed to import topology devices");
    } finally {
      setImporting(null);
    }
  }

  if (loading) return <Loading />;

  return (
    <div>
      <PageHeader
        title="GNS3 Integration"
        subtitle="Synchronize NetSecAuditor with live GNS3 validation sandboxes."
        action={
          <button onClick={() => setShowAdd(!showAdd)} className="btn-primary">
            {showAdd ? "Cancel" : "Add GNS3 Server"}
          </button>
        }
      />

      <div className="p-8 max-w-6xl mx-auto space-y-6">
        {showAdd && (
          <div className="card p-6 bg-slate-800/50">
            <h3 className="text-lg font-bold text-slate-100 mb-4">Add GNS3 Server</h3>
            <form onSubmit={handleAddServer} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1">Server Name</label>
                  <input required value={newServer.name} onChange={e => setNewServer({...newServer, name: e.target.value})} className="input w-full" placeholder="Internal GNS3 Node 1" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1">API URL</label>
                  <input required value={newServer.url} onChange={e => setNewServer({...newServer, url: e.target.value})} className="input w-full" placeholder="http://localhost:3080" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1">Username (Optional)</label>
                  <input value={newServer.username} onChange={e => setNewServer({...newServer, username: e.target.value})} className="input w-full" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1">Password (Optional)</label>
                  <input type="password" value={newServer.password} onChange={e => setNewServer({...newServer, password: e.target.value})} className="input w-full" />
                </div>
              </div>
              <div className="flex justify-end pt-2">
                <button type="submit" className="btn-primary">Connect Server</button>
              </div>
            </form>
          </div>
        )}

        {servers.length === 0 ? (
          <EmptyState message="No GNS3 Servers Configured. Connect a GNS3 server to start importing live topologies for Batfish validation." />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <div className="lg:col-span-1 space-y-2">
              <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-4">Configured Servers</h3>
              {servers.map(s => (
                <button
                  key={s.id}
                  onClick={() => handleSelectServer(s.id)}
                  className={`w-full text-left p-4 rounded-xl border transition-colors ${selectedServer === s.id ? 'bg-cyan-900/30 border-cyan-500' : 'bg-soc-panel border-soc-border hover:border-slate-600'}`}
                >
                  <div className="font-bold text-slate-200">{s.name}</div>
                  <div className="text-xs text-slate-500 mt-1 truncate">{s.url}</div>
                </button>
              ))}
            </div>

            <div className="lg:col-span-3">
              {!selectedServer ? (
                <div className="h-full flex items-center justify-center text-slate-500 bg-soc-panel border border-soc-border rounded-xl min-h-[300px]">
                  Select a server to view active simulated labs
                </div>
              ) : loadingLabs ? (
                <div className="h-full flex items-center justify-center p-12 bg-soc-panel border border-soc-border rounded-xl">
                  <div className="animate-spin w-8 h-8 rounded-full border-4 border-cyan-500/30 border-t-cyan-500"></div>
                </div>
              ) : labs.length === 0 ? (
                <EmptyState message="There are no projects/labs available on this GNS3 server." />
              ) : (
                <div className="card">
                  <h3 className="text-lg font-bold text-slate-200 mb-4">Available GNS3 Labs</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {labs.map(lab => (
                      <div key={lab.project_id} className="p-4 border border-slate-700/50 bg-slate-800/30 rounded-lg">
                        <div className="flex justify-between items-start mb-2">
                          <h4 className="font-semibold text-cyan-300">{lab.name}</h4>
                          <span className={`px-2 py-0.5 rounded text-xs ${lab.status === 'opened' ? 'bg-emerald-900/40 text-emerald-400' : 'bg-slate-700 text-slate-300'}`}>
                            {lab.status}
                          </span>
                        </div>
                        <div className="text-xs text-slate-400 mb-4 truncate text-opacity-80 font-mono">
                          {lab.project_id}
                        </div>
                        <button
                          onClick={() => handleImportLab(lab.project_id)}
                          disabled={importing === lab.project_id}
                          className="w-full btn-primary text-sm flex items-center justify-center"
                        >
                          {importing === lab.project_id ? (
                            <>
                              <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                              Importing...
                            </>
                          ) : (
                            "Import to NetSecAuditor & Scan"
                          )}
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
