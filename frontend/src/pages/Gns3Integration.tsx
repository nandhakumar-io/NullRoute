import React, { useState, useEffect } from "react";
import { endpoints } from "../api";
import { PageHeader, Loading, EmptyState } from "../components/ui";

export default function Gns3Integration() {
  const [servers, setServers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [newServer, setNewServer] = useState({ name: "", url: "http://localhost:3080", username: "", password: "" });
  
  const [selectedServer, setSelectedServer] = useState<string | null>(null);
  const [pingStatus, setPingStatus] = useState<any>(null);

  const [labs, setLabs] = useState<any[]>([]);
  const [loadingLabs, setLoadingLabs] = useState(false);
  
  const [selectedLab, setSelectedLab] = useState<string | null>(null);
  const [topology, setTopology] = useState<{nodes: any[], links: any[]} | null>(null);
  const [loadingTopology, setLoadingTopology] = useState(false);
  
  const [selectedNodes, setSelectedNodes] = useState<Set<string>>(new Set());
  const [importing, setImporting] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

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

  async function handleDeleteServer(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    if (!confirm("Are you sure you want to remove this GNS3 server?")) return;
    try {
      await endpoints.deleteGns3Server(id);
      if (selectedServer === id) setSelectedServer(null);
      loadServers();
    } catch {
      alert("Failed to delete server");
    }
  }

  async function handleSelectServer(id: string) {
    setSelectedServer(id);
    setSelectedLab(null);
    setTopology(null);
    setLoadingLabs(true);
    setPingStatus(null);
    
    // Fire and forget ping
    endpoints.pingGns3Server(id).then(r => setPingStatus(r.data)).catch(() => setPingStatus({reachable: false}));
    
    try {
      const res = await endpoints.gns3Labs(id);
      setLabs(res.data);
    } catch {
      alert("Failed to load labs");
    } finally {
      setLoadingLabs(false);
    }
  }

  async function handleViewTopology(labId: string) {
    if (!selectedServer) return;
    setSelectedLab(labId);
    setLoadingTopology(true);
    setSelectedNodes(new Set());
    try {
      const res = await endpoints.gns3Topology(selectedServer, labId);
      setTopology(res.data);
      // Auto-select all nodes that aren't already imported and aren't infra
      const skippable = ["cloud", "ethernet_switch", "frame_relay_switch", "nat", "ethernet_hub"];
      const toSelect = new Set<string>();
      res.data.nodes.forEach((n: any) => {
        if (!n.already_imported && !skippable.includes(n.node_type)) {
          toSelect.add(n.node_id);
        }
      });
      setSelectedNodes(toSelect);
    } catch {
      alert("Failed to load topology");
      setSelectedLab(null);
    } finally {
      setLoadingTopology(false);
    }
  }

  async function handleLabAction(labId: string, action: 'start' | 'stop') {
    if (!selectedServer) return;
    setActionLoading(`${action}-${labId}`);
    try {
      if (action === 'start') {
        await endpoints.startGns3Lab(selectedServer, labId);
      } else {
        await endpoints.stopGns3Lab(selectedServer, labId);
      }
      // Reload labs to get updated status
      const res = await endpoints.gns3Labs(selectedServer);
      setLabs(res.data);
      if (selectedLab === labId) {
         handleViewTopology(labId);
      }
    } catch (e: any) {
      alert(`Failed to ${action} lab`);
    } finally {
      setActionLoading(null);
    }
  }

  async function handleImportSelected() {
    if (!selectedServer || !selectedLab) return;
    setImporting(true);
    try {
      const res = await endpoints.importGns3Lab(selectedServer, selectedLab, Array.from(selectedNodes));
      alert(`Successfully imported ${res.data.imported} devices! Go to Device Inventory to scan them.`);
      // Reload topology to update the "already_imported" badges
      handleViewTopology(selectedLab);
    } catch {
      alert("Failed to import topology devices");
    } finally {
      setImporting(false);
    }
  }
  
  function toggleNode(nodeId: string) {
    const next = new Set(selectedNodes);
    if (next.has(nodeId)) next.delete(nodeId);
    else next.add(nodeId);
    setSelectedNodes(next);
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

      <div className="p-8 max-w-[1400px] mx-auto space-y-6">
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
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
            
            {/* SERVERS COLUMN */}
            <div className="lg:col-span-1 space-y-2 sticky top-[100px]">
              <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-4">Configured Servers</h3>
              {servers.map(s => (
                <div
                  key={s.id}
                  onClick={() => handleSelectServer(s.id)}
                  className={`w-full text-left p-4 rounded-xl border transition-colors cursor-pointer group ${selectedServer === s.id ? 'bg-cyan-900/40 border-cyan-500 shadow-[0_0_15px_var(--cyan-glow)]' : 'bg-soc-panel border-soc-border hover:border-slate-500'}`}
                >
                  <div className="flex justify-between items-start">
                    <div className="font-bold text-slate-200">{s.name}</div>
                    <button 
                      onClick={(e) => handleDeleteServer(s.id, e)}
                      className="text-slate-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                    </button>
                  </div>
                  <div className="text-xs text-slate-500 mt-1 truncate">{s.url}</div>
                  
                  {selectedServer === s.id && pingStatus && (
                    <div className="mt-3 text-xs pt-3 border-t border-slate-700/50">
                      {pingStatus.reachable ? (
                        <div className="flex items-center text-emerald-400">
                          <span className="w-2 h-2 rounded-full bg-emerald-500 mr-2 shadow-[0_0_5px_#10b981]"></span>
                          Connected (v{pingStatus.version}) • {pingStatus.latency_ms}ms
                        </div>
                      ) : (
                        <div className="flex items-center text-rose-400">
                          <span className="w-2 h-2 rounded-full bg-rose-500 mr-2 shadow-[0_0_5px_#f43f5e]"></span>
                          Unreachable
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* LABS OR TOPOLOGY COLUMN */}
            <div className="lg:col-span-3">
              {!selectedServer ? (
                <div className="h-full flex items-center justify-center text-slate-500 bg-soc-panel border border-soc-border rounded-xl min-h-[400px]">
                  Select a server to view active projects
                </div>
              ) : loadingLabs ? (
                <div className="h-full flex items-center justify-center p-12 bg-soc-panel border border-soc-border rounded-xl min-h-[400px]">
                  <div className="animate-spin w-8 h-8 rounded-full border-4 border-cyan-500/30 border-t-cyan-500"></div>
                </div>
              ) : labs.length === 0 ? (
                <EmptyState message="There are no projects/labs available on this GNS3 server." />
              ) : selectedLab && topology ? (
                // --- TOPOLOGY VIEW ---
                <div className="card border-cyan-900/50">
                  <div className="flex justify-between items-center mb-6 border-b border-slate-700/50 pb-4">
                    <div>
                      <button 
                        onClick={() => setSelectedLab(null)}
                        className="text-cyan-400 hover:text-cyan-300 text-sm font-medium flex items-center mb-2"
                      >
                        <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg>
                        Back to Labs
                      </button>
                      <h3 className="text-xl font-bold text-slate-100">
                        {labs.find(l => l.project_id === selectedLab)?.name}
                      </h3>
                      <div className="text-xs text-slate-400 mt-1">
                        Select nodes to import into NetSecAuditor Device Inventory for scanning.
                      </div>
                    </div>
                    
                    <div className="flex space-x-3">
                      <button
                        onClick={() => handleLabAction(selectedLab, 'start')}
                        disabled={actionLoading !== null}
                        className="btn-secondary flex items-center text-emerald-400 hover:text-emerald-300 border-emerald-900 hover:border-emerald-700 hover:bg-emerald-900/20"
                      >
                        <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                        Start All
                      </button>
                      <button
                        onClick={() => handleLabAction(selectedLab, 'stop')}
                        disabled={actionLoading !== null}
                        className="btn-secondary flex items-center text-rose-400 hover:text-rose-300 border-rose-900 hover:border-rose-700 hover:bg-rose-900/20"
                      >
                        <svg className="w-4 h-4 mr-1.5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8 7a1 1 0 00-1 1v4a1 1 0 001 1h4a1 1 0 001-1V8a1 1 0 00-1-1H8z" clipRule="evenodd" /></svg>
                        Stop All
                      </button>
                    </div>
                  </div>
                  
                  {loadingTopology ? (
                     <div className="py-20 flex justify-center"><div className="animate-spin w-8 h-8 flex-shrink-0 rounded-full border-4 border-cyan-500/30 border-t-cyan-500"></div></div>
                  ) : (
                    <>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                        {topology.nodes.map((node: any) => {
                          const isInfra = ["cloud", "ethernet_switch", "frame_relay_switch", "nat", "ethernet_hub"].includes(node.node_type);
                          const isSelected = selectedNodes.has(node.node_id);
                          
                          return (
                            <div 
                              key={node.node_id}
                              onClick={() => !isInfra && !node.already_imported && toggleNode(node.node_id)}
                              className={`p-4 rounded-xl border relative ${
                                isInfra ? 'bg-slate-800/20 border-slate-700/30 opacity-70 cursor-not-allowed' :
                                node.already_imported ? 'bg-cyan-900/10 border-cyan-900/30 cursor-not-allowed' :
                                isSelected ? 'bg-cyan-900/30 border-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.15)] cursor-pointer ring-1 ring-cyan-500' : 
                                'bg-soc-panel border-soc-border hover:border-slate-500 cursor-pointer'
                              }`}
                            >
                              {!isInfra && !node.already_imported && (
                                <div className={`absolute top-4 right-4 w-5 h-5 rounded border ${isSelected ? 'bg-cyan-500 border-cyan-500 text-white' : 'border-slate-500 bg-slate-800'} flex items-center justify-center transition-colors`}>
                                  {isSelected && <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>}
                                </div>
                              )}
                              
                              <div className="flex items-start">
                                <div className={`w-10 h-10 rounded-lg flex items-center justify-center mr-4 ${isInfra ? 'bg-slate-800 text-slate-500' : 'bg-slate-800 text-cyan-400'}`}>
                                  {isInfra ? (
                                    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" /></svg>
                                  ) : (
                                    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" /></svg>
                                  )}
                                </div>
                                <div className="pr-8">
                                  <div className="font-bold text-slate-200">{node.name}</div>
                                  <div className="text-xs text-slate-400 capitalize">{node.node_type}</div>
                                  
                                  <div className="flex flex-wrap gap-2 mt-3 items-center">
                                    <span className={`flex flex-row items-center px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider ${node.status === 'started' ? 'bg-emerald-900/40 text-emerald-400' : 'bg-slate-700/50 text-slate-400'}`}>
                                      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${node.status === 'started' ? 'bg-emerald-500' : 'bg-slate-500'}`}></span>
                                      {node.status}
                                    </span>
                                    
                                    {node.console_host && node.console_host !== '0.0.0.0' && (
                                       <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-900/30 text-indigo-300 font-mono">
                                         {node.console_host}:{node.console}
                                       </span>
                                    )}
                                    
                                    {node.already_imported && (
                                       <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-900/30 text-cyan-300 font-medium">
                                         In Inventory
                                       </span>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                      
                      <div className="flex justify-between items-center pt-6 border-t border-slate-700/50">
                        <div className="text-sm text-slate-400">
                          {selectedNodes.size} device{selectedNodes.size === 1 ? '' : 's'} selected for import
                        </div>
                        <button
                          onClick={handleImportSelected}
                          disabled={importing || selectedNodes.size === 0}
                          className="btn-primary"
                        >
                          {importing ? "Importing..." : "Import Selected to Inventory"}
                        </button>
                      </div>
                    </>
                  )}
                </div>
              ) : (
                // --- LABS DASHBOARD ---
                <div className="card">
                  <h3 className="text-lg font-bold text-slate-100 mb-6">Available GNS3 Sandbox Projects</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {labs.map(lab => (
                      <div key={lab.project_id} className="p-5 border border-slate-700/50 bg-slate-800/30 rounded-xl hover:border-slate-500 transition-colors group">
                        <div className="flex justify-between items-start mb-3">
                          <h4 className="font-bold text-cyan-300 text-lg group-hover:text-cyan-200">{lab.name}</h4>
                          <span className={`px-2 py-1 rounded text-[10px] uppercase font-bold tracking-wider flex items-center ${lab.status === 'opened' ? 'bg-emerald-900/40 text-emerald-400' : 'bg-slate-700/80 text-slate-300'}`}>
                            <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${lab.status === 'opened' ? 'bg-emerald-500' : 'bg-slate-500'}`}></span>
                            {lab.status}
                          </span>
                        </div>
                        <div className="text-xs text-slate-500 mb-6 font-mono">
                          {lab.project_id}
                        </div>
                        <div className="flex space-x-3">
                          <button
                            onClick={() => handleViewTopology(lab.project_id)}
                            className="flex-1 btn-primary text-sm shadow-[0_0_10px_rgba(6,182,212,0.1)] group-hover:shadow-[0_0_15px_rgba(6,182,212,0.2)]"
                          >
                            View Topology
                          </button>
                          {lab.status !== 'opened' && (
                            <button
                              onClick={() => handleLabAction(lab.project_id, 'start')}
                              disabled={actionLoading === `start-${lab.project_id}`}
                              className="btn-secondary text-sm border-slate-600 hover:border-emerald-500 hover:text-emerald-400 px-4"
                              title="Start Project"
                            >
                              {actionLoading === `start-${lab.project_id}` ? "..." : (
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                              )}
                            </button>
                          )}
                        </div>
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
