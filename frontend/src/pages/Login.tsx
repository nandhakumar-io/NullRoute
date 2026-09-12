import React from "react";
import { useNavigate } from "react-router-dom";
import { useAuth, Role } from "../context/AuthContext";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = (role: Role) => {
    login(role);
    navigate("/");
  };

  return (
    <div className="min-h-screen bg-[#0B1120] flex items-center justify-center p-4">
      <div className="max-w-4xl w-full flex rounded-2xl overflow-hidden shadow-2xl border border-soc-border bg-soc-panel">
        
        {/* Left Side: Branding */}
        <div className="w-1/2 p-12 bg-gradient-to-br from-cyan-950/40 to-blue-900/20 border-r border-soc-border flex flex-col justify-center">
          <div className="w-16 h-16 bg-cyan-500 rounded-2xl flex items-center justify-center mb-6 shadow-[0_0_30px_rgba(6,182,212,0.3)]">
            <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-4xl font-bold text-white mb-4 tracking-tight">NullRoute</h1>
          <p className="text-slate-400 text-lg leading-relaxed">
            Multi-vendor network security compliance auditor. Validate configurations against organizational rules and catch catastrophic behavioral drifts before they reach production.
          </p>
          <div className="mt-8 text-xs font-mono text-cyan-500/50">
            [PRODUCTION BUILD]
          </div>
        </div>

        {/* Right Side: Demo Login Selection */}
        <div className="w-1/2 p-12 flex flex-col justify-center">
          <h2 className="text-2xl font-semibold text-white mb-2">Simulated SSO Login</h2>
          <p className="text-sm text-slate-400 mb-8">
            Select a role to assume. In a production environment, this redirects to the Keycloak Identity Provider.
          </p>

          <div className="space-y-4">
            <button 
              onClick={() => handleLogin("security_analyst")}
              className="w-full relative group bg-slate-800/50 hover:bg-cyan-950/30 border border-slate-700 hover:border-cyan-500/50 rounded-xl p-4 text-left transition-all duration-300"
            >
              <div className="font-semibold text-slate-200 group-hover:text-cyan-400">Security Analyst</div>
              <div className="text-sm text-slate-500 mt-1">Can review changes, approve AI rules, and manage policies.</div>
            </button>

            <button 
              onClick={() => handleLogin("viewer")}
              className="w-full relative group bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700 hover:border-slate-500 rounded-xl p-4 text-left transition-all duration-300"
            >
              <div className="font-semibold text-slate-200 group-hover:text-white">Read-Only Viewer</div>
              <div className="text-sm text-slate-500 mt-1">Can only view dashboards and read reports. Cannot mutate state.</div>
            </button>
            
            <button 
              onClick={() => handleLogin("admin")}
              className="w-full relative group bg-slate-800/50 hover:bg-fuchsia-900/20 border border-slate-700 hover:border-fuchsia-500/50 rounded-xl p-4 text-left transition-all duration-300"
            >
              <div className="font-semibold text-slate-200 group-hover:text-fuchsia-400">System Administrator</div>
              <div className="text-sm text-slate-500 mt-1">Full access to all systems including tenant management.</div>
            </button>
          </div>
          
        </div>
      </div>
    </div>
  );
}
