import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth, Role } from "../context/AuthContext";

const ROLES: { role: Role; label: string; description: string; icon: string; color: string; glow: string }[] = [
  {
    role: "security_analyst",
    label: "Security Analyst",
    description: "Review AI suggestions, approve remediations, manage compliance policies.",
    icon: "🔍",
    color: "from-cyan-500/20 to-cyan-900/10 border-cyan-700/60 hover:border-cyan-400",
    glow: "shadow-cyan-900/40",
  },
  {
    role: "operator",
    label: "Network Operator",
    description: "Deploy approved changes, run scans, manage device inventory.",
    icon: "⚙️",
    color: "from-blue-500/20 to-blue-900/10 border-blue-700/60 hover:border-blue-400",
    glow: "shadow-blue-900/40",
  },
  {
    role: "auditor",
    label: "Compliance Auditor",
    description: "Read-only access to all findings, reports, and evidence ledger.",
    icon: "📋",
    color: "from-violet-500/20 to-violet-900/10 border-violet-700/60 hover:border-violet-400",
    glow: "shadow-violet-900/40",
  },
  {
    role: "admin",
    label: "System Administrator",
    description: "Full access: tenant management, RBAC, system health, all operations.",
    icon: "🛡️",
    color: "from-fuchsia-500/20 to-fuchsia-900/10 border-fuchsia-700/60 hover:border-fuchsia-400",
    glow: "shadow-fuchsia-900/40",
  },
];

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [selecting, setSelecting] = useState<Role | null>(null);

  const handleLogin = (role: Role) => {
    setSelecting(role);
    setTimeout(() => {
      login(role);
      navigate("/");
    }, 400);
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden"
      style={{ background: "radial-gradient(ellipse at 60% 20%, #0e2a38 0%, #080e1a 60%, #060810 100%)" }}
    >
      {/* Ambient glow blobs */}
      <div className="pointer-events-none absolute -top-32 -left-32 w-[600px] h-[600px] rounded-full bg-cyan-700/10 blur-3xl" />
      <div className="pointer-events-none absolute bottom-0 right-0 w-[500px] h-[500px] rounded-full bg-blue-700/10 blur-3xl" />

      <div className="relative z-10 max-w-5xl w-full">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl mb-5 bg-gradient-to-br from-cyan-500 to-blue-600 shadow-[0_0_40px_rgba(6,182,212,0.4)]">
            <svg className="w-10 h-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-5xl font-extrabold tracking-tight text-white mb-3"
            style={{ textShadow: "0 0 40px rgba(6,182,212,0.25)" }}>
            NetSecAuditor
          </h1>
          <p className="text-slate-400 text-lg max-w-xl mx-auto leading-relaxed">
            AI-driven multi-vendor network security compliance. OPA-deterministic, Batfish-verified, LLM-assisted.
          </p>
          <div className="mt-4 inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-800/50 bg-cyan-900/20 text-xs text-cyan-400 font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" /> SSO SIMULATED — SELECT ROLE TO AUTHENTICATE
          </div>
        </div>

        {/* Role cards grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {ROLES.map(({ role, label, description, icon, color, glow }) => (
            <button
              key={role}
              id={`login-role-${role}`}
              onClick={() => handleLogin(role)}
              disabled={selecting !== null}
              className={`relative group text-left p-6 rounded-2xl border bg-gradient-to-br ${color} transition-all duration-300 shadow-lg ${glow} hover:shadow-xl hover:-translate-y-0.5 disabled:opacity-60 disabled:cursor-wait`}
              style={{ backdropFilter: "blur(12px)" }}
            >
              <div className="flex items-start gap-4">
                <span className="text-3xl mt-0.5">{icon}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-bold text-slate-100 text-lg">{label}</div>
                    {selecting === role && (
                      <span className="text-xs text-cyan-400 font-mono animate-pulse">Authenticating…</span>
                    )}
                  </div>
                  <p className="text-sm text-slate-400 mt-1 leading-relaxed">{description}</p>
                  <div className="mt-3 flex items-center gap-1.5 text-xs font-mono text-slate-600">
                    <span className="w-1 h-1 rounded-full bg-slate-600" />
                    role: <span className="text-slate-500">{role}</span>
                  </div>
                </div>
              </div>
              {/* Animated border gradient on hover */}
              <div className="pointer-events-none absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                style={{ boxShadow: "inset 0 0 0 1px rgba(6,182,212,0.2)" }} />
            </button>
          ))}
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-slate-600 mt-8">
          In production, role assignment is enforced via Keycloak JWT claims —
          the SSO panel above is a demo-mode convenience only and is not available in AUTH_ENABLED=true deployments.
        </p>
      </div>
    </div>
  );
}
