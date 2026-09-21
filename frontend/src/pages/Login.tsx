import React, { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

// The login page is always a white page with dark ink, regardless of the
// app theme. Colors are inline (not text-slate-* utilities) on purpose:
// index.css force-remaps those to theme variables, which is what made the
// old dark-gradient login render dark-on-dark.
const INK = "#0f172a";
const MUTED = "#475569";
const BORDER = "#cbd5e1";
const BRAND = "#28406f";

export default function Login() {
  const { login, isAuthenticated, isLoggingIn, authError } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from || "/";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [tenant, setTenant] = useState("");
  const [showTenant, setShowTenant] = useState(false);

  if (isAuthenticated) return <Navigate to={from} replace />;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password || isLoggingIn) return;
    try {
      await login(username.trim(), password, tenant.trim() || undefined);
      navigate(from, { replace: true });
    } catch {
      // authError is already set by the context and rendered below.
      setPassword("");
    }
  };

  const field: React.CSSProperties = {
    width: "100%", padding: "0.65rem 0.8rem", border: `1px solid ${BORDER}`, borderRadius: 8,
    background: "#fff", color: INK, fontSize: "1rem", outline: "none",
  };
  const label: React.CSSProperties = { display: "block", fontSize: "0.875rem", fontWeight: 600, color: INK, marginBottom: 6 };

  return (
    <div style={{ minHeight: "100vh", background: "#ffffff", display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
      <form onSubmit={submit} style={{ width: "100%", maxWidth: 400 }} aria-labelledby="login-title">
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{ width: 56, height: 56, borderRadius: 14, background: BRAND, margin: "0 auto 14px", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <svg width="30" height="30" fill="none" viewBox="0 0 24 24" stroke="#fff" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 id="login-title" style={{ fontSize: "1.75rem", fontWeight: 800, color: INK, margin: 0 }}>NetSecAuditor</h1>
          <p style={{ color: MUTED, marginTop: 6, fontSize: "0.95rem" }}>Sign in to continue</p>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label htmlFor="login-username" style={label}>Username</label>
          <input id="login-username" style={field} value={username} onChange={(e) => setUsername(e.target.value)}
            autoComplete="username" autoFocus required />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label htmlFor="login-password" style={label}>Password</label>
          <input id="login-password" type="password" style={field} value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password" required />
        </div>

        {showTenant ? (
          <div style={{ marginBottom: 16 }}>
            <label htmlFor="login-tenant" style={label}>Tenant <span style={{ fontWeight: 400, color: MUTED }}>(only if your username exists in more than one)</span></label>
            <input id="login-tenant" style={field} value={tenant} onChange={(e) => setTenant(e.target.value)} />
          </div>
        ) : (
          <button type="button" onClick={() => setShowTenant(true)}
            style={{ background: "none", border: "none", color: BRAND, cursor: "pointer", fontSize: "0.875rem", padding: 0, marginBottom: 16 }}>
            Multiple organisations? Specify a tenant
          </button>
        )}

        {authError && (
          <div role="alert" style={{ background: "#fef2f2", border: "1px solid #fecaca", color: "#991b1b", borderRadius: 8, padding: "0.6rem 0.8rem", fontSize: "0.9rem", marginBottom: 16 }}>
            {authError}
          </div>
        )}

        <button type="submit" disabled={isLoggingIn || !username || !password}
          style={{ width: "100%", padding: "0.75rem", borderRadius: 8, border: "none", background: BRAND, color: "#fff", fontSize: "1rem", fontWeight: 600,
            cursor: isLoggingIn ? "wait" : "pointer", opacity: isLoggingIn || !username || !password ? 0.6 : 1 }}>
          {isLoggingIn ? "Signing in…" : "Sign in"}
        </button>

        <p style={{ color: MUTED, fontSize: "0.8rem", textAlign: "center", marginTop: 20 }}>
          Accounts are created by an administrator. On a fresh install, use the bootstrap admin from your deployment configuration.
        </p>
      </form>
    </div>
  );
}
