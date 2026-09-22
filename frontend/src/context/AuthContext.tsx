import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { setTargetTenant, api } from "../api";
import { Navigate } from "react-router-dom";

export type Role = "admin" | "security_analyst" | "operator" | "auditor" | "viewer";

interface AuthContextType {
  token: string | null;
  role: Role | null;
  username: string | null;
  isAuthenticated: boolean;
  authError: string | null;
  isLoggingIn: boolean;
  login: (username: string, password: string, tenant?: string) => Promise<void>;
  tenantName: string | null;
  ready: boolean;
  authDisabled: boolean;
  logout: () => void;
  /** Adopt a freshly issued token (e.g. after a password change rotated the old ones). */
  applyToken: (token: string) => void;
  hasRole: (role: Role) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = "netsecauditor.token";
const ROLE_KEY = "netsecauditor.role";
const USERNAME_KEY = "netsecauditor.username";
const TENANT_KEY = "netsecauditor.tenant";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(localStorage.getItem(TOKEN_KEY));
  const [role, setRole] = useState<Role | null>((localStorage.getItem(ROLE_KEY) as Role) || null);
  const [username, setUsername] = useState<string | null>(localStorage.getItem(USERNAME_KEY));
  const [tenantName, setTenantName] = useState<string | null>(localStorage.getItem(TENANT_KEY));
  const [authDisabled, setAuthDisabled] = useState(false);
  const [ready, setReady] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ROLE_KEY);
    localStorage.removeItem(USERNAME_KEY);
    localStorage.removeItem(TENANT_KEY);
    setTenantName(null);
    setToken(null);
    setRole(null);
    setUsername(null);
    // Best-effort: invalidate the token server-side (bumps token_version).
    // Fire-and-forget -- logging out client-side must succeed either way.
    api.post("/api/auth/logout").finally(() => {
      window.location.href = "/login";
    });
  }, []);

  useEffect(() => {
    // Demo deployments (AUTH_ENABLED=false) have no login: skip the form.
    let cancelled = false;
    api
      .get("/api/auth/config")
      .then((r) => { if (!cancelled) setAuthDisabled(r.data?.auth_enabled === false); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setReady(true); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    // Attach the bearer token to every request, and log the user out the
    // moment the backend says the token is no longer valid (expired,
    // invalidated by a prior logout/password change, or account disabled)
    // rather than leaving them stuck on 401s until they notice.
    const reqInterceptor = api.interceptors.request.use((config) => {
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
    const resInterceptor = api.interceptors.response.use(
      (response) => response,
      (error) => {
        const url: string = error?.config?.url || "";
        // Not for /auth/login (a wrong password is a 401 too) or /auth/logout
        // (would recurse into logout()).
        if (error?.response?.status === 401 && token && !url.includes("/api/auth/")) {
          logout();
        }
        return Promise.reject(error);
      }
    );

    return () => {
      api.interceptors.request.eject(reqInterceptor);
      api.interceptors.response.eject(resInterceptor);
    };
  }, [token, logout]);

  const login = async (loginUsername: string, password: string, tenant?: string) => {
    setIsLoggingIn(true);
    setAuthError(null);
    try {
      const { data } = await api.post("/api/auth/login", {
        username: loginUsername,
        password,
        ...(tenant ? { tenant } : {}),
      });
      const accessToken: string = data.access_token;

      // Fetch identity (role/tenant) using the freshly issued token, since
      // /login only returns the token itself.
      const meResp = await api.get("/api/auth/me", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const roles: string[] = meResp.data.roles || [];
      const primaryRole = (roles.includes("admin") ? "admin" : roles[0]) as Role | undefined;

      localStorage.setItem(TOKEN_KEY, accessToken);
      if (primaryRole) localStorage.setItem(ROLE_KEY, primaryRole);
      localStorage.setItem(USERNAME_KEY, meResp.data.username || loginUsername);

      setToken(accessToken);
      setRole(primaryRole || null);
      setUsername(meResp.data.username || loginUsername);
      if (meResp.data.tenant_name) {
        setTargetTenant(meResp.data.tenant_name);
        localStorage.setItem(TENANT_KEY, meResp.data.tenant_name);
        setTenantName(meResp.data.tenant_name);
      }
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      setAuthError(
        typeof detail === "string"
          ? detail
          : "Login failed. Check your username and password and try again."
      );
      throw err;
    } finally {
      setIsLoggingIn(false);
    }
  };

  const effectiveRole: Role | null = role ?? (authDisabled ? "admin" : null);
  const applyToken = (t: string) => {
    localStorage.setItem(TOKEN_KEY, t);
    setToken(t);
  };

  const hasRole = (r: Role) => effectiveRole === r || effectiveRole === "admin";

  return (
    <AuthContext.Provider
      value={{ token, role: effectiveRole, username: username ?? (authDisabled ? "demo-admin" : null), isAuthenticated: !!token || authDisabled, tenantName, ready, authDisabled, authError, isLoggingIn, login, logout, applyToken, hasRole }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

export function ProtectedRoute({ children, allowedRoles }: { children: React.ReactNode, allowedRoles?: Role[] }) {
  const { isAuthenticated, role, ready } = useAuth();

  if (!ready) return (
    <div style={{
      position: "fixed", inset: 0,
      background: "#0b1120",
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      gap: 16,
    }}>
      <svg width="40" height="40" viewBox="0 0 40 40" style={{ animation: "spin 1s linear infinite" }}>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        <circle cx="20" cy="20" r="16" fill="none" stroke="#1e3a5f" strokeWidth="4" />
        <path d="M20 4 A16 16 0 0 1 36 20" fill="none" stroke="#3b82f6" strokeWidth="4" strokeLinecap="round" />
      </svg>
      <span style={{ color: "#94a3b8", fontSize: "0.875rem", letterSpacing: "0.05em" }}>Loading…</span>
    </div>
  );

  if (!isAuthenticated) {
    // Redirect to login if not authenticated
    return <Navigate to="/login" replace state={{ from: window.location.pathname + window.location.search }} />;
  }
  
  if (allowedRoles && role && !allowedRoles.includes(role) && role !== "admin") {
    return (
      <div className="p-8 flex items-center justify-center h-full">
        <div className="bg-soc-panel border border-red-900/50 rounded-lg p-6 max-w-md text-center">
          <svg className="w-12 h-12 text-red-500 mx-auto mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <h2 className="text-xl font-bold text-slate-200 mb-2">Access Denied</h2>
          <p className="text-slate-400">You do not have the necessary role ({allowedRoles.join(' or ')}) to view this resource.</p>
        </div>
      </div>
    );
  }
  
  return <>{children}</>;
}