import React, { createContext, useContext, useState, useEffect } from "react";
import { setTargetTenant, api } from "../api";
import { Navigate } from "react-router-dom";

export type Role = "admin" | "security_analyst" | "operator" | "auditor" | "viewer";

interface AuthContextType {
  token: string | null;
  role: Role | null;
  username: string | null;
  isAuthenticated: boolean;
  login: (mockRole: Role) => void;
  logout: () => void;
  hasRole: (role: Role) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(localStorage.getItem("token"));
  const [role, setRole] = useState<Role | null>((localStorage.getItem("role") as Role) || null);

  useEffect(() => {
    // Setup Axios interceptor to automatically inject Bearer token
    const interceptor = api.interceptors.request.use((config) => {
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
    
    // Also inject demo tenant if none provided
    setTargetTenant("tenant-a");

    return () => {
      api.interceptors.request.eject(interceptor);
    };
  }, [token]);

  const login = (role: Role) => {
    const mockToken = `MOCK_${role}`;
    localStorage.setItem("token", mockToken);
    localStorage.setItem("role", role);
    setToken(mockToken);
    setRole(role);
  };

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    setToken(null);
    setRole(null);
  };

  const hasRole = (r: Role) => role === r || role === "admin";

  const username = role ? `demo-${role}` : null;

  return (
    <AuthContext.Provider value={{ token, role, username, isAuthenticated: !!token, login, logout, hasRole }}>
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
  const { isAuthenticated, role } = useAuth();
  
  if (!isAuthenticated) {
    // Redirect to login if not authenticated
    return <Navigate to="/login" replace />; 
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
