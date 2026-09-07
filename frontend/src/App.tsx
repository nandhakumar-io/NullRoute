import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";
import { useTheme } from "./theme";
import { useAuth } from "./context/AuthContext";

type NavItem = { to: string; label: string; end?: boolean; roles?: string[] };
type NavGroup = { label: string; items: NavItem[] };

const NAV_GROUPS: NavGroup[] = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Dashboard", end: true },
    ],
  },
  {
    label: "Operations",
    items: [
      { to: "/devices", label: "Devices" },
      { to: "/network-scans", label: "Network Scans & Discovery", roles: ["admin", "security_analyst", "operator"] },
      { to: "/schedules", label: "Schedules" },
      { to: "/gns3-integration", label: "GNS3 Virtual Sandbox", roles: ["admin", "security_analyst"] },
    ],
  },
  {
    label: "Compliance",
    items: [
      { to: "/compliance", label: "Findings" },
      { to: "/drift", label: "Drift" },
      { to: "/validation", label: "Validation", roles: ["admin", "security_analyst", "operator"] },
      { to: "/reports", label: "Reports" },
    ],
  },
  {
    label: "Security",
    items: [
      { to: "/topology", label: "Topology" },
      { to: "/evidence", label: "Evidence Ledger" },
      { to: "/alerts", label: "Alerts" },
    ],
  },
  {
    label: "AI",
    items: [
      { to: "/ai-analysis", label: "AI Analysis" },
      { to: "/training", label: "Training Center", roles: ["admin", "security_analyst"] },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/config-search", label: "Config Search" },
      { to: "/ingestion", label: "Ingestion", roles: ["admin", "security_analyst"] },
      { to: "/knowledge-base", label: "Knowledge Base", roles: ["admin", "security_analyst", "auditor"] },
      { to: "/system/health", label: "System Health", roles: ["admin"] },
      { to: "/observability", label: "Observability", roles: ["admin"] },
      { to: "/audit-log", label: "Audit Log", roles: ["admin", "auditor"] },
    ],
  },
];

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const { logout, role, username } = useAuth();
  
  // Filter Nav Groups based on current user role
  const filteredNavGroups = NAV_GROUPS.map(group => {
    return {
      ...group,
      items: group.items.filter(item => {
        if (!item.roles) return true;
        if (role === "admin") return true;
        if (!role) return false;
        return item.roles.includes(role);
      })
    };
  }).filter(group => group.items.length > 0);

  return (
    <div className="min-h-screen flex">
      <aside className="w-64 shrink-0 bg-soc-panel border-r border-soc-border flex flex-col">
        <div className="px-5 py-6 border-b border-soc-border flex items-start justify-between gap-2">
          <div>
            <div className="text-cyan-400 font-bold text-lg tracking-tight">Compliance Auditor</div>
            <div className="text-xs text-slate-500 mt-1">SIH-26155 · Multi-Vendor NetSec</div>
          </div>
          <button
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            className="shrink-0 w-8 h-8 rounded-lg border border-soc-border bg-slate-800/60 hover:bg-slate-700 flex items-center justify-center text-slate-300 transition-colors"
          >
            {theme === "dark" ? (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
            ) : (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
            )}
          </button>
        </div>
        <nav className="flex-1 px-3 py-4 overflow-y-auto space-y-4">
          {filteredNavGroups.map((group) => (
            <div key={group.label}>
              <div className="px-3 mb-1 text-[10px] font-bold uppercase tracking-widest text-slate-600">
                {group.label}
              </div>
              <div className="space-y-0.5">
                {group.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={(item as any).end}
                    className={({ isActive }) =>
                      clsx(
                        "block px-3 py-2 rounded-lg text-sm font-medium transition-colors",
                        isActive
                          ? "bg-cyan-950/60 text-cyan-300 border border-cyan-800/60"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      )
                    }
                  >
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        
        {/* User Identity / Logout Box */}
        <div className="p-4 border-t border-soc-border bg-slate-900/30">
           <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-bold text-slate-200">{username || "Unknown"}</div>
                <div className="text-xs text-cyan-500 uppercase tracking-wider font-semibold">{role || "No Role"}</div>
              </div>
              <button 
                onClick={logout}
                className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-900/20 rounded-md transition-colors"
                title="Logout"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
              </button>
           </div>
        </div>
      </aside>
      <main className="flex-1 min-w-0">
        <Outlet />
      </main>
    </div>
  );
}