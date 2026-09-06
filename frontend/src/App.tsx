import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";
import { useTheme } from "./theme";

const NAV_GROUPS = [
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
      { to: "/network-scans", label: "Network Scans & Discovery" },
      { to: "/schedules", label: "Schedules" },
    ],
  },
  {
    label: "Compliance",
    items: [
      { to: "/compliance", label: "Findings" },
      { to: "/drift", label: "Drift" },
      { to: "/validation", label: "Validation" },
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
      { to: "/training", label: "Training Center" },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/config-search", label: "Config Search" },
      { to: "/ingestion", label: "Ingestion" },
      { to: "/knowledge-base", label: "Knowledge Base" },
      { to: "/system/health", label: "System Health" },
      { to: "/observability", label: "Observability" },
      { to: "/audit-log", label: "Audit Log" },
    ],
  },
];

export default function App() {
  const { theme, toggleTheme } = useTheme();
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
          {NAV_GROUPS.map((group) => (
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
        <div className="px-5 py-4 border-t border-soc-border text-xs text-slate-500">
          100% self-hosted stack · No paid cloud AI
        </div>
      </aside>
      <main className="flex-1 min-w-0">
        <Outlet />
      </main>
    </div>
  );
}