import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/devices", label: "Devices" },
  { to: "/topology", label: "Topology" },
  { to: "/drift", label: "Drift" },
  { to: "/schedules", label: "Schedules" },
  { to: "/alerts", label: "Alerts" },
  { to: "/ai-analysis", label: "AI Analysis" },
  { to: "/ingestion", label: "Ingestion" },
  { to: "/compliance", label: "Compliance" },
  { to: "/validation", label: "Validation" },
  { to: "/training", label: "Training Center" },
  { to: "/reports", label: "Reports" },
  { to: "/knowledge-base", label: "Knowledge Base" },
  { to: "/observability", label: "Observability" },
  { to: "/evidence", label: "Evidence Ledger" },
  { to: "/audit-log", label: "Audit Log" },
];

export default function App() {
  return (
    <div className="min-h-screen flex">
      <aside className="w-64 shrink-0 bg-soc-panel border-r border-soc-border flex flex-col">
        <div className="px-5 py-6 border-b border-soc-border">
          <div className="text-cyan-400 font-bold text-lg tracking-tight">Compliance Auditor</div>
          <div className="text-xs text-slate-500 mt-1">SIH-26155 · Multi-Vendor NetSec</div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
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