import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { useTheme } from "./theme";
import { useAuth } from "./context/AuthContext";

type NavItem = { to: string; label: string; end?: boolean; roles?: string[] };
type NavGroup = { key: string; label: string; icon: IconName; items: NavItem[] };

const NAV_GROUPS: NavGroup[] = [
  {
    key: "overview",
    label: "Overview",
    icon: "grid",
    items: [{ to: "/", label: "Dashboard", end: true }],
  },
  {
    key: "operations",
    label: "Operations",
    icon: "server",
    items: [
      { to: "/devices", label: "Devices" },
      { to: "/backups", label: "Config Backups" },
      { to: "/network-scans", label: "Network Scans & Discovery", roles: ["admin", "security_analyst", "operator"] },
      { to: "/schedules", label: "Schedules" },
      { to: "/gns3-integration", label: "GNS3 Virtual Sandbox", roles: ["admin", "security_analyst"] },
    ],
  },
  {
    key: "compliance",
    label: "Compliance",
    icon: "checklist",
    items: [
      { to: "/compliance", label: "Findings" },
      { to: "/drift", label: "Drift" },
      { to: "/validation", label: "Validation", roles: ["admin", "security_analyst", "operator"] },
      { to: "/reports", label: "Reports" },
      { to: "/report-verification", label: "Report Verification" },
    ],
  },
  {
    key: "security",
    label: "Security",
    icon: "shield",
    items: [
      { to: "/topology", label: "Topology" },
      { to: "/evidence", label: "Evidence Ledger" },
      { to: "/alerts", label: "Alerts" },
      { to: "/control-library", label: "Control Library", roles: ["admin", "security_analyst", "auditor"] },
      { to: "/vulnerabilities", label: "Vulnerabilities" },
    ],
  },
  {
    key: "ai",
    label: "AI",
    icon: "spark",
    items: [
      { to: "/review-queue", label: "Review Queue" },
      { to: "/ai-analysis", label: "AI Analysis" },
      { to: "/training", label: "Training Center", roles: ["admin", "security_analyst"] },
    ],
  },
  {
    key: "administration",
    label: "Administration",
    icon: "gear",
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

const RAIL_KEY = "netsecauditor.railCollapsed";
const GROUP_KEY_PREFIX = "netsecauditor.navgroup.";

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const { logout, role, username } = useAuth();
  const location = useLocation();

  const [collapsed, setCollapsed] = useState<boolean>(() => localStorage.getItem(RAIL_KEY) === "1");
  useEffect(() => localStorage.setItem(RAIL_KEY, collapsed ? "1" : "0"), [collapsed]);

  const [closedGroups, setClosedGroups] = useState<Record<string, boolean>>(() => {
    const map: Record<string, boolean> = {};
    for (const g of NAV_GROUPS) map[g.key] = localStorage.getItem(GROUP_KEY_PREFIX + g.key) === "1";
    return map;
  });
  const toggleGroup = (key: string) =>
    setClosedGroups((prev) => {
      const next = { ...prev, [key]: !prev[key] };
      localStorage.setItem(GROUP_KEY_PREFIX + key, next[key] ? "1" : "0");
      return next;
    });

  const filteredNavGroups = useMemo(
    () =>
      NAV_GROUPS.map((group) => ({
        ...group,
        items: group.items.filter((item) => {
          if (!item.roles) return true;
          if (role === "admin") return true;
          if (!role) return false;
          return item.roles.includes(role);
        }),
      })).filter((group) => group.items.length > 0),
    [role]
  );

  const currentLabel = useMemo(() => {
    for (const g of filteredNavGroups) {
      for (const item of g.items) {
        if (item.end ? location.pathname === item.to : location.pathname.startsWith(item.to)) {
          return { section: g.label, page: item.label };
        }
      }
    }
    return { section: "Overview", page: "Dashboard" };
  }, [filteredNavGroups, location.pathname]);

  return (
    <div className="min-h-screen flex" style={{ backgroundColor: "var(--paper)" }}>
      <aside
        className={clsx(
          "shrink-0 bg-rail border-r border-rail-border flex flex-col transition-[width] duration-150 ease-out",
          collapsed ? "w-[72px]" : "w-64"
        )}
      >
        <div className="h-16 px-4 border-b border-rail-border flex items-center justify-between gap-2">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="shrink-0 w-8 h-8 rounded bg-seal flex items-center justify-center text-[13px] font-semibold text-white tracking-tight">
              NR
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="text-rail-text font-semibold text-sm leading-tight truncate">NullRoute</div>
                <div className="text-[11px] text-rail-textDim leading-tight truncate">Multi-vendor network compliance</div>
              </div>
            )}
          </div>
        </div>

        <nav className="flex-1 px-2.5 py-3 overflow-y-auto overflow-x-hidden rail-scroll space-y-1">
          {filteredNavGroups.map((group) => {
            const isClosed = !collapsed && closedGroups[group.key];
            return (
              <div key={group.key}>
                <button
                  type="button"
                  onClick={() => !collapsed && toggleGroup(group.key)}
                  className={clsx(
                    "w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-rail-textDim hover:text-rail-text transition-colors",
                    collapsed && "justify-center"
                  )}
                  title={group.label}
                >
                  <Icon name={group.icon} className="w-[18px] h-[18px] shrink-0" />
                  {!collapsed && (
                    <>
                      <span className="rail-nav-group-label flex-1 text-left text-[13px]">{group.label}</span>
                      <Icon
                        name="chevron"
                        className={clsx("w-3.5 h-3.5 shrink-0 transition-transform", isClosed && "-rotate-90")}
                      />
                    </>
                  )}
                </button>
                {!isClosed && (
                  <div className={clsx("space-y-0.5", collapsed ? "mt-0.5" : "mt-0.5 ml-[13px] pl-[19px] border-l border-rail-border")}>
                    {group.items.map((item) => (
                      <NavLink
                        key={item.to}
                        to={item.to}
                        end={item.end}
                        title={collapsed ? item.label : undefined}
                        className={({ isActive }) =>
                          clsx(
                            "rail-nav-item relative block rounded-md text-[13px] transition-colors truncate",
                            isActive && "active",
                            collapsed ? "mx-auto w-2 h-2 rounded-full my-2" : "px-2.5 py-1.5",
                            isActive
                              ? collapsed
                                ? "bg-seal"
                                : "bg-white/[0.08] text-white"
                              : collapsed
                              ? "bg-rail-border"
                              : "text-rail-textDim hover:bg-white/[0.06] hover:text-rail-text"
                          )
                        }
                      >
                        {({ isActive }) => (
                          <>
                            {!collapsed && isActive && (
                              <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full bg-seal -ml-[19px]" />
                            )}
                            {!collapsed && item.label}
                          </>
                        )}
                      </NavLink>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        <div className="p-2.5 border-t border-rail-border">
          <button
            type="button"
            onClick={() => setCollapsed((c) => !c)}
            className="w-full flex items-center justify-center gap-2 py-2 rounded-md text-rail-textDim hover:text-rail-text hover:bg-white/[0.04] transition-colors"
            title={collapsed ? "Expand navigation" : "Collapse navigation"}
          >
            <Icon name="collapse" className={clsx("w-4 h-4 transition-transform", collapsed && "rotate-180")} />
            {!collapsed && <span className="text-xs font-medium">Collapse</span>}
          </button>
        </div>
      </aside>

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-16 shrink-0 bg-soc-panel border-b border-soc-border flex items-center gap-4 px-6">
          <div className="min-w-0">
            <div className="text-[11px] font-medium" style={{ color: "var(--ink-faint)" }}>
              {currentLabel.section}
            </div>
            <div className="text-sm font-semibold truncate" style={{ color: "var(--ink)" }}>
              {currentLabel.page}
            </div>
          </div>

          <div className="flex-1 max-w-md">
            <div className="relative">
              <Icon
                name="search"
                className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2"
                style={{ color: "var(--ink-faint)" }}
              />
              <input
                type="text"
                placeholder="Search devices, controls, findings…"
                className="input w-full pl-9"
              />
            </div>
          </div>

          <div className="flex-1" />

          <button
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            className="shrink-0 w-9 h-9 rounded-md border flex items-center justify-center transition-colors"
            style={{ borderColor: "var(--border)", color: "var(--ink-muted)" }}
          >
            <Icon name={theme === "dark" ? "sun" : "moon"} className="w-4 h-4" />
          </button>

          <div className="flex items-center gap-2.5 pl-3 border-l" style={{ borderColor: "var(--border)" }}>
            <div className="w-8 h-8 rounded-full bg-brand-soft flex items-center justify-center text-xs font-semibold" style={{ color: "var(--brand)" }}>
              {(username || "?").slice(0, 1).toUpperCase()}
            </div>
            <div className="hidden sm:block">
              <div className="text-sm font-medium leading-tight" style={{ color: "var(--ink)" }}>{username || "Unknown"}</div>
              <div className="text-[11px] leading-tight capitalize" style={{ color: "var(--ink-faint)" }}>{(role || "no role").replace("_", " ")}</div>
            </div>
            <button
              onClick={logout}
              className="p-2 rounded-md transition-colors hover:bg-red-500/10"
              style={{ color: "var(--ink-faint)" }}
              title="Logout"
            >
              <Icon name="logout" className="w-4 h-4" />
            </button>
          </div>
        </header>

        <main className="flex-1 min-w-0 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// A small, consistent set of hand-drawn line icons — one per nav group plus
// the header/rail controls — so the shell doesn't pull in an icon package
// for a dozen glyphs.
// ---------------------------------------------------------------------------

type IconName =
  | "grid" | "server" | "checklist" | "shield" | "spark" | "gear"
  | "chevron" | "collapse" | "search" | "sun" | "moon" | "logout";

function Icon({ name, className, style }: { name: IconName; className?: string; style?: React.CSSProperties }) {
  const common = {
    className,
    style,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.75,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };
  switch (name) {
    case "grid":
      return (
        <svg {...common}>
          <rect x="3.5" y="3.5" width="7" height="7" rx="1.2" />
          <rect x="13.5" y="3.5" width="7" height="7" rx="1.2" />
          <rect x="3.5" y="13.5" width="7" height="7" rx="1.2" />
          <rect x="13.5" y="13.5" width="7" height="7" rx="1.2" />
        </svg>
      );
    case "server":
      return (
        <svg {...common}>
          <rect x="3.5" y="4" width="17" height="6.5" rx="1.4" />
          <rect x="3.5" y="13.5" width="17" height="6.5" rx="1.4" />
          <circle cx="7.2" cy="7.25" r="0.9" fill="currentColor" stroke="none" />
          <circle cx="7.2" cy="16.75" r="0.9" fill="currentColor" stroke="none" />
        </svg>
      );
    case "checklist":
      return (
        <svg {...common}>
          <path d="M9 5h11" />
          <path d="M9 12h11" />
          <path d="M9 19h11" />
          <path d="M4 5l1.2 1.2L7.2 4" />
          <path d="M4 12l1.2 1.2L7.2 11" />
          <path d="M4 19l1.2 1.2L7.2 18" />
        </svg>
      );
    case "shield":
      return (
        <svg {...common}>
          <path d="M12 3.5l7 2.6v5.4c0 4.6-2.9 7.9-7 9-4.1-1.1-7-4.4-7-9V6.1l7-2.6z" />
          <path d="M9.2 12l1.9 1.9 3.7-3.9" />
        </svg>
      );
    case "spark":
      return (
        <svg {...common}>
          <path d="M12 3.5l1.7 4.9 4.9 1.7-4.9 1.7-1.7 4.9-1.7-4.9-4.9-1.7 4.9-1.7 1.7-4.9z" />
          <path d="M18.5 15.5l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z" />
        </svg>
      );
    case "gear":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 3.5v2.2M12 18.3v2.2M20.5 12h-2.2M5.7 12H3.5M17.7 6.3l-1.5 1.5M7.8 16.2l-1.5 1.5M17.7 17.7l-1.5-1.5M7.8 7.8L6.3 6.3" />
        </svg>
      );
    case "chevron":
      return (
        <svg {...common}>
          <path d="M6 9l6 6 6-6" />
        </svg>
      );
    case "collapse":
      return (
        <svg {...common}>
          <rect x="3.5" y="4" width="17" height="16" rx="2" />
          <path d="M9.5 4v16" />
          <path d="M15 10l-2.5 2 2.5 2" />
        </svg>
      );
    case "search":
      return (
        <svg {...common}>
          <circle cx="10.5" cy="10.5" r="6.5" />
          <path d="M20 20l-4.8-4.8" />
        </svg>
      );
    case "sun":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 3v1.6M12 19.4V21M4.9 4.9l1.1 1.1M18 18l1.1 1.1M3 12h1.6M19.4 12H21M4.9 19.1L6 18M18 6l1.1-1.1" />
        </svg>
      );
    case "moon":
      return (
        <svg {...common}>
          <path d="M20 14.2A8.2 8.2 0 1 1 9.8 4 6.6 6.6 0 0 0 20 14.2z" />
        </svg>
      );
    case "logout":
      return (
        <svg {...common}>
          <path d="M9 4.5H6a1.5 1.5 0 0 0-1.5 1.5v12A1.5 1.5 0 0 0 6 19.5h3" />
          <path d="M13.5 8l4 4-4 4" />
          <path d="M17.2 12H9" />
        </svg>
      );
  }
}