import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { useTheme } from "./theme";
import { useAuth } from "./context/AuthContext";
import RunningPipelines from "./components/RunningPipelines";

type IconName =
  | "grid" | "server" | "checklist" | "shield" | "spark" | "gear"
  | "chevron" | "collapse" | "search" | "sun" | "moon" | "logout"
  | "device" | "backup" | "network-scan" | "schedule" | "event" | "lab"
  | "finding" | "drift" | "validate" | "report" | "report-verify"
  | "topology" | "evidence" | "bell" | "library" | "vuln"
  | "queue" | "ai" | "train"
  | "config-search" | "ingest" | "knowledge" | "health" | "observe" | "audit"
  | "menu" | "x" | "home";

type NavItem = { to: string; label: string; icon: IconName; end?: boolean; roles?: string[] };
type NavGroup = { key: string; label: string; icon: IconName; items: NavItem[] };

const NAV_GROUPS: NavGroup[] = [
  {
    key: "overview",
    label: "Overview",
    icon: "grid",
    items: [{ to: "/", label: "Dashboard", icon: "home", end: true }],
  },
  {
    key: "operations",
    label: "Operations",
    icon: "server",
    items: [
      { to: "/devices", label: "Devices", icon: "device" },
      { to: "/backups", label: "Config Backups", icon: "backup" },
      { to: "/network-scans", label: "Network Scans", icon: "network-scan", roles: ["admin", "security_analyst", "operator"] },
      { to: "/schedules", label: "Schedules", icon: "schedule" },
      { to: "/event-triggers", label: "Event Scanning", icon: "event" },
      { to: "/gns3-integration", label: "GNS3 Sandbox", icon: "lab", roles: ["admin", "security_analyst"] },
    ],
  },
  {
    key: "compliance",
    label: "Compliance",
    icon: "checklist",
    items: [
      { to: "/compliance", label: "Findings", icon: "finding" },
      { to: "/drift", label: "Drift", icon: "drift" },
      { to: "/validation", label: "Validation", icon: "validate", roles: ["admin", "security_analyst", "operator"] },
      { to: "/reports", label: "Reports", icon: "report" },
      { to: "/report-verification", label: "Report Verify", icon: "report-verify" },
    ],
  },
  {
    key: "security",
    label: "Security",
    icon: "shield",
    items: [
      { to: "/topology", label: "Topology", icon: "topology" },
      { to: "/evidence", label: "Evidence Ledger", icon: "evidence" },
      { to: "/alerts", label: "Alerts", icon: "bell" },
      { to: "/control-library", label: "Control Library", icon: "library", roles: ["admin", "security_analyst", "auditor"] },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: "vuln" },
    ],
  },
  {
    key: "ai",
    label: "AI",
    icon: "spark",
    items: [
      { to: "/review-queue", label: "Review Queue", icon: "queue" },
      { to: "/ai-analysis", label: "AI Analysis", icon: "ai" },
      { to: "/training", label: "Training Center", icon: "train", roles: ["admin", "security_analyst"] },
    ],
  },
  {
    key: "administration",
    label: "Admin",
    icon: "gear",
    items: [
      { to: "/config-search", label: "Config Search", icon: "config-search" },
      { to: "/ingestion", label: "Ingestion", icon: "ingest", roles: ["admin", "security_analyst"] },
      { to: "/knowledge-base", label: "Knowledge Base", icon: "knowledge", roles: ["admin", "security_analyst", "auditor"] },
      { to: "/system/health", label: "System Health", icon: "health", roles: ["admin"] },
      { to: "/observability", label: "Observability", icon: "observe", roles: ["admin"] },
      { to: "/audit-log", label: "Audit Log", icon: "audit", roles: ["admin", "auditor"] },
    ],
  },
];

const RAIL_KEY = "netsecauditor.railCollapsed";
const GROUP_KEY_PREFIX = "netsecauditor.navgroup.";

/* ── Tooltip shown in fully-collapsed mode on hover ── */
function NavTooltip({ label }: { label: string }) {
  return (
    <span
      className="pointer-events-none absolute left-[calc(100%+8px)] top-1/2 -translate-y-1/2 z-50
        whitespace-nowrap rounded-md px-2.5 py-1.5 text-xs font-medium shadow-xl
        opacity-0 group-hover/tip:opacity-100 transition-opacity duration-150"
      style={{ background: "var(--paper-float)", color: "var(--ink)", border: "1px solid var(--border)" }}
    >
      {label}
    </span>
  );
}

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const { logout, role, username } = useAuth();
  const location = useLocation();
  const hoverTimerRef = useRef<number | null>(null);

  /* ── sidebar state ── */
  const [pinCollapsed, setPinCollapsed] = useState<boolean>(
    () => localStorage.getItem(RAIL_KEY) === "1"
  );
  const [hoverExpanded, setHoverExpanded] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const collapsed = pinCollapsed && !hoverExpanded;

  useEffect(() => localStorage.setItem(RAIL_KEY, pinCollapsed ? "1" : "0"), [pinCollapsed]);

  // Close mobile nav on route change
  useEffect(() => setMobileOpen(false), [location.pathname]);

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

  /* Hover expand/collapse with small delay to avoid flicker */
  const handleMouseEnter = () => {
    if (!pinCollapsed) return;
    if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
    hoverTimerRef.current = window.setTimeout(() => setHoverExpanded(true), 80);
  };
  const handleMouseLeave = () => {
    if (!pinCollapsed) return;
    if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
    hoverTimerRef.current = window.setTimeout(() => setHoverExpanded(false), 120);
  };

  /* ── shared sidebar content ── */
  const SidebarContent = ({ mobile = false }: { mobile?: boolean }) => (
    <>
      {/* Brand */}
      <div
        className={clsx(
          "h-16 border-b border-rail-border flex items-center justify-between gap-2",
          mobile ? "px-4" : "px-3"
        )}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="shrink-0 w-8 h-8 rounded bg-seal flex items-center justify-center text-[13px] font-semibold text-white tracking-tight">
            NR
          </div>
          {(!collapsed || mobile) && (
            <div className="min-w-0">
              <div className="text-rail-text font-semibold text-sm leading-tight truncate">NullRoute</div>
              <div className="text-[11px] text-rail-textDim leading-tight truncate">Multi-vendor compliance</div>
            </div>
          )}
        </div>
        {mobile && (
          <button
            onClick={() => setMobileOpen(false)}
            className="p-1.5 rounded-md text-rail-textDim hover:text-rail-text hover:bg-white/10 transition-colors"
          >
            <Icon name="x" className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-3 overflow-y-auto overflow-x-hidden rail-scroll space-y-0.5">
        {filteredNavGroups.map((group) => {
          const isClosed = (!collapsed || mobile) && closedGroups[group.key];
          return (
            <div key={group.key}>
              {/* Group header */}
              <button
                type="button"
                onClick={() => (!collapsed || mobile) && toggleGroup(group.key)}
                className={clsx(
                  "relative group/tip w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-rail-textDim hover:text-rail-text hover:bg-white/[0.05] transition-colors",
                  (collapsed && !mobile) && "justify-center"
                )}
                title={group.label}
              >
                <Icon name={group.icon} className="w-[18px] h-[18px] shrink-0" />
                {(!collapsed || mobile) ? (
                  <>
                    <span className="rail-nav-group-label flex-1 text-left text-[13px] font-medium">{group.label}</span>
                    <Icon
                      name="chevron"
                      className={clsx("w-3.5 h-3.5 shrink-0 transition-transform", isClosed && "-rotate-90")}
                    />
                  </>
                ) : (
                  <NavTooltip label={group.label} />
                )}
              </button>

              {/* Group items */}
              {!isClosed && (
                <div
                  className={clsx(
                    "space-y-0.5",
                    (collapsed && !mobile)
                      ? "mt-0.5"
                      : "mt-0.5 ml-[13px] pl-[19px] border-l border-rail-border"
                  )}
                >
                  {group.items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.end}
                      title={(collapsed && !mobile) ? item.label : undefined}
                      className={({ isActive }) =>
                        clsx(
                          "relative group/tip flex items-center gap-2 rounded-md text-[13px] transition-colors",
                          isActive ? "active" : "",
                          (collapsed && !mobile)
                            ? "mx-auto w-9 h-9 justify-center"
                            : "px-2.5 py-1.5",
                          isActive
                            ? (collapsed && !mobile)
                              ? "bg-seal/20 text-seal"
                              : "bg-white/[0.08] text-white"
                            : (collapsed && !mobile)
                            ? "text-rail-textDim hover:bg-white/[0.06] hover:text-rail-text"
                            : "text-rail-textDim hover:bg-white/[0.06] hover:text-rail-text"
                        )
                      }
                    >
                      {({ isActive }) => (
                        <>
                          {/* Active pill – expanded */}
                          {(!collapsed || mobile) && isActive && (
                            <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full bg-seal -ml-[19px]" />
                          )}
                          <Icon name={item.icon} className={clsx("shrink-0", (collapsed && !mobile) ? "w-[18px] h-[18px]" : "w-[15px] h-[15px]")} />
                          {(!collapsed || mobile) && <span>{item.label}</span>}
                          {(collapsed && !mobile) && <NavTooltip label={item.label} />}
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

      {/* Pin/Collapse toggle - desktop only */}
      {!mobile && (
        <div className="p-2.5 border-t border-rail-border">
          <button
            type="button"
            onClick={() => { setPinCollapsed((c) => !c); setHoverExpanded(false); }}
            className="w-full flex items-center justify-center gap-2 py-2 rounded-md text-rail-textDim hover:text-rail-text hover:bg-white/[0.04] transition-colors"
            title={pinCollapsed ? "Pin sidebar open" : "Collapse sidebar"}
          >
            <Icon name="collapse" className={clsx("w-4 h-4 transition-transform", pinCollapsed && "rotate-180")} />
            {!collapsed && <span className="text-xs font-medium">Collapse</span>}
          </button>
        </div>
      )}
    </>
  );

  return (
    <div className="min-h-screen flex" style={{ backgroundColor: "var(--paper)" }}>
      {/* ── Desktop sidebar ── */}
      <aside
        className={clsx(
          "hidden md:flex shrink-0 bg-rail border-r border-rail-border flex-col transition-[width] duration-200 ease-out overflow-hidden",
          collapsed ? "w-[60px]" : "w-60"
        )}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
      >
        <SidebarContent />
      </aside>

      {/* ── Mobile sidebar overlay ── */}
      {mobileOpen && (
        <div
          className="md:hidden fixed inset-0 z-50 flex"
          role="dialog"
          aria-label="Navigation"
        >
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
          />
          {/* Drawer */}
          <aside
            className="relative z-10 flex flex-col bg-rail border-r border-rail-border w-72 max-w-[85vw] h-full"
            style={{ animation: "slideInLeft 0.2s ease-out" }}
          >
            <SidebarContent mobile />
          </aside>
        </div>
      )}

      {/* ── Main content ── */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top header */}
        <header className="h-14 md:h-16 shrink-0 bg-soc-panel border-b border-soc-border flex items-center gap-3 md:gap-4 px-3 md:px-6">
          {/* Mobile menu button */}
          <button
            className="md:hidden shrink-0 w-9 h-9 rounded-md flex items-center justify-center transition-colors hover:bg-white/10"
            style={{ color: "var(--ink-muted)" }}
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
          >
            <Icon name="menu" className="w-5 h-5" />
          </button>

          {/* Breadcrumb */}
          <div className="min-w-0 flex-1 md:flex-none">
            <div className="text-[11px] font-medium hidden md:block" style={{ color: "var(--ink-faint)" }}>
              {currentLabel.section}
            </div>
            <div className="text-sm font-semibold truncate" style={{ color: "var(--ink)" }}>
              {currentLabel.page}
            </div>
          </div>

          {/* Desktop search */}
          <div className="hidden md:block flex-1 max-w-md">
            <div className="relative">
              <Icon name="search" className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "var(--ink-faint)" }} />
              <input type="text" placeholder="Search devices, controls, findings…" className="input w-full pl-9" />
            </div>
          </div>

          <div className="flex-1 md:flex-none" />

          <RunningPipelines />

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            className="shrink-0 w-9 h-9 rounded-md border flex items-center justify-center transition-colors"
            style={{ borderColor: "var(--border)", color: "var(--ink-muted)" }}
          >
            <Icon name={theme === "dark" ? "sun" : "moon"} className="w-4 h-4" />
          </button>

          {/* User pill */}
          <div className="flex items-center gap-2 pl-2 md:pl-3 border-l" style={{ borderColor: "var(--border)" }}>
            <div className="w-8 h-8 rounded-full bg-brand-soft flex items-center justify-center text-xs font-semibold" style={{ color: "var(--brand)" }}>
              {(username || "?").slice(0, 1).toUpperCase()}
            </div>
            <NavLink to="/account" title="Account" className="hidden lg:block">
              <div className="text-sm font-medium leading-tight" style={{ color: "var(--ink)" }}>{username || "Unknown"}</div>
              <div className="text-[11px] leading-tight capitalize" style={{ color: "var(--ink-faint)" }}>{(role || "no role").replace("_", " ")}</div>
            </NavLink>
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

        {/* Page */}
        <main className="flex-1 min-w-0 overflow-y-auto">
          <Outlet />
        </main>

        {/* ── Mobile bottom nav ── */}
        <nav className="md:hidden shrink-0 border-t border-soc-border bg-soc-panel flex items-center justify-around px-1 py-1 safe-area-pb">
          {filteredNavGroups.slice(0, 5).map((group) => {
            const isActive = group.items.some((item) =>
              item.end ? location.pathname === item.to : location.pathname.startsWith(item.to)
            );
            // Navigate to first item in group
            const firstItem = group.items[0];
            return (
              <NavLink
                key={group.key}
                to={firstItem.to}
                end={firstItem.end}
                className={() =>
                  clsx(
                    "flex flex-col items-center gap-0.5 px-3 py-2 rounded-xl transition-colors text-[10px] font-medium",
                    isActive ? "text-seal bg-seal/10" : "text-rail-textDim"
                  )
                }
              >
                <Icon name={group.icon} className="w-5 h-5" />
                <span>{group.label}</span>
              </NavLink>
            );
          })}
          {/* "More" opens the mobile drawer */}
          <button
            onClick={() => setMobileOpen(true)}
            className="flex flex-col items-center gap-0.5 px-3 py-2 rounded-xl transition-colors text-[10px] font-medium text-rail-textDim"
          >
            <Icon name="menu" className="w-5 h-5" />
            <span>More</span>
          </button>
        </nav>
      </div>

      {/* Slide-in animation keyframes */}
      <style>{`
        @keyframes slideInLeft {
          from { transform: translateX(-100%); }
          to   { transform: translateX(0); }
        }
        .safe-area-pb { padding-bottom: max(0.25rem, env(safe-area-inset-bottom)); }
      `}</style>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Icons — expanded set for group headers AND individual nav items
// ---------------------------------------------------------------------------

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
    // ── group icons ──
    case "grid":
    case "home":
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
          <path d="M9 5h11" /><path d="M9 12h11" /><path d="M9 19h11" />
          <path d="M4 5l1.2 1.2L7.2 4" /><path d="M4 12l1.2 1.2L7.2 11" /><path d="M4 19l1.2 1.2L7.2 18" />
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
    // ── util ──
    case "chevron":
      return (<svg {...common}><path d="M6 9l6 6 6-6" /></svg>);
    case "collapse":
      return (
        <svg {...common}>
          <rect x="3.5" y="4" width="17" height="16" rx="2" />
          <path d="M9.5 4v16" />
          <path d="M15 10l-2.5 2 2.5 2" />
        </svg>
      );
    case "search":
      return (<svg {...common}><circle cx="10.5" cy="10.5" r="6.5" /><path d="M20 20l-4.8-4.8" /></svg>);
    case "sun":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 3v1.6M12 19.4V21M4.9 4.9l1.1 1.1M18 18l1.1 1.1M3 12h1.6M19.4 12H21M4.9 19.1L6 18M18 6l1.1-1.1" />
        </svg>
      );
    case "moon":
      return (<svg {...common}><path d="M20 14.2A8.2 8.2 0 1 1 9.8 4 6.6 6.6 0 0 0 20 14.2z" /></svg>);
    case "logout":
      return (
        <svg {...common}>
          <path d="M9 4.5H6a1.5 1.5 0 0 0-1.5 1.5v12A1.5 1.5 0 0 0 6 19.5h3" />
          <path d="M13.5 8l4 4-4 4" />
          <path d="M17.2 12H9" />
        </svg>
      );
    case "menu":
      return (<svg {...common}><path d="M4 6h16M4 12h16M4 18h16" /></svg>);
    case "x":
      return (<svg {...common}><path d="M18 6L6 18M6 6l12 12" /></svg>);
    // ── sub-item icons ──
    case "device":
      return (<svg {...common}><rect x="5" y="3" width="14" height="18" rx="2" /><circle cx="12" cy="17" r="1" fill="currentColor" stroke="none" /></svg>);
    case "backup":
      return (
        <svg {...common}>
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
      );
    case "network-scan":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="3" />
          <path d="M4.9 4.9l2.1 2.1M17 7l2.1-2.1M4.9 19.1l2.1-2.1M17 17l2.1 2.1" />
          <circle cx="12" cy="12" r="8" strokeDasharray="4 2" />
        </svg>
      );
    case "schedule":
      return (
        <svg {...common}>
          <rect x="3" y="4" width="18" height="18" rx="2" />
          <path d="M16 2v4M8 2v4M3 10h18" />
          <path d="M8 14h.01M12 14h.01M16 14h.01M8 18h.01M12 18h.01" />
        </svg>
      );
    case "event":
      return (
        <svg {...common}>
          <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
        </svg>
      );
    case "lab":
      return (
        <svg {...common}>
          <path d="M9 3h6M10 3v7l-4 9a1 1 0 0 0 .9 1.5h10.2A1 1 0 0 0 18 19l-4-9V3" />
        </svg>
      );
    case "finding":
      return (
        <svg {...common}>
          <circle cx="11" cy="11" r="7" />
          <path d="M11 8v3l2 2M21 21l-4.35-4.35" />
        </svg>
      );
    case "drift":
      return (
        <svg {...common}>
          <path d="M3 12h4l3-7 4 14 3-7h4" />
        </svg>
      );
    case "validate":
      return (
        <svg {...common}>
          <path d="M9 12l2 2 4-4" />
          <path d="M20.6 12a8.6 8.6 0 1 1-17.2 0 8.6 8.6 0 0 1 17.2 0z" />
        </svg>
      );
    case "report":
      return (
        <svg {...common}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="16" y1="13" x2="8" y2="13" />
          <line x1="16" y1="17" x2="8" y2="17" />
          <line x1="10" y1="9" x2="8" y2="9" />
        </svg>
      );
    case "report-verify":
      return (
        <svg {...common}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <path d="M9 15l2 2 4-4" />
        </svg>
      );
    case "topology":
      return (
        <svg {...common}>
          <circle cx="12" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><circle cx="19" cy="19" r="2" />
          <path d="M12 7v4M12 11l-5.5 6M12 11l5.5 6" />
        </svg>
      );
    case "evidence":
      return (
        <svg {...common}>
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <path d="M7 7h10M7 12h10M7 17h6" />
        </svg>
      );
    case "bell":
      return (
        <svg {...common}>
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
      );
    case "library":
      return (
        <svg {...common}>
          <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
          <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
        </svg>
      );
    case "vuln":
      return (
        <svg {...common}>
          <path d="M12 9v4M12 17h.01" />
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        </svg>
      );
    case "queue":
      return (
        <svg {...common}>
          <path d="M9 11l3 3L22 4" />
          <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
        </svg>
      );
    case "ai":
      return (
        <svg {...common}>
          <path d="M12 3.5l1.7 4.9 4.9 1.7-4.9 1.7-1.7 4.9-1.7-4.9-4.9-1.7 4.9-1.7 1.7-4.9z" />
          <path d="M5 17l.5 1.5L7 19l-1.5.5L5 21l-.5-1.5L3 19l1.5-.5z" />
        </svg>
      );
    case "train":
      return (
        <svg {...common}>
          <rect x="4" y="4" width="16" height="12" rx="2" />
          <path d="M8 20l4-4 4 4M12 16v4" />
          <path d="M4 10h16" />
        </svg>
      );
    case "config-search":
      return (<svg {...common}><circle cx="10.5" cy="10.5" r="6.5" /><path d="M20 20l-4.8-4.8M8 8h5M8 11h3" /></svg>);
    case "ingest":
      return (
        <svg {...common}>
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
      );
    case "knowledge":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" />
          <path d="M12 8v4M12 16h.01" />
        </svg>
      );
    case "health":
      return (
        <svg {...common}>
          <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
        </svg>
      );
    case "observe":
      return (
        <svg {...common}>
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      );
    case "audit":
      return (
        <svg {...common}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <path d="M8 13h8M8 17h5" />
        </svg>
      );
    default:
      return null;
  }
}