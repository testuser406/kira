import { useEffect, useRef, useState, type ReactNode } from "react";
import { useSession } from "./AuthGate";

export type PageId =
  | "overview" | "bandwidth" | "productivity" | "security" | "vpn"
  | "reports" | "productivity_report" | "schedules" | "custom"
  | "events" | "alerts" | "system" | "retention";

type NavItem = { id: PageId; label: string; icon: string; title: string; desc: string; range?: boolean };
export const NAV: { group: string; items: NavItem[] }[] = [
  { group: "Monitoring", items: [
    { id: "overview", label: "Overview", icon: "M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z", title: "Overview", desc: "Traffic, threats and top talkers for the selected period.", range: true },
    { id: "bandwidth", label: "Live Bandwidth", icon: "M3 17l6-6 4 4 8-8M21 7v6h-6", title: "Live Bandwidth", desc: "Per-minute traffic, top users, applications and destinations." },
    { id: "productivity", label: "Live Productivity", icon: "M12 8v5l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", title: "Live Productivity", desc: "Productive, neutral and unproductive browsing right now." },
    { id: "security", label: "Live Security", icon: "M12 3 4 6v6c0 5 3.4 8.3 8 9 4.6-.7 8-4 8-9V6l-8-3Z", title: "Live Security", desc: "Threats, blocks and IPS/AV/ATP events per minute." },
    { id: "vpn", label: "Live VPN", icon: "M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5V11Z", title: "Live VPN", desc: "Active tunnels, users and traffic per tunnel." },
  ]},
  { group: "Reporting", items: [
    { id: "reports", label: "Reports", icon: "M7 3h8l4 4v14H7V3Zm8 0v4h4M10 13h6M10 17h6", title: "Reports", desc: "Build, preview, export and share reports from the full history." },
    { id: "productivity_report", label: "Productivity", icon: "M4 20V10m6 10V4m6 16v-7m6 7H2", title: "Productivity", desc: "Browsing time, categories and Site Clean." },
    { id: "schedules", label: "Scheduled Reports", icon: "M8 3v4m8-4v4M4 9h16M5 5h14v16H5V5Z", title: "Scheduled Reports", desc: "Reports delivered automatically by e-mail or webhook." },
    { id: "custom", label: "Custom Reports", icon: "M12 5v14M5 12h14", title: "Custom Reports", desc: "Saved report definitions with their own filters." },
  ]},
  { group: "Investigation", items: [
    { id: "events", label: "Event Explorer", icon: "M21 21l-4.3-4.3M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z", title: "Event Explorer", desc: "Search and filter raw firewall events.", range: true },
  ]},
  { group: "Alerting", items: [
    { id: "alerts", label: "Alert Rules", icon: "M15 17h5l-1.4-1.4A2 2 0 0 1 18 14.2V11a6 6 0 0 0-12 0v3.2a2 2 0 0 1-.6 1.4L4 17h5m6 0a3 3 0 1 1-6 0", title: "Alert Rules", desc: "Thresholds, notifications and delivery." },
  ]},
  { group: "Administration", items: [
    { id: "system", label: "System", icon: "M4 6h16M4 12h16M4 18h16", title: "System", desc: "Health, diagnostics, privacy, users and audit log." },
    { id: "retention", label: "Data Retention", icon: "M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3Zm0 0v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7", title: "Data Retention", desc: "How long raw events and aggregates are kept." },
  ]},
];
export const ALL_ITEMS = NAV.flatMap((g) => g.items.map((i) => ({ ...i, group: g.group })));

export function usePage(): [PageId, (p: PageId) => void] {
  const read = (): PageId => {
    const id = window.location.hash.replace(/^#\/?/, "") as PageId;
    return ALL_ITEMS.some((i) => i.id === id) ? id : "overview";
  };
  const [page, setPage] = useState<PageId>(read);
  useEffect(() => {
    const on = () => setPage(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return [page, (p) => { window.location.hash = `/${p}`; }];
}

export function Icon({ d, className = "h-[18px] w-[18px]" }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}

export function Sidebar(props: {
  page: PageId; onNavigate: (p: PageId) => void; collapsed: boolean; onToggle: () => void;
  mobileOpen: boolean; onClose: () => void; footer: ReactNode;
}) {
  const { page, onNavigate, collapsed, onToggle, mobileOpen, onClose, footer } = props;
  return (
    <>
      {mobileOpen && <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={onClose} />}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-white/[0.06] bg-[#060a12] transition-all duration-200 lg:sticky lg:top-0 lg:z-20 lg:h-screen ${
          mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        } ${collapsed ? "w-[68px]" : "w-64"}`}
      >
        <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-white/[0.06] px-4">
          <svg viewBox="0 0 32 32" className="h-7 w-7 shrink-0" aria-hidden="true">
            <path d="M16 2 4 7v9c0 7.2 5.1 12.4 12 14 6.9-1.6 12-6.8 12-14V7L16 2Z" fill="#10b981" />
            <path d="M16 9v9m0 4v.5" stroke="#04110c" strokeWidth="2.4" strokeLinecap="round" />
          </svg>
          {!collapsed && (
            <div className="leading-tight">
              <div className="text-[15px] font-semibold tracking-tight text-slate-50">Kira</div>
              <div className="text-[9px] uppercase tracking-[0.18em] text-slate-500">Firewall Analytics</div>
            </div>
          )}
        </div>
        <nav className="flex-1 overflow-y-auto px-2.5 py-3">
          {NAV.map((g) => (
            <div key={g.group} className="mb-4">
              {!collapsed ? (
                <div className="px-2.5 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-600">{g.group}</div>
              ) : (
                <div className="mx-2 mb-2 border-t border-white/[0.05]" />
              )}
              {g.items.map((i) => {
                const active = page === i.id;
                return (
                  <button
                    key={i.id}
                    type="button"
                    title={collapsed ? i.label : undefined}
                    onClick={() => { onNavigate(i.id); onClose(); }}
                    className={`group relative mb-0.5 flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left text-[13px] transition ${
                      active ? "bg-emerald-400/[0.10] font-medium text-emerald-300" : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-100"
                    } ${collapsed ? "justify-center" : ""}`}
                  >
                    {active && <span className="absolute left-0 top-1.5 h-[calc(100%-12px)] w-[3px] rounded-r bg-emerald-400" />}
                    <Icon d={i.icon} />
                    {!collapsed && <span className="truncate">{i.label}</span>}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="shrink-0 border-t border-white/[0.06] p-3">
          {!collapsed && <div className="mb-2 text-[11px] text-slate-500">{footer}</div>}
          <button
            type="button"
            onClick={onToggle}
            className="hidden w-full items-center justify-center gap-2 rounded-lg border border-white/[0.06] py-1.5 text-[11px] text-slate-500 hover:text-slate-200 lg:flex"
          >
            <Icon d={collapsed ? "M9 6l6 6-6 6" : "M15 6l-6 6 6 6"} className="h-4 w-4" />
            {!collapsed && "Collapse"}
          </button>
        </div>
      </aside>
    </>
  );
}

export function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem("kira.theme") || "dark"; } catch { return "dark"; }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("light", theme === "light");
    try { localStorage.setItem("kira.theme", theme); } catch { /* ignore */ }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "light" ? "dark" : "light"))];
}

export function UserMenu({ theme, onTheme }: { theme: string; onTheme: () => void }) {
  const session = useSession();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const on = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const key = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", on);
    document.addEventListener("keydown", key);
    return () => { document.removeEventListener("mousedown", on); document.removeEventListener("keydown", key); };
  }, [open]);
  if (!session) return null;
  const { me, signOut, openAccount } = session;
  const name = me.auth_disabled ? "Local access" : me.username;
  const initials = name.slice(0, 2).toUpperCase();
  return (
    <div ref={ref} className="relative">
      <button type="button" onClick={() => setOpen((o) => !o)} className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] py-1 pl-1 pr-2.5 hover:bg-white/[0.06]" aria-haspopup="menu" aria-expanded={open}>
        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-emerald-500/20 text-[11px] font-semibold text-emerald-300">{initials}</span>
        <span className="hidden text-left leading-tight sm:block">
          <span className="block text-xs font-medium text-slate-200">{name}</span>
          <span className="block text-[10px] capitalize text-slate-500">{me.auth_disabled ? "auth disabled" : me.role}</span>
        </span>
        <Icon d="M6 9l6 6 6-6" className="h-3.5 w-3.5 text-slate-500" />
      </button>
      {open && (
        <div role="menu" className="absolute right-0 top-full z-50 mt-2 w-60 overflow-hidden rounded-xl border border-white/10 bg-[#0b1220] shadow-2xl shadow-black/50">
          <div className="border-b border-white/[0.06] px-4 py-3">
            <div className="text-sm font-medium text-slate-100">{name}</div>
            <div className="mt-0.5 text-[11px] capitalize text-slate-500">{me.auth_disabled ? "Authentication is disabled" : `${me.role} account`}</div>
          </div>
          <div className="p-1.5 text-[13px]">
            {!me.auth_disabled && (
              <MenuItem onClick={() => { setOpen(false); openAccount(); }} icon="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-8 9a8 8 0 0 1 16 0">Account &amp; password</MenuItem>
            )}
            <MenuItem onClick={onTheme} icon="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z">{theme === "light" ? "Dark theme" : "Light theme"}</MenuItem>
            {!me.auth_disabled && (
              <>
                <div className="my-1 border-t border-white/[0.06]" />
                <MenuItem onClick={() => void signOut()} icon="M15 17l5-5-5-5M20 12H9m4 8H5V4h8">Sign out</MenuItem>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function MenuItem({ children, icon, onClick }: { children: ReactNode; icon: string; onClick: () => void }) {
  return (
    <button type="button" role="menuitem" onClick={onClick} className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-slate-300 hover:bg-white/[0.06] hover:text-white">
      <Icon d={icon} className="h-4 w-4 text-slate-500" />
      {children}
    </button>
  );
}
