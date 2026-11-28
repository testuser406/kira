import { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { fmtAgo, fmtNumber } from "./format";
import type { EventRow, Meta, Overview, TopRow } from "./types";
import { EventsTable } from "./components/EventsTable";
import { RetentionControl } from "./components/RetentionControl";
import { KpiCards } from "./components/KpiCards";
import { CollectorPanel, SecurityPanel } from "./components/SidePanels";
import { TopPanel } from "./components/TopPanel";
import { TrafficChart, type TrafficMode } from "./components/TrafficChart";
import { Suspense, lazy } from "react";
import type { LiveKind } from "./components/LiveMinute";
const LiveMinuteView = lazy(() => import("./components/LiveMinute").then((m) => ({ default: m.LiveMinuteView })));
const ReportsPage = lazy(() => import("./components/ReportsPage").then((m) => ({ default: m.ReportsPage })));
const DestinationsPage = lazy(() => import("./components/DestinationsPage").then((m) => ({ default: m.DestinationsPage })));
const SecurityPage = lazy(() => import("./components/SecurityPage").then((m) => ({ default: m.SecurityPage })));
const ProductivityPage = lazy(() => import("./components/ProductivityPage").then((m) => ({ default: m.ProductivityPage })));
const SystemPage = lazy(() => import("./components/SystemPage").then((m) => ({ default: m.SystemPage })));
import AlertRulesManager from "./components/AlertRulesManager";
import ReportSchedulesManager from "./components/ReportSchedulesManager";
import CustomReportsManager from "./components/CustomReportsManager";
import { Card, Skeleton, Spinner } from "./components/ui";
import type { EventCursor, EventFilters } from "./types";
import { ALL_ITEMS, Icon, Sidebar, UserMenu, hashQuery, usePage, useTheme } from "./components/Shell";
import { SearchPage } from "./components/SearchPage";

const RANGES = [
  { id: "1h", label: "1h", hours: 1 },
  { id: "6h", label: "6h", hours: 6 },
  { id: "24h", label: "24h", hours: 24 },
  { id: "7d", label: "7d", hours: 168 },
  { id: "30d", label: "30d", hours: 720 },
] as const;

type Tops = {
  users: TopRow[];
  destinations: TopRow[];
  categories: TopRow[];
  threats: TopRow[];
};

const EMPTY_TOPS: Tops = { users: [], destinations: [], categories: [], threats: [] };

export default function App() {
  const [tenant, setTenant] = useState("");
  const [range, setRange] = useState<string>("24h");
  const [mode, setMode] = useState<TrafficMode>("requests");
  const [live, setLive] = useState(true);
  const [tick, setTick] = useState(0);

  const [meta, setMeta] = useState<Meta | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [page, navigate] = usePage();
  const [mobileNav, setMobileNav] = useState(false);
  const [theme, toggleTheme] = useTheme();
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem("kira.nav") === "1"; } catch { return false; }
  });
  const toggleCollapsed = () => setCollapsed((c) => {
    try { localStorage.setItem("kira.nav", c ? "0" : "1"); } catch { /* ignore */ }
    return !c;
  });
  const [tops, setTops] = useState<Tops>(EMPTY_TOPS);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  // Filters are applied on Enter / Apply, not on every keystroke, so typing never floods the API.
  const [filters, setFilters] = useState<EventFilters>({ q: "", user: "", category: "", device: "" });
  const [action, setAction] = useState("");
  const [group, setGroup] = useState("");
  const [pageSize, setPageSize] = useState(() => {
    try { const n = Number(localStorage.getItem("kira.pageSize")); return [50, 100, 200, 500].includes(n) ? n : 100; } catch { return 100; }
  });
  const [cursors, setCursors] = useState<(EventCursor | null)[]>([null]);
  const [pageIndex, setPageIndex] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);

  const spanHours = useMemo(
    () => RANGES.find((option) => option.id === range)?.hours ?? 24,
    [range],
  );

  // Tenant list and collector health. Refreshed slowly: it does not drive charts.
  useEffect(() => {
    const controller = new AbortController();
    let refreshTimer: number | undefined;
    const load = async () => {
      try {
        const result = await api.meta(tenant || undefined, controller.signal);
        setMeta(result);
        if (!tenant) setTenant(result.tenant.slug);
      } catch (err) {
        if (controller.signal.aborted) return;
        const message = err instanceof Error ? err.message : String(err);
        if (tenant) {
          // Saved/selected tenant disappeared; fall back to the server default.
          setTenant("");
        }
        setError(message);
      } finally {
        if (!controller.signal.aborted) {
          refreshTimer = window.setTimeout(load, 5 * 60_000);
        }
      }
    };
    void load();
    return () => {
      controller.abort();
      if (refreshTimer !== undefined) window.clearTimeout(refreshTimer);
    };
  }, [tenant]);

  useEffect(() => {
    if (!tenant || (page !== "overview" && page !== "events")) return;
    const controller = new AbortController();
    let refreshTimer: number | undefined;
    setRefreshing(true);
    const load = async () => {
      try {
        const nextOverview = await api.overview(tenant, range, controller.signal);
        const users = await api.top(tenant, range, "users", 8, controller.signal);
        const destinations = await api.top(tenant, range, "destinations", 8, controller.signal);
        const categories = await api.top(tenant, range, "categories", 8, controller.signal);
        const threats = await api.top(tenant, range, "threats", 5, controller.signal);
        if (controller.signal.aborted) return;
        setOverview(nextOverview);
        setTops({
          users: users.rows,
          destinations: destinations.rows,
          categories: categories.rows,
          threats: threats.rows,
        });
        setError(null);
        setUpdatedAt(new Date());
      } catch (err) {
        if (controller.signal.aborted) return;
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!controller.signal.aborted) {
          setRefreshing(false);
          if (live) {
            refreshTimer = window.setTimeout(() => setTick((value) => value + 1), 60_000);
          }
        }
      }
    };
    void load();
    return () => {
      controller.abort();
      if (refreshTimer !== undefined) window.clearTimeout(refreshTimer);
    };
  }, [tenant, range, tick, live, page]);

  // Any filter / range / page-size change starts again from the newest page.
  useEffect(() => {
    setCursors([null]);
    setPageIndex(0);
  }, [tenant, range, filters, action, group, pageSize]);

  // Log entries: one request per page, keyed by the previous page's last event (no OFFSET scans).
  useEffect(() => {
    if (!tenant || page !== "events") return;
    const controller = new AbortController();
    setEventsLoading(true);
    const cursor = cursors[pageIndex] ?? null;
    api.events(
      tenant,
      range,
      {
        q: filters.q || undefined,
        action: action || undefined,
        group: group || undefined,
        user: filters.user || undefined,
        category: filters.category || undefined,
        device: filters.device || undefined,
        limit: pageSize,
        before_ts: cursor?.before_ts,
        before_id: cursor?.before_id,
      },
      controller.signal,
    )
      .then((r) => {
        if (controller.signal.aborted) return;
        setEvents(r.rows);
        setHasMore(r.has_more);
        // cursors[i] is where page i starts; keep it in step with what was just read.
        setCursors((prev) => (r.next ? [...prev.slice(0, pageIndex + 1), r.next] : prev.slice(0, pageIndex + 1)));
        setEventsError(null);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setEventsError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => { if (!controller.signal.aborted) setEventsLoading(false); });
    return () => controller.abort();
  // Live refresh only re-reads the newest page; older pages stay put while you read them.
  }, [tenant, range, filters, action, group, pageSize, pageIndex, page, pageIndex === 0 ? tick : 0]);

  const refresh = () => setTick((value) => value + 1);
  const hasData = overview !== null;
  const waitingForLogs = hasData && overview.totals.events === 0;

  const item = ALL_ITEMS.find((i) => i.id === page)!;
  const showControls = page === "overview" || page === "events";
  const kpis = page === "overview";

  const body = (() => {
    switch (page) {
      case "system": return <Suspense fallback={null}><SystemPage /></Suspense>;
      case "reports": return <Suspense fallback={null}><ReportsPage tenant={tenant} /></Suspense>;
      case "destinations": return <Suspense fallback={null}><DestinationsPage tenant={tenant} /></Suspense>;
      case "security_center": return <Suspense fallback={null}><SecurityPage tenant={tenant} /></Suspense>;
      case "productivity_report": return <Suspense fallback={null}><ProductivityPage tenant={tenant} /></Suspense>;
      case "bandwidth": case "productivity": case "security": case "vpn":
        return <Suspense fallback={null}><LiveMinuteView kind={page as LiveKind} tenant={tenant} /></Suspense>;
      case "search":
        return <SearchPage tenant={tenant} initialQuery={hashQuery()} onQuery={(q) => history.replaceState(null, "", `#/search?q=${encodeURIComponent(q)}`)} />;
      case "alerts": return <AlertRulesManager />;
      case "schedules": return <ReportSchedulesManager />;
      case "custom": return <CustomReportsManager />;
      case "retention":
        return (
          <Card className="p-5">
            <h2 className="text-sm font-semibold text-slate-100">Raw event retention</h2>
            <p className="mt-1 max-w-2xl text-sm text-slate-400">
              Raw events are kept for a short window; reports and dashboards use hourly and per-minute aggregates that are kept much longer.
              Changing the window shows a size preview first and needs the admin token.
            </p>
            <div className="mt-4"><RetentionControl /></div>
          </Card>
        );
      case "events":
        return (
          <EventsTable rows={events} loading={eventsLoading} error={eventsError} spanHours={spanHours} rawRetentionHours={meta?.raw_retention_hours ?? 6}
            filters={filters} onApply={setFilters} action={action} onAction={setAction} group={group} onGroup={setGroup}
            tenant={tenant} from={range}
            pageIndex={pageIndex} pageSize={pageSize} hasMore={hasMore}
            onPrev={() => setPageIndex((i) => Math.max(0, i - 1))}
            onNext={() => setPageIndex((i) => (hasMore ? i + 1 : i))}
            onPageSize={(n) => { setPageSize(n); try { localStorage.setItem("kira.pageSize", String(n)); } catch { /* ignore */ } }} />
        );
      default:
        if (!hasData) return <DashboardSkeleton />;
        if (waitingForLogs && !meta?.last_event_at) return <WaitingForLogs />;
        return (
          <>
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <TrafficChart series={overview.series} mode={mode} onMode={setMode} spanHours={spanHours} />
              </div>
              <div className="flex flex-col gap-4">
                <SecurityPanel total={overview.totals.threats} rows={tops.threats} loading={refreshing} />
                <CollectorPanel meta={meta} />
              </div>
            </div>
            <div className="grid gap-4 lg:grid-cols-3">
              <TopPanel title="Top users / hosts" hint="Usernames or source IPs when no username is logged" rows={tops.users} accent="sky" loading={refreshing} emptyHint="No usernames or source IP addresses were logged in this range." />
              <TopPanel title="Top destinations" hint="Websites and applications" rows={tops.destinations} accent="emerald" loading={refreshing} showBlocked={false} />
              <TopPanel title="Categories" hint="Web filter categories" rows={tops.categories} accent="violet" loading={refreshing} showBlocked={false} />
            </div>
          </>
        );
    }
  })();

  const lastSeen = meta?.last_event_at ? fmtAgo(meta.last_event_at) : null;
  return (
    <div className="flex min-h-screen">
      <Sidebar
        page={page}
        onNavigate={navigate}
        collapsed={collapsed}
        onToggle={toggleCollapsed}
        mobileOpen={mobileNav}
        onClose={() => setMobileNav(false)}
        footer={
          <span className="flex items-center gap-1.5">
            <span className={`h-1.5 w-1.5 rounded-full ${lastSeen ? "bg-emerald-400" : "bg-slate-600"}`} />
            {lastSeen ? `Last log ${lastSeen}` : "No logs yet"}
          </span>
        }
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-white/[0.06] bg-[#070b14]/90 px-4 backdrop-blur-md md:px-6">
          <button type="button" onClick={() => setMobileNav(true)} className="rounded-lg border border-white/10 p-1.5 text-slate-400 lg:hidden" aria-label="Open menu">
            <Icon d="M4 6h16M4 12h16M4 18h16" />
          </button>
          <nav className="hidden min-w-0 items-center gap-1.5 text-[13px] sm:flex" aria-label="Breadcrumb">
            <span className="text-slate-500">{(item as { group?: string }).group}</span>
            <span className="text-slate-700">/</span>
            <span className="truncate font-medium text-slate-200">{item.label}</span>
          </nav>
          <form className="ml-auto hidden md:block" onSubmit={(e) => { e.preventDefault(); const v = new FormData(e.currentTarget).get("q"); if (typeof v === "string" && v.trim().length >= 2) { window.location.hash = `/search?q=${encodeURIComponent(v.trim())}`; } }}>
            <input name="q" placeholder="Search users, sites, IPs…" className="w-56 rounded-lg border border-white/10 bg-black/25 px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-400/40 focus:outline-none lg:w-72" />
          </form>
          <div className="ml-2 flex items-center gap-2 md:ml-0">
            {showControls && (
              <div className="hidden rounded-lg border border-white/10 bg-black/25 p-0.5 md:flex">
                {RANGES.map((option) => (
                  <button key={option.id} type="button" onClick={() => setRange(option.id)}
                    className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${range === option.id ? "bg-white/10 text-slate-100" : "text-slate-500 hover:text-slate-300"}`}>
                    {option.label}
                  </button>
                ))}
              </div>
            )}
            {meta && meta.tenants.length > 1 && (
              <select value={tenant} onChange={(e) => setTenant(e.target.value)} title="Site"
                className="rounded-lg border border-white/10 bg-[#0b1220] px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
                {meta.tenants.map((o) => <option key={o.slug} value={o.slug}>{o.name}</option>)}
              </select>
            )}
            <button type="button" onClick={() => setLive((v) => !v)}
              className={`inline-flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition ${live ? "border-emerald-400/30 bg-emerald-400/[0.08] text-emerald-300" : "border-white/10 bg-white/[0.03] text-slate-400 hover:text-slate-200"}`}
              title={live ? "Pause automatic refresh" : "Resume automatic refresh"}>
              <span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-emerald-400 live-dot" : "bg-slate-500"}`} />
              {live ? "Live" : "Paused"}
            </button>
            <button type="button" onClick={refresh} disabled={refreshing} title="Refresh now"
              className="inline-flex items-center rounded-lg border border-white/10 bg-white/[0.03] p-1.5 text-slate-400 transition hover:text-slate-200 disabled:opacity-60">
              {refreshing ? <Spinner /> : <RefreshIcon />}
            </button>
            <UserMenu theme={theme} onTheme={toggleTheme} />
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1600px] flex-1 space-y-4 px-4 py-6 md:px-8">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div>
              <h1 className="text-xl font-semibold tracking-tight text-slate-50">{item.title}</h1>
              <p className="mt-0.5 text-sm text-slate-500">{item.desc}</p>
            </div>
            {showControls && (
              <span className="text-[11px] text-slate-600">{updatedAt ? `Updated ${fmtAgo(updatedAt.toISOString())}` : "Connecting…"}</span>
            )}
          </div>

          {error && showControls ? (
            <div className="flex items-start justify-between gap-4 rounded-xl border border-rose-500/25 bg-rose-500/[0.07] px-4 py-3">
              <p className="text-sm text-rose-200"><span className="font-medium">Cannot load data.</span> {error}</p>
              <button type="button" onClick={refresh} className="shrink-0 rounded-md border border-rose-400/30 px-2 py-1 text-xs text-rose-200 hover:bg-rose-400/10">Retry</button>
            </div>
          ) : null}

          {kpis && <KpiCards totals={overview?.totals ?? null} loading={!hasData} />}
          {body}
        </main>

        <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.05] px-4 py-3 text-[10px] text-slate-600 md:px-8">
          <span>{meta ? `${meta.tenant.name} · ${meta.raw_retention_hours}h raw retention · ${fmtNumber(overview?.totals.events ?? 0)} events in range` : "Self-hosted: log data never leaves this server"}</span>
          <span>Kira · Sophos Firewall syslog collector · UDP/TCP 5514</span>
        </footer>
      </div>
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Card className="p-5 lg:col-span-2">
        <Skeleton className="h-4 w-36" />
        <Skeleton className="mt-6 h-[220px] w-full" />
      </Card>
      <div className="flex flex-col gap-4">
        <Card className="p-5">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="mt-4 h-8 w-16" />
          <Skeleton className="mt-4 h-3 w-full" />
          <Skeleton className="mt-2 h-3 w-3/4" />
        </Card>
        <Card className="flex-1 p-5">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="mt-4 h-3 w-2/3" />
          <Skeleton className="mt-3 h-3 w-1/2" />
        </Card>
      </div>
    </div>
  );
}

function WaitingForLogs() {
  return (
    <Card className="p-6 md:p-8">
      <div className="flex flex-wrap items-center gap-3">
        <span className="live-dot h-2 w-2 rounded-full bg-emerald-400" />
        <h2 className="text-base font-semibold text-slate-100">Waiting for your first firewall logs</h2>
      </div>
      <p className="mt-2 max-w-3xl text-sm text-slate-400">
        The collector and database are ready. Point Sophos Firewall at this server and events will
        appear here within seconds — no agent required.
      </p>
      <ol className="mt-6 grid gap-4 md:grid-cols-3">
        <Step
          n="1"
          title="Open syslog settings"
          body="In SFOS go to System → Logging → Syslog servers and add a server with this host's address."
        />
        <Step
          n="2"
          title="Use port 5514"
          body="Select UDP or TCP 5514, keep the default plain (key=value) format, and enable Firewall, Content Filtering, IPS, AV and Authentication log types."
        />
        <Step
          n="3"
          title="Watch traffic land"
          body="This dashboard refreshes every 60 seconds, one request at a time to reduce database load. Use Refresh for an immediate update. Usernames appear once the firewall logs them with web or firewall events."
        />
      </ol>
      <p className="mt-6 rounded-lg border border-white/[0.06] bg-black/30 px-3 py-2 font-mono text-[11px] text-slate-400">
        Syslog server: &lt;this server IP&gt; · Port: 5514 (UDP/TCP) · Format: plain
      </p>
    </Card>
  );
}

function Step({ n, title, body }: { n: string; title: string; body: string }) {
  return (
    <li className="rounded-xl border border-white/[0.06] bg-white/[0.015] p-4">
      <span className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-emerald-400/25 bg-emerald-400/10 text-[11px] font-semibold text-emerald-300">
        {n}
      </span>
      <h3 className="mt-3 text-sm font-medium text-slate-200">{title}</h3>
      <p className="mt-1 text-xs leading-relaxed text-slate-500">{body}</p>
    </li>
  );
}

function RefreshIcon() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M20 11a8 8 0 1 0-2.3 5.7" strokeLinecap="round" />
      <path d="M20 4v7h-7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
