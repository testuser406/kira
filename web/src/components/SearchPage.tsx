import { useEffect, useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtAgo, fmtBytes, fmtNumber } from "../format";
import { Card, CardHeader, Empty } from "./ui";

interface Hit { key: string; events: number; blocked: number; bytes: number; last_seen: string }
interface Group { dimension: string; label: string; items: Hit[] }
interface Point { t: string; events: number; allowed: number; blocked: number; bytes_up: number; bytes_down: number; browse_minutes: number }
interface Ranked { key: string; events: number; blocked: number; bytes: number }
interface Timeline {
  user: string; days: number; unit: string;
  totals: { events: number; allowed: number; blocked: number; bytes_up: number; bytes_down: number; browse_minutes: number };
  timeline: Point[]; top_sites: Ranked[]; top_categories: Ranked[];
}

async function get<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { credentials: "same-origin", signal });
  const ct = res.headers.get("content-type") ?? "";
  if (!ct.includes("json")) throw new Error("API is outdated - stop, rebuild and start Kira");
  const body = await res.json();
  if (!res.ok) throw new Error(body?.error ?? `HTTP ${res.status}`);
  return body as T;
}

const DAYS: [number, string][] = [[1, "24h"], [7, "7d"], [30, "30d"], [90, "90d"]];

export function SearchPage({ tenant, initialQuery, onQuery }: { tenant: string; initialQuery: string; onQuery: (q: string) => void }) {
  const [text, setText] = useState(initialQuery);
  const [days, setDays] = useState(30);
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  // Searching is explicit (Enter or the button): one request per search, never per keystroke.
  const [submitted, setSubmitted] = useState(initialQuery.trim());
  useEffect(() => { setText(initialQuery); setSubmitted(initialQuery.trim()); }, [initialQuery]);

  useEffect(() => {
    if (submitted.length < 2) { setGroups(null); setError(""); return; }
    const controller = new AbortController();
    setLoading(true);
    get<{ groups: Group[] }>(`/api/v1/search?q=${encodeURIComponent(submitted)}&days=${days}&tenant=${encodeURIComponent(tenant)}`, controller.signal)
      .then((r) => { setGroups(r.groups); setError(""); onQuery(submitted); })
      .catch((e: Error) => { if (!controller.signal.aborted) setError(e.message); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [submitted, days, tenant]);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const q = text.trim();
    if (q.length < 2) { setError("Type at least two characters, then press Enter."); return; }
    setError("");
    setSubmitted(q);
  };

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <form onSubmit={submit} className="flex flex-wrap items-center gap-3">
          <input
            autoFocus
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Search a user, IP, domain, application, category, rule, country, threat…"
            className="min-w-[260px] flex-1 rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-emerald-400/40 focus:outline-none"
          />
          <button type="submit" disabled={loading} className="rounded-lg bg-emerald-500/90 px-3.5 py-2 text-sm font-medium text-black hover:bg-emerald-400 disabled:opacity-50">
            Search
          </button>
          <div className="flex rounded-lg border border-white/10 bg-black/25 p-0.5">
            {DAYS.map(([d, label]) => (
              <button key={d} type="button" onClick={() => setDays(d)}
                className={`rounded-md px-2.5 py-1 text-[11px] font-medium ${days === d ? "bg-white/10 text-slate-100" : "text-slate-500 hover:text-slate-300"}`}>
                {label}
              </button>
            ))}
          </div>
        </form>
        {loading && <p className="mt-2 text-xs text-slate-500">Searching…</p>}
        {error && <p className="mt-2 text-sm text-rose-300">{error}</p>}
      </Card>

      {selected && <UserTimeline user={selected} tenant={tenant} days={Math.max(days, 7)} onClose={() => setSelected(null)} />}

      {groups === null && !error && <Empty title="Search everything Kira has seen" hint="Type at least two characters and press Enter. Results come from the hourly history, up to 400 days." />}
      {groups && groups.length === 0 && <Empty title="No matches" hint="Try a shorter term or a longer period." />}
      <div className="grid gap-4 lg:grid-cols-2">
        {groups?.map((g) => (
          <Card key={g.dimension}>
            <CardHeader title={g.label} hint={`${g.items.length} match${g.items.length === 1 ? "" : "es"}`} />
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide text-slate-500">
                    <th className="px-4 py-2 font-medium">Name</th>
                    <th className="px-2 py-2 text-right font-medium">Requests</th>
                    <th className="px-2 py-2 text-right font-medium">Blocked</th>
                    <th className="px-2 py-2 text-right font-medium">Traffic</th>
                    <th className="px-4 py-2 text-right font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {g.items.map((h) => (
                    <tr key={h.key} className="border-t border-white/[0.05] hover:bg-white/[0.03]">
                      <td className="max-w-[260px] truncate px-4 py-2 text-slate-200">
                        {g.dimension === "users" ? (
                          <button type="button" className="text-emerald-300 hover:underline" onClick={() => { setSelected(h.key); window.scrollTo({ top: 0, behavior: "smooth" }); }}>{h.key}</button>
                        ) : h.key}
                      </td>
                      <td className="px-2 py-2 text-right tabular-nums text-slate-300">{fmtNumber(h.events)}</td>
                      <td className="px-2 py-2 text-right tabular-nums text-rose-300/80">{fmtNumber(h.blocked)}</td>
                      <td className="px-2 py-2 text-right tabular-nums text-slate-300">{fmtBytes(h.bytes)}</td>
                      <td className="px-4 py-2 text-right text-xs text-slate-500">{fmtAgo(h.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

function UserTimeline({ user, tenant, days: initialDays, onClose }: { user: string; tenant: string; days: number; onClose: () => void }) {
  const [days, setDays] = useState(initialDays);
  const [data, setData] = useState<Timeline | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setData(null);
    get<Timeline>(`/api/v1/investigate/user?user=${encodeURIComponent(user)}&days=${days}&tenant=${encodeURIComponent(tenant)}`)
      .then((r) => { setData(r); setError(""); })
      .catch((e: Error) => setError(e.message));
  }, [user, days, tenant]);

  const fmtT = (iso: string) => {
    const d = new Date(iso);
    return data?.unit === "hour"
      ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : d.toLocaleDateString([], { month: "short", day: "numeric" });
  };
  const mins = (m: number) => (m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`);

  return (
    <Card>
      <CardHeader title={`Timeline: ${user}`} hint={`Last ${days} days, ${data?.unit === "hour" ? "per hour" : "per day"}`} />
      <div className="flex items-center justify-between gap-2 px-4 pb-2">
        <div className="flex rounded-lg border border-white/10 bg-black/25 p-0.5">
          {[[1, "24h"], [3, "3d"], [7, "7d"], [30, "30d"], [90, "90d"]].map(([d, label]) => (
            <button key={String(d)} type="button" onClick={() => setDays(d as number)}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium ${days === d ? "bg-white/10 text-slate-100" : "text-slate-500 hover:text-slate-300"}`}>
              {label}
            </button>
          ))}
        </div>
        <button type="button" onClick={onClose} className="text-xs text-slate-500 hover:text-slate-200">Close</button>
      </div>
      {error && <p className="px-4 pb-4 text-sm text-rose-300">{error}</p>}
      {!data && !error && <p className="px-4 pb-4 text-sm text-slate-500">Loading…</p>}
      {data && (
        <div className="space-y-4 px-4 pb-4">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            {[
              ["Requests", fmtNumber(data.totals.events)],
              ["Blocked", fmtNumber(data.totals.blocked)],
              ["Downloaded", fmtBytes(data.totals.bytes_down)],
              ["Uploaded", fmtBytes(data.totals.bytes_up)],
              ["Browse time", mins(data.totals.browse_minutes)],
            ].map(([l, v]) => (
              <div key={l} className="rounded-lg border border-white/[0.06] bg-black/20 px-3 py-2">
                <div className="text-[11px] text-slate-500">{l}</div>
                <div className="text-lg font-semibold tabular-nums text-slate-100">{v}</div>
              </div>
            ))}
          </div>
          {data.timeline.length === 0 ? (
            <Empty title="No activity" hint="Nothing recorded for this user in the period." />
          ) : (
            <div className="h-60">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.timeline} margin={{ left: 4, right: 12, top: 8 }}>
                  <defs>
                    <linearGradient id="tl_ok" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#34d399" stopOpacity={0.35} /><stop offset="100%" stopColor="#34d399" stopOpacity={0.02} /></linearGradient>
                    <linearGradient id="tl_bad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fb7185" stopOpacity={0.35} /><stop offset="100%" stopColor="#fb7185" stopOpacity={0.02} /></linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="t" tickFormatter={fmtT} stroke="#64748b" fontSize={11} minTickGap={36} />
                  <YAxis tickFormatter={(v: number) => fmtNumber(v)} stroke="#64748b" fontSize={11} width={56} />
                  <Tooltip labelFormatter={(l) => fmtT(String(l))} formatter={(v, n) => [fmtNumber(Number(v)), String(n)]} contentStyle={{ background: "#0b1220", border: "1px solid rgba(255,255,255,0.1)" }} />
                  <Area type="monotone" dataKey="allowed" name="Allowed" stroke="#34d399" fill="url(#tl_ok)" strokeWidth={1.8} isAnimationActive={false} />
                  <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#fb7185" fill="url(#tl_bad)" strokeWidth={1.8} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
          <div className="grid gap-4 lg:grid-cols-2">
            {([["Top sites", data.top_sites], ["Top categories", data.top_categories]] as [string, Ranked[]][]).map(([title, rows]) => (
              <div key={title}>
                <div className="mb-1 text-xs font-medium text-slate-400">{title}</div>
                {rows.length === 0 ? <p className="text-sm text-slate-600">No data</p> : (
                  <table className="w-full text-sm">
                    <tbody>
                      {rows.map((r) => (
                        <tr key={r.key} className="border-t border-white/[0.05]">
                          <td className="max-w-[240px] truncate py-1.5 text-slate-200">{r.key}</td>
                          <td className="py-1.5 text-right tabular-nums text-slate-300">{fmtNumber(r.events)}</td>
                          <td className="py-1.5 pl-3 text-right tabular-nums text-rose-300/80">{r.blocked > 0 ? `${fmtNumber(r.blocked)} blocked` : ""}</td>
                          <td className="py-1.5 pl-3 text-right tabular-nums text-slate-500">{fmtBytes(r.bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}
