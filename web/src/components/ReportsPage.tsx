import { useCallback, useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtBytes, fmtNumber } from "../format";
import { Card, CardHeader } from "./ui";

interface Kpi { label: string; value: number; unit: string; delta?: number }
interface Column { name: string; unit: string }
interface Chart { unit: string; labels: string[]; datasets: { name: string; values: number[] }[] }
interface Section { title: string; columns: Column[]; rows: (string | number)[][]; chart: Chart | null; note: string | null }
interface Summary { title: string; tenant: string; from: string; to: string; granularity: string; kpis: Kpi[]; sections: Section[] }

const TYPES: [string, string][] = [
  ["executive", "Executive summary"],
  ["online_productivity", "Online productivity"],
  ["user_overview", "User overview"],
  ["user", "Users"],
  ["websites_allowed_blocked", "Allowed & blocked websites"],
  ["security_threat", "Security & threats"],
  ["network_bandwidth", "Network bandwidth"],
  ["vpn_connections", "VPN connections"],
  ["firewall_policy", "Firewall policy"],
  ["subnet", "Subnets"],
  ["activity_timeline", "Activity timeline"],
];
const RANGES: [string, string][] = [["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["90d", "Last 90 days"], ["custom", "Custom range"]];
const COLORS = ["#38bdf8", "#fb7185", "#34d399", "#fbbf24"];

function fmt(v: number | string, unit: string): string {
  if (typeof v === "string") return v;
  if (unit === "bytes") return fmtBytes(v);
  if (unit === "minutes") return v >= 60 ? `${Math.floor(v / 60)}h ${Math.round(v % 60)}m` : `${Math.round(v)}m`;
  if (unit === "percent") return `${v.toFixed(1)}%`;
  return fmtNumber(v);
}

export function ReportsPage({ tenant }: { tenant: string }) {
  const [type, setType] = useState("executive");
  const [range, setRange] = useState("24h");
  const [cFrom, setCFrom] = useState("");
  const [cTo, setCTo] = useState("");
  const [user, setUser] = useState("");
  const [top, setTop] = useState(15);
  const [data, setData] = useState<Summary | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const qs = useCallback((format: string) => {
    const custom = range === "custom" && cFrom;
    const p = new URLSearchParams({ tenant, type, from: custom ? new Date(cFrom).toISOString() : range === "custom" ? "24h" : range, top: String(top), format });
    if (custom && cTo) p.set("to", new Date(cTo).toISOString());
    if (type === "user_overview" && user.trim()) p.set("user", user.trim());
    return `/api/v1/reports/summary?${p}`;
  }, [tenant, type, range, top, user, cFrom, cTo]);

  const run = useCallback(async () => {
    if (type === "user_overview" && !user.trim()) { setErr("Enter a user name for the user overview"); return; }
    setBusy(true);
    try {
      const res = await fetch(qs("json"), { credentials: "same-origin" });
      if (!res.ok) throw new Error(res.status === 400 ? await res.text() : `HTTP ${res.status}`);
      if (!(res.headers.get("content-type") ?? "").includes("json")) throw new Error("API is outdated - stop, rebuild and start Kira");
      setData((await res.json()) as Summary);
      setErr(null);
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }, [qs, type, user]);

  useEffect(() => { if (type !== "user_overview" && (range !== "custom" || cFrom)) void run(); }, [type, range, top]); // eslint-disable-line react-hooks/exhaustive-deps

  const sel = "rounded-md border border-white/10 bg-black/30 px-2 py-1.5 text-sm text-slate-200";
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-end gap-3 px-5 py-4">
          <label className="text-xs text-slate-500">Report
            <select className={`${sel} mt-1 block`} value={type} onChange={(e) => setType(e.target.value)}>
              {TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          <label className="text-xs text-slate-500">Period
            <select className={`${sel} mt-1 block`} value={range} onChange={(e) => setRange(e.target.value)}>
              {RANGES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          {range === "custom" ? (
            <>
              <label className="text-xs text-slate-500">From
                <input type="datetime-local" className={`${sel} mt-1 block`} value={cFrom} onChange={(e) => setCFrom(e.target.value)} />
              </label>
              <label className="text-xs text-slate-500">To
                <input type="datetime-local" className={`${sel} mt-1 block`} value={cTo} onChange={(e) => setCTo(e.target.value)} />
              </label>
            </>
          ) : null}
          {type === "user_overview" ? (
            <label className="text-xs text-slate-500">User
              <input className={`${sel} mt-1 block`} value={user} placeholder="username or IP" onChange={(e) => setUser(e.target.value)} />
            </label>
          ) : null}
          <label className="text-xs text-slate-500">Top N
            <select className={`${sel} mt-1 block`} value={top} onChange={(e) => setTop(Number(e.target.value))}>
              {[10, 15, 25, 50, 100].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <button id="run-report" type="button" onClick={() => void run()} disabled={busy}
            className="rounded-md border border-sky-400/40 bg-sky-400/10 px-3 py-1.5 text-sm text-sky-200 disabled:opacity-50">
            {busy ? "Running…" : "Run report"}
          </button>
          <div className="ml-auto flex gap-2">
            <a className="rounded-md border border-white/10 px-3 py-1.5 text-sm text-slate-300 hover:bg-white/5" href={qs("pdf")}>Export PDF</a>
            <a className="rounded-md border border-white/10 px-3 py-1.5 text-sm text-slate-300 hover:bg-white/5" href={qs("csv")}>Export CSV</a>
          </div>
        </div>
        {err ? <p className="px-5 pb-3 text-sm text-rose-300">{err}</p> : null}
      </Card>

      {data ? (
        <>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">{data.title}</h2>
            <p className="text-xs text-slate-500">
              {new Date(data.from).toLocaleString()} – {new Date(data.to).toLocaleString()} · {data.granularity}ly resolution
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {data.kpis.map((k) => (
              <div key={k.label} className="rounded-lg border border-white/[0.06] bg-black/20 p-3">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">{k.label}</p>
                <p className="mt-1 text-xl font-semibold text-slate-100">{fmt(k.value, k.unit)}</p>
                {k.delta !== undefined ? (
                  <p className={`mt-0.5 text-[11px] ${k.delta > 0 ? "text-sky-300" : k.delta < 0 ? "text-slate-400" : "text-slate-500"}`}>
                    {k.delta > 0 ? "▲" : k.delta < 0 ? "▼" : "•"} {Math.abs(k.delta)}{k.unit === "percent" ? " pts" : "%"} vs previous period
                  </p>
                ) : null}
              </div>
            ))}
          </div>
          {data.sections.map((s) => (
            <Card key={s.title}>
              <CardHeader title={s.title} />
              {s.note ? <p className="px-5 pt-3 text-xs text-amber-300">{s.note}</p> : null}
              {s.chart ? <ChartView chart={s.chart} /> : <TableView section={s} onDrill={s.columns[0].name === "User" ? (u) => { setUser(u); setType("user_overview"); setTimeout(() => document.getElementById("run-report")?.click(), 0); } : undefined} />}
            </Card>
          ))}
        </>
      ) : null}
    </div>
  );
}

function ChartView({ chart }: { chart: Chart }) {
  const rows = chart.labels.map((l, i) => {
    const r: Record<string, string | number> = { l };
    chart.datasets.forEach((d) => { r[d.name] = d.values[i] ?? 0; });
    return r;
  });
  return (
    <div className="h-64 px-2 pb-3 pt-3">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ left: 4, right: 12, top: 8 }}>
          <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis dataKey="l" stroke="#64748b" fontSize={11} minTickGap={28} />
          <YAxis tickFormatter={(v: number) => fmt(v, chart.unit)} stroke="#64748b" fontSize={11} width={64} />
          <Tooltip formatter={(v, n) => [fmt(Number(v), chart.unit), String(n)]}
            contentStyle={{ background: "#0b1220", border: "1px solid rgba(255,255,255,0.1)" }} />
          {chart.datasets.map((d, i) => (
            <Bar key={d.name} dataKey={d.name} stackId="s" fill={COLORS[i % 4]} isAnimationActive={false} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TableView({ section, onDrill }: { section: Section; onDrill?: (key: string) => void }) {
  const [sortCol, setSortCol] = useState<number | null>(null);
  const [desc, setDesc] = useState(true);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  if (section.rows.length === 0) return <p className="px-5 py-4 text-sm text-slate-500">No data</p>;
  let rows = section.rows.filter((r) => !q || String(r[0]).toLowerCase().includes(q.toLowerCase()));
  if (sortCol !== null) {
    const c = sortCol;
    rows = [...rows].sort((a, b) => {
      const x = a[c], y = b[c];
      const d = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
      return desc ? -d : d;
    });
  }
  const limit = 15;
  const shown = open || q ? rows : rows.slice(0, limit);
  const max = Math.max(1e-9, ...rows.map((r) => Number(r[1]) || 0));
  return (
    <div className="overflow-x-auto px-5 pb-4 pt-2">
      {section.rows.length > limit ? (
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={`Filter ${section.columns[0].name.toLowerCase()}…`}
          className="mb-2 w-56 rounded-md border border-white/10 bg-black/30 px-2 py-1 text-xs text-slate-200" />
      ) : null}
      <table className="w-full text-[13px]">
        <thead>
          <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500">
            {section.columns.map((c, i) => (
              <th key={c.name} onClick={() => { if (sortCol === i) setDesc(!desc); else { setSortCol(i); setDesc(true); } }}
                className={`cursor-pointer select-none py-1.5 hover:text-slate-300 ${i ? "text-right" : ""}`}>
                {c.name}{sortCol === i ? (desc ? " ▾" : " ▴") : ""}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {shown.map((r, ri) => (
            <tr key={ri} className="border-t border-white/[0.04]">
              {r.map((v, i) => (
                <td key={i} className={`py-1.5 ${i ? `tabular text-right ${section.columns[i].name === "Blocked" && Number(v) > 0 ? "text-amber-300" : "text-slate-400"}` : "max-w-[320px] truncate text-slate-200"}`} title={String(v)}>
                  {i === 0 && onDrill ? (
                    <button type="button" className="text-left text-sky-200 hover:underline" onClick={() => onDrill(String(v))}>{String(v)}</button>
                  ) : i === 1 && typeof v === "number" ? (
                    <span className="inline-flex items-center gap-2">
                      <span className="inline-block h-1 rounded-full bg-sky-400/70" style={{ width: `${Math.max(2, (v / max) * 60)}px` }} />
                      {fmt(v, section.columns[i].unit)}
                    </span>
                  ) : fmt(v, section.columns[i].unit)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {!q && rows.length > limit ? (
        <button type="button" onClick={() => setOpen(!open)} className="mt-2 text-xs text-sky-300 hover:underline">
          {open ? "Show top 15" : `Show all ${rows.length}`}
        </button>
      ) : null}
    </div>
  );
}
