import { useEffect, useRef, useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtBytes, fmtClock, fmtNumber } from "../format";
import { Card, CardHeader, Empty } from "./ui";

export type LiveKind = "bandwidth" | "productivity" | "security" | "vpn";

interface Point {
  t: string;
  events: number;
  allowed: number;
  blocked: number;
  bytes_up: number;
  bytes_down: number;
}
interface Ranked {
  key: string;
  events: number;
  blocked: number;
  bytes_up: number;
  bytes_down: number;
  bytes: number;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Data = Record<string, any> & { series: Point[] };

const WINDOWS = [5, 15, 60, 360];
const REFRESH_MS = 15_000;

function bps(v: number): string {
  if (v >= 1e9) return `${(v / 1e9).toFixed(2)} Gbps`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(2)} Mbps`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)} Kbps`;
  return `${v} bps`;
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-black/20 p-3">
      <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1 text-xl font-semibold ${tone ?? "text-slate-100"}`}>{value}</p>
    </div>
  );
}

function Chart({
  series,
  keys,
  fmt,
}: {
  series: Point[];
  keys: { k: keyof Point; color: string; name: string }[];
  fmt: (n: number) => string;
}) {
  return (
    <div className="h-64 px-2 pb-3 pt-2">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={series} margin={{ left: 4, right: 12, top: 8 }}>
          <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis dataKey="t" tickFormatter={fmtClock} stroke="#64748b" fontSize={11} minTickGap={36} />
          <YAxis tickFormatter={(v: number) => fmt(v)} stroke="#64748b" fontSize={11} width={64} />
          <Tooltip
            labelFormatter={(l) => fmtClock(String(l))}
            formatter={(v, n) => [fmt(Number(v)), String(n)]}
            contentStyle={{ background: "#0b1220", border: "1px solid rgba(255,255,255,0.1)" }}
          />
          {keys.map((s) => (
            <Area key={String(s.k)} type="monotone" dataKey={s.k} name={s.name} stroke={s.color}
              fill={s.color} fillOpacity={0.15} strokeWidth={1.8} isAnimationActive={false} />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function Rank({ title, rows, mode }: { title: string; rows: Ranked[]; mode: "bytes" | "events" }) {
  const val = (r: Ranked) => (mode === "bytes" ? r.bytes : r.events);
  const max = Math.max(1, ...rows.map(val));
  return (
    <Card className="flex h-full flex-col">
      <CardHeader title={title} />
      <div className="flex-1 px-5 pb-4 pt-3">
        {rows.length === 0 ? (
          <Empty title="Nothing in this window" hint="Activity appears here within a minute of arriving." />
        ) : (
          <ul className="space-y-2.5">
            {rows.map((r) => (
              <li key={r.key}>
                <div className="flex items-baseline justify-between gap-3">
                  <span className="truncate text-[13px] text-slate-300" title={r.key}>{r.key}</span>
                  <span className="tabular shrink-0 text-xs text-slate-400">
                    {mode === "bytes" ? fmtBytes(r.bytes) : fmtNumber(r.events)}
                  </span>
                </div>
                <div className="mt-1 h-1 overflow-hidden rounded-full bg-white/[0.05]">
                  <div className="h-full rounded-full bg-sky-400/70" style={{ width: `${(val(r) / max) * 100}%` }} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}

export function LiveMinuteView({ kind, tenant }: { kind: LiveKind; tenant: string }) {
  const [windowMin, setWindowMin] = useState(15);
  const [data, setData] = useState<Data | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [updated, setUpdated] = useState<Date | null>(null);
  const inflight = useRef<AbortController | null>(null);

  useEffect(() => {
    let stop = false;
    setData(null);
    const load = async () => {
      inflight.current?.abort();
      const ctl = new AbortController();
      inflight.current = ctl;
      try {
        const qs = new URLSearchParams({ tenant, window: String(windowMin) });
        const res = await fetch(`/api/v1/live/${kind}?${qs}`, { signal: ctl.signal, credentials: "same-origin" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const body = await res.json();
        if (!stop) {
          setData(body.data as Data);
          setUpdated(new Date());
          setErr(null);
        }
      } catch (e) {
        if (!stop && (e as Error).name !== "AbortError") setErr((e as Error).message);
      }
    };
    void load();
    const id = window.setInterval(() => { if (!document.hidden) void load(); }, REFRESH_MS);
    return () => { stop = true; window.clearInterval(id); inflight.current?.abort(); };
  }, [kind, tenant, windowMin]);

  const d = data;
  const rank = (k: string) => (d?.[k] as Ranked[] | undefined) ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-slate-500">
          Per-minute data · refreshes every 15s{updated ? ` · updated ${updated.toLocaleTimeString()}` : ""}
          {err ? <span className="ml-2 text-rose-300">({err})</span> : null}
        </p>
        <div className="flex gap-1">
          {WINDOWS.map((w) => (
            <button key={w} type="button" onClick={() => setWindowMin(w)}
              className={`rounded-md border px-2.5 py-1 text-xs ${w === windowMin
                ? "border-sky-400/40 bg-sky-400/10 text-sky-200"
                : "border-white/10 text-slate-400 hover:bg-white/5"}`}>
              {w < 60 ? `${w}m` : `${w / 60}h`}
            </button>
          ))}
        </div>
      </div>

      {!d ? (
        <Card><div className="p-8 text-sm text-slate-500">Loading…</div></Card>
      ) : kind === "bandwidth" ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Download now" value={bps(d.now_bps_down)} tone="text-sky-300" />
            <Stat label="Upload now" value={bps(d.now_bps_up)} tone="text-emerald-300" />
            <Stat label="Peak minute" value={fmtBytes(d.peak_bytes_per_min)} />
            <Stat label={`Total (${windowMin}m)`} value={fmtBytes(d.total_up + d.total_down)} />
          </div>
          <Card>
            <CardHeader title="Bandwidth per minute" />
            <Chart series={d.series} fmt={fmtBytes} keys={[
              { k: "bytes_down", color: "#38bdf8", name: "Download" },
              { k: "bytes_up", color: "#34d399", name: "Upload" }]} />
          </Card>
          <div className="grid gap-4 md:grid-cols-2">
            <Rank title="Top users by traffic" rows={rank("top_users")} mode="bytes" />
            <Rank title="Top applications by traffic" rows={rank("top_applications")} mode="bytes" />
          </div>
        </>
      ) : kind === "productivity" ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
            <Stat label={`Web requests (${windowMin}m)`} value={fmtNumber(d.web_requests)} />
            <Stat label="Blocked by web filter" value={fmtNumber(d.blocked)} tone="text-amber-300" />
            <Stat label="Per minute (avg)" value={fmtNumber(Math.round(d.web_requests / windowMin))} />
          </div>
          <Card>
            <CardHeader title="Web requests per minute" />
            <Chart series={d.series} fmt={fmtNumber} keys={[
              { k: "allowed", color: "#38bdf8", name: "Allowed" },
              { k: "blocked", color: "#fbbf24", name: "Blocked" }]} />
          </Card>
          <div className="grid gap-4 md:grid-cols-3">
            <Rank title="Top categories" rows={rank("top_categories")} mode="events" />
            <Rank title="Top websites" rows={rank("top_domains")} mode="events" />
            <Rank title="Most active users" rows={rank("top_users")} mode="events" />
          </div>
        </>
      ) : kind === "security" ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
            <Stat label={`Threat events (${windowMin}m)`} value={fmtNumber(d.threats)} tone="text-rose-300" />
            <Stat label="Blocked traffic" value={fmtNumber(d.blocked_traffic)} tone="text-amber-300" />
            <Stat label="Distinct sources" value={fmtNumber(rank("top_sources").length)} />
          </div>
          <Card>
            <CardHeader title="Threat events per minute" />
            <Chart series={d.series} fmt={fmtNumber} keys={[{ k: "events", color: "#fb7185", name: "Threats" }]} />
          </Card>
          <div className="grid gap-4 md:grid-cols-2">
            <Rank title="Top threats" rows={rank("top_threats")} mode="events" />
            <Rank title="Top threat sources" rows={rank("top_sources")} mode="events" />
          </div>
        </>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Active tunnels" value={fmtNumber(d.active_tunnels)} tone="text-emerald-300" />
            <Stat label="Active VPN users" value={fmtNumber(d.active_users)} tone="text-sky-300" />
            <Stat label="Down" value={fmtBytes(d.total_down)} />
            <Stat label="Up" value={fmtBytes(d.total_up)} />
          </div>
          <Card>
            <CardHeader title="VPN traffic per minute" />
            <Chart series={d.series} fmt={fmtBytes} keys={[
              { k: "bytes_down", color: "#38bdf8", name: "Down" },
              { k: "bytes_up", color: "#34d399", name: "Up" }]} />
          </Card>
          <div className="grid gap-4 md:grid-cols-2">
            <Rank title="Tunnels" rows={rank("tunnels")} mode="bytes" />
            <Rank title="VPN users" rows={rank("users")} mode="bytes" />
          </div>
        </>
      )}
    </div>
  );
}
