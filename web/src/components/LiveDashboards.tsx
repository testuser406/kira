import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { fmtBytes, fmtClock, fmtNumber, fmtRangeTick } from "../format";
import type { LiveDashboards, RankedKey, SecurityEvent, VpnTunnel } from "../types";
import { ActionBadge, Badge, Card, CardHeader, Empty, Skeleton } from "./ui";

/* ---------- shared building blocks ---------- */

function BigStat({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-black/20 p-3">
      <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1 text-xl font-semibold ${tone ?? "text-slate-100"}`}>{value}</p>
      {hint ? <p className="mt-0.5 text-[11px] text-slate-600">{hint}</p> : null}
    </div>
  );
}

function RankPanel({
  title,
  hint,
  rows,
  emptyHint,
  accent,
}: {
  title: string;
  hint?: string;
  rows: RankedKey[];
  emptyHint?: string;
  accent: string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.events ?? r.bytes ?? 0));
  return (
    <Card className="flex h-full flex-col">
      <CardHeader title={title} hint={hint} />
      <div className="flex-1 px-5 pb-4 pt-3">
        {rows.length === 0 ? (
          <Empty title="Nothing to show" hint={emptyHint ?? "No activity in this range."} />
        ) : (
          <ul className="space-y-2.5">
            {rows.map((row) => {
              const value = row.events ?? row.bytes ?? 0;
              return (
                <li key={row.key} className="group">
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="truncate text-[13px] text-slate-300" title={row.key}>
                      {row.key}
                    </span>
                    <span className="tabular shrink-0 text-xs text-slate-400">
                      {row.events != null ? fmtNumber(row.events) : fmtBytes(row.bytes)}
                    </span>
                  </div>
                  <div className="mt-1 h-1 flex-1 overflow-hidden rounded-full bg-white/[0.05]">
                    <div
                      className={`h-full rounded-full ${accent}`}
                      style={{ width: `${Math.max(2, (value / max) * 100)}%` }}
                    />
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Card>
  );
}

function LoadingPanel() {
  return (
    <Card className="p-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full" />
        ))}
      </div>
      <Skeleton className="mt-4 h-64 w-full" />
    </Card>
  );
}

/* ---------- Bandwidth ---------- */

export function LiveBandwidth({ data, spanHours }: { data: LiveDashboards["bandwidth"]; spanHours: number }) {
  const total = data.total_up + data.total_down;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <BigStat label="Current download" value={`${fmtBytes(data.throughput_bps_down)}/s`} tone="text-cyan-300" />
        <BigStat label="Current upload" value={`${fmtBytes(data.throughput_bps_up)}/s`} tone="text-violet-300" />
        <BigStat label="Total downloaded" value={fmtBytes(data.total_down)} />
        <BigStat label="Total uploaded" value={fmtBytes(data.total_up)} hint={`${fmtBytes(total)} combined`} />
      </div>

      <Card className="flex h-full flex-col">
        <CardHeader title="Live bandwidth" hint="Bytes per time bucket (volume)" />
        {data.series.length === 0 ? (
          <Empty title="No traffic in this range" hint="Choose a wider range or wait for logs." />
        ) : (
          <div className="mt-3 h-[260px] w-full pr-3">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data.series} margin={{ top: 6, right: 6, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="t"
                  tickFormatter={(v: string) => fmtRangeTick(v, spanHours)}
                  tick={{ fill: "#64748b", fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: "#1e293b" }}
                  minTickGap={32}
                />
                <YAxis
                  tickFormatter={(v: number) => fmtBytes(v)}
                  tick={{ fill: "#64748b", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  width={58}
                />
                <Tooltip
                  content={({ active, payload, label }: any) =>
                    active && payload?.length ? (
                      <div className="rounded-lg border border-white/10 bg-[#0b1220]/95 px-3 py-2 shadow-xl">
                        <p className="mb-1 text-[11px] text-slate-400">{fmtClock(String(label))}</p>
                        {payload.map((e: any) => (
                          <p key={String(e.dataKey)} className="flex items-center gap-2 text-xs text-slate-200">
                            <span className="inline-block h-2 w-2 rounded-sm" style={{ backgroundColor: e.color }} />
                            <span className="text-slate-400">{e.name}</span>
                            <span className="tabular ml-auto font-medium">{fmtBytes(Number(e.value))}</span>
                          </p>
                        ))}
                      </div>
                    ) : null
                  }
                  cursor={{ stroke: "#334155", strokeDasharray: "3 3" }}
                />
                <Line type="linear" dataKey="bytes_down" name="Download" stroke="#22d3ee" strokeWidth={1.6} isAnimationActive={false} dot={false} />
                <Line type="linear" dataKey="bytes_up" name="Upload" stroke="#a78bfa" strokeWidth={1.6} isAnimationActive={false} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <RankPanel
          title="Top bandwidth users"
          hint="By combined traffic"
          rows={data.top_users}
          emptyHint="No users recorded in this range."
          accent="bg-cyan-400/70"
        />
        <RankPanel
          title="Top bandwidth applications"
          hint="By combined traffic"
          rows={data.top_apps}
          emptyHint="No applications recorded in this range."
          accent="bg-violet-400/70"
        />
      </div>
    </div>
  );
}

/* ---------- Productivity ---------- */

export function LiveProductivity({ data }: { data: LiveDashboards["productivity"] }) {
  const totalEvents =
    data.top_users.reduce((s, r) => s + (r.events ?? 0), 0);
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-white/[0.06] bg-black/20 px-4 py-3">
        <p className="text-[10px] uppercase tracking-wider text-slate-500">User activity</p>
        <p className="mt-1 text-xl font-semibold text-slate-100">{fmtNumber(totalEvents)} logged events</p>
        <p className="mt-0.5 text-[11px] text-slate-600">Web, firewall and application activity in the selected window</p>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <RankPanel
          title="Top categories"
          hint="Web filter categories"
          rows={data.top_categories}
          emptyHint="No categories in this range."
          accent="bg-sky-400/70"
        />
        <RankPanel
          title="Top applications"
          hint="Most-used applications"
          rows={data.top_apps}
          emptyHint="No applications in this range."
          accent="bg-violet-400/70"
        />
        <RankPanel
          title="Top users"
          hint="Most active identities"
          rows={data.top_users}
          emptyHint="No usernames recorded in this range."
          accent="bg-emerald-400/70"
        />
      </div>
    </div>
  );
}

/* ---------- Security ---------- */

function SecurityFeedRow({ ev }: { ev: SecurityEvent }) {
  return (
    <li className="flex items-start gap-3 border-b border-white/[0.04] px-5 py-2.5 last:border-0">
      <span className="mt-0.5 w-20 shrink-0 text-[10px] tabular text-slate-500">
        {new Date(ev.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })}
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate text-xs font-medium text-slate-200" title={ev.name}>{ev.name}</p>
        <p className="mt-0.5 truncate text-[10px] text-slate-500">
          {[ev.src_ip, "→", ev.dst_ip].filter(Boolean).join(" ")}
          {ev.message ? ` · ${ev.message}` : ""}
        </p>
      </div>
      <ActionBadge action={ev.action} />
    </li>
  );
}

export function LiveSecurity({ data }: { data: LiveDashboards["security"] }) {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <BigStat label="Threat events" value={fmtNumber(data.threats)} tone="text-rose-300" />
        <BigStat label="Blocked actions" value={fmtNumber(data.blocked)} tone="text-amber-300" />
        <BigStat label="Threats blocked" value={fmtNumber(data.threats_blocked)} tone="text-rose-300" />
        <BigStat label="Distinct threats" value={fmtNumber(data.top_threats.length)} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <RankPanel
          title="Top threats"
          hint="By event count"
          rows={data.top_threats}
          emptyHint="No threat events in this range."
          accent="bg-rose-400/70"
        />
        <Card className="lg:col-span-2">
          <CardHeader title="Live security feed" hint="Recent threat and blocked events" />
          {data.recent.length === 0 ? (
            <Empty title="No recent security events" hint="Threats and blocked actions will appear here in real time." />
          ) : (
            <ul className="py-2">
              {data.recent.map((ev, i) => (
                <SecurityFeedRow key={`${ev.ts}-${i}`} ev={ev} />
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}

/* ---------- VPN ---------- */

export function LiveVpn({ data }: { data: LiveDashboards["vpn"] }) {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <BigStat label="VPN connections" value={fmtNumber(data.connections)} tone="text-cyan-300" />
        <BigStat label="Active users" value={fmtNumber(data.users)} />
        <BigStat label="Active tunnels" value={fmtNumber(data.tunnels)} />
        <BigStat label="Downloaded" value={fmtBytes(data.bytes_down)} tone="text-cyan-300" />
        <BigStat label="Uploaded" value={fmtBytes(data.bytes_up)} tone="text-violet-300" />
      </div>

      <Card>
        <CardHeader title="Active VPN sessions" hint="Tunnels by user, traffic and last activity" />
        {data.active_tunnels.length === 0 ? (
          <Empty title="No VPN activity in this range" hint="VPN connection events will appear here once users connect." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-xs">
              <thead>
                <tr className="border-y border-white/[0.06] bg-white/[0.015] text-[10px] uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Tunnel</th>
                  <th className="px-3 py-2 text-right font-medium">Connections</th>
                  <th className="px-3 py-2 text-right font-medium">Downloaded</th>
                  <th className="px-3 py-2 text-right font-medium">Uploaded</th>
                  <th className="px-5 py-2 font-medium">Last activity</th>
                </tr>
              </thead>
              <tbody>
                {data.active_tunnels.map((t: VpnTunnel, i) => (
                  <tr key={`${t.user}-${t.tunnel}-${i}`} className="border-b border-white/[0.04]">
                    <td className="px-5 py-2 font-medium text-slate-200">{t.user}</td>
                    <td className="px-3 py-2 text-slate-400"><Badge tone="cyan">{t.tunnel}</Badge></td>
                    <td className="px-3 py-2 text-right tabular text-slate-300">{fmtNumber(t.connections)}</td>
                    <td className="px-3 py-2 text-right tabular text-cyan-300">{fmtBytes(t.bytes_down)}</td>
                    <td className="px-3 py-2 text-right tabular text-violet-300">{fmtBytes(t.bytes_up)}</td>
                    <td className="px-5 py-2 text-slate-500">{fmtClock(t.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

/* ---------- container ---------- */

export function LiveDashboardsView({
  data,
  loading,
  spanHours,
}: {
  data: LiveDashboards | null;
  loading: boolean;
  spanHours: number;
}) {
  if (loading && !data) return <LoadingPanel />;
  if (!data) return <Empty title="No data yet" hint="Waiting for the live dashboard payload." />;

  return (
    <div className="space-y-4">
      <LiveBandwidth data={data.bandwidth} spanHours={spanHours} />
      <LiveProductivity data={data.productivity} />
      <LiveSecurity data={data.security} />
      <LiveVpn data={data.vpn} />
    </div>
  );
}