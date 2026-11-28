import { useCallback, useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtNumber } from "../format";
import { Badge, Button, Card, CardHeader, Empty } from "./ui";

interface Ranked { key: string; events: number; blocked: number }
interface Summary {
  hours: number;
  threat_events: number;
  threat_blocked: number;
  open_findings: Record<"low" | "medium" | "high" | "critical", number>;
  timeline: { t: string; type: string; events: number }[];
  types: Ranked[];
  top_threats: Ranked[];
  top_sources: Ranked[];
  countries: Ranked[];
  sources_masked: boolean;
}
interface Finding {
  id: string; kind: string; severity: "low" | "medium" | "high" | "critical";
  subject: string; detail: string; first_seen: string; last_seen: string; count: number; acknowledged: boolean;
}
interface IntelItem { indicator: string; kind: string; source: string; added_at: string }

const WINDOWS: [number, string][] = [[1, "1h"], [24, "24h"], [168, "7d"]];
const SEV_TONE = { low: "slate", medium: "amber", high: "rose", critical: "rose" } as const;
const KIND_LABEL: Record<string, string> = {
  traffic_spike: "Traffic spike", new_country: "New country", new_host: "New host", unusual_hours: "Unusual hours",
  brute_force: "Brute force", port_scan: "Port scan", intel_ip: "Threat-intel IP", intel_domain: "Threat-intel domain",
};
const PALETTE = ["#f43f5e", "#f59e0b", "#38bdf8", "#a78bfa", "#34d399", "#94a3b8"];

// Approximate country centroids [lat, lon], keyed by ISO-3 and ISO-2 (SFOS logs either form).
const GEO: Record<string, [number, number]> = {};
for (const row of [
  "USA US 39 -98", "CAN CA 56 -106", "MEX MX 23 -102", "BRA BR -10 -52", "ARG AR -34 -64", "CHL CL -30 -71", "COL CO 4 -73",
  "PER PE -9 -75", "VEN VE 7 -66", "GBR GB 54 -2", "IRL IE 53 -8", "FRA FR 46 2", "DEU DE 51 10", "NLD NL 52 5", "BEL BE 51 4",
  "CHE CH 47 8", "AUT AT 47 14", "ITA IT 42 12", "ESP ES 40 -4", "PRT PT 39 -8", "POL PL 52 19", "CZE CZ 50 15", "SWE SE 62 15",
  "NOR NO 61 9", "FIN FI 64 26", "DNK DK 56 10", "ROU RO 46 25", "BGR BG 43 25", "GRC GR 39 22", "HUN HU 47 19", "UKR UA 49 32",
  "RUS RU 60 90", "TUR TR 39 35", "ISR IL 31 35", "SAU SA 24 45", "ARE AE 24 54", "IRN IR 32 53", "IRQ IQ 33 44", "PAK PK 30 70",
  "IND IN 21 78", "BGD BD 24 90", "CHN CN 35 103", "HKG HK 22 114", "TWN TW 24 121", "JPN JP 36 138", "KOR KR 36 128",
  "VNM VN 16 106", "THA TH 15 101", "MYS MY 4 102", "SGP SG 1 104", "IDN ID -2 118", "PHL PH 12 122", "AUS AU -25 134",
  "NZL NZ -41 174", "ZAF ZA -29 24", "EGY EG 27 30", "NGA NG 9 8", "KEN KE 0 38", "MAR MA 32 -6", "DZA DZ 28 3", "KAZ KZ 48 68",
  "LTU LT 55 24", "LVA LV 57 25", "EST EE 59 26", "SVK SK 49 19", "SRB RS 44 21", "HRV HR 45 16", "BLR BY 53 28", "MDA MD 47 29",
]) {
  const [a, b, lat, lon] = row.split(" ");
  GEO[a] = [Number(lat), Number(lon)];
  GEO[b] = [Number(lat), Number(lon)];
}

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { credentials: "same-origin", ...init });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const b = (await res.json()) as { error?: string }; if (b.error) msg = b.error; } catch { /* keep status */ }
    throw new Error(msg);
  }
  return (await res.json()) as T;
}

function GeoMap({ rows }: { rows: Ranked[] }) {
  const pts = rows.map((r) => ({ ...r, geo: GEO[r.key.toUpperCase()] })).filter((r) => r.geo);
  const max = Math.max(1, ...pts.map((p) => p.events));
  const W = 720, H = 360;
  const xy = ([lat, lon]: [number, number]) => [((lon + 180) / 360) * W, ((90 - lat) / 180) * H] as const;
  const unplaced = rows.length - pts.length;
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full rounded-xl border border-white/[0.06] bg-black/20" role="img" aria-label="Traffic destinations by country">
        {[-60, -30, 0, 30, 60].map((lat) => <line key={lat} x1={0} x2={W} y1={xy([lat, 0])[1]} y2={xy([lat, 0])[1]} stroke="currentColor" className="text-white/[0.06]" />)}
        {[-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150].map((lon) => <line key={lon} y1={0} y2={H} x1={xy([0, lon])[0]} x2={xy([0, lon])[0]} stroke="currentColor" className="text-white/[0.06]" />)}
        {pts.map((p) => {
          const [x, y] = xy(p.geo);
          const r = 4 + 18 * Math.sqrt(p.events / max);
          const hot = p.blocked > 0 && p.blocked / Math.max(1, p.events) > 0.5;
          return (
            <g key={p.key}>
              <circle cx={x} cy={y} r={r} fill={hot ? "#f43f5e" : "#38bdf8"} fillOpacity={0.35} stroke={hot ? "#f43f5e" : "#38bdf8"} strokeWidth={1}>
                <title>{`${p.key}: ${fmtNumber(p.events)} events, ${fmtNumber(p.blocked)} blocked`}</title>
              </circle>
              {r > 9 ? <text x={x} y={y + 3} textAnchor="middle" className="fill-slate-200 text-[9px]">{p.key}</text> : null}
            </g>
          );
        })}
      </svg>
      <p className="mt-2 text-xs text-slate-500">
        Bubble size = events to that country; red = mostly blocked.{unplaced > 0 ? ` ${unplaced} countries without a map position are listed in the table.` : ""}
      </p>
    </div>
  );
}

function RankTable({ rows, empty }: { rows: Ranked[]; empty: string }) {
  if (rows.length === 0) return <p className="px-5 py-4 text-sm text-slate-500">{empty}</p>;
  const max = Math.max(1, ...rows.map((r) => r.events));
  return (
    <ul className="space-y-1.5 px-5 py-4">
      {rows.map((r) => (
        <li key={r.key} className="text-[13px]">
          <div className="flex justify-between gap-3">
            <span className="truncate text-slate-200" title={r.key}>{r.key}</span>
            <span className="shrink-0 tabular-nums text-slate-400">{fmtNumber(r.events)}{r.blocked ? ` · ${fmtNumber(r.blocked)} blocked` : ""}</span>
          </div>
          <div className="mt-0.5 h-1 rounded bg-white/[0.05]"><div className="h-1 rounded bg-sky-400/70" style={{ width: `${(r.events / max) * 100}%` }} /></div>
        </li>
      ))}
    </ul>
  );
}

function Intel({ canEdit }: { canEdit: boolean }) {
  const [items, setItems] = useState<IntelItem[]>([]);
  const [total, setTotal] = useState(0);
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const r = await json<{ total: number; items: IntelItem[] }>("/api/v1/security/intel?limit=50");
      setItems(r.items); setTotal(r.total);
    } catch (e) { setMsg((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const add = async () => {
    try {
      const r = await json<{ parsed: number; added: number }>("/api/v1/security/intel", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text, url }),
      });
      setMsg(`${r.added} new indicators added (${r.parsed} parsed)`); setText(""); setUrl(""); void load();
    } catch (e) { setMsg((e as Error).message); }
  };
  const del = async (qs: string) => {
    try { await json(`/api/v1/security/intel?${qs}`, { method: "DELETE" }); void load(); } catch (e) { setMsg((e as Error).message); }
  };
  return (
    <Card>
      <CardHeader title="Threat intelligence" hint={`${fmtNumber(total)} indicators. Traffic to or from listed IPs and domains raises a high-severity finding.`}
        right={canEdit && total > 0 ? <Button size="sm" variant="danger" onClick={() => { if (confirm("Remove all indicators?")) void del("all=true"); }}>Clear all</Button> : undefined} />
      <div className="space-y-3 px-5 py-4">
        {canEdit ? (
          <>
            <textarea value={text} onChange={(e) => setText(e.target.value)} rows={3} placeholder="Paste IPs or domains, one per line (hosts-file and CSV lines work too)"
              className="w-full rounded-lg border border-white/10 bg-black/30 p-2 text-xs text-slate-200 placeholder:text-slate-600" />
            <div className="flex flex-wrap gap-2">
              <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="or feed URL (https://...)"
                className="min-w-[16rem] flex-1 rounded-lg border border-white/10 bg-black/30 px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-600" />
              <Button onClick={() => void add()} disabled={!text.trim() && !url.trim()}>Import</Button>
            </div>
          </>
        ) : <p className="text-xs text-slate-500">Administrator role required to change indicators.</p>}
        {msg ? <p className="text-xs text-slate-400">{msg}</p> : null}
        {items.length > 0 ? (
          <ul className="max-h-48 divide-y divide-white/[0.05] overflow-auto text-[12.5px]">
            {items.map((i) => (
              <li key={i.indicator} className="flex items-center justify-between gap-2 py-1">
                <span className="truncate font-mono text-slate-200">{i.indicator}</span>
                <span className="flex shrink-0 items-center gap-2 text-slate-500"><Badge tone={i.kind === "ip" ? "sky" : "violet"}>{i.kind}</Badge>
                  <span className="max-w-[10rem] truncate">{i.source}</span>
                  {canEdit ? <button className="text-rose-300 hover:text-rose-200" onClick={() => void del(`indicator=${encodeURIComponent(i.indicator)}`)} aria-label={`Remove ${i.indicator}`}>x</button> : null}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </Card>
  );
}

export function SecurityPage({ tenant }: { tenant: string }) {
  const [hours, setHours] = useState(24);
  const [sum, setSum] = useState<Summary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [showAll, setShowAll] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [admin, setAdmin] = useState(false);

  const load = useCallback(async () => {
    try {
      const t = encodeURIComponent(tenant);
      setSum(await json<Summary>(`/api/v1/security/summary?tenant=${t}&hours=${hours}`));
      setFindings((await json<{ findings: Finding[] }>(`/api/v1/security/findings?tenant=${t}&hours=${Math.max(hours, 24)}&status=${showAll ? "all" : "open"}`)).findings);
      setErr(null);
    } catch (e) { setErr((e as Error).message); }
  }, [tenant, hours, showAll]);
  useEffect(() => { void load(); const id = window.setInterval(() => void load(), 60_000); return () => window.clearInterval(id); }, [load]);
  useEffect(() => {
    json<{ role?: string; user?: { role?: string } }>("/api/v1/auth/me").then((m) => setAdmin((m.role ?? m.user?.role) === "admin")).catch(() => setAdmin(false));
  }, []);

  const ack = async (id: string) => {
    try { await json(`/api/v1/security/findings/${id}/ack`, { method: "POST" }); void load(); } catch (e) { setErr((e as Error).message); }
  };

  if (err && !sum) return <Card className="p-5 text-sm text-rose-300">{err}</Card>;
  if (!sum) return <Card className="p-5 text-sm text-slate-500">Loading...</Card>;

  const types = Array.from(new Set(sum.timeline.map((p) => p.type)));
  const rows = new Map<string, Record<string, number | string>>();
  for (const p of sum.timeline) {
    const row = rows.get(p.t) ?? { t: p.t };
    row[p.type] = ((row[p.type] as number) ?? 0) + p.events;
    rows.set(p.t, row);
  }
  const chart = Array.from(rows.values());
  const open = sum.open_findings;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {WINDOWS.map(([h, label]) => (
          <Button key={h} size="sm" variant={hours === h ? "default" : "secondary"} onClick={() => setHours(h)}>{label}</Button>
        ))}
        {err ? <span className="text-xs text-rose-300">{err}</span> : null}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          ["Threat events", fmtNumber(sum.threat_events), "text-slate-100"],
          ["Blocked", fmtNumber(sum.threat_blocked), "text-emerald-300"],
          ["Open findings", fmtNumber(open.low + open.medium + open.high + open.critical), "text-amber-300"],
          ["High / critical", fmtNumber(open.high + open.critical), "text-rose-300"],
        ].map(([label, value, tone]) => (
          <Card key={label} className="p-4"><p className="text-[11px] uppercase tracking-wider text-slate-500">{label}</p><p className={`mt-1 text-2xl font-semibold tabular-nums ${tone}`}>{value}</p></Card>
        ))}
      </div>

      <Card>
        <CardHeader title="Attack timeline" hint="IPS, anti-virus, ATP and other threat events per hour, by detection type." />
        <div className="h-64 px-3 py-4">
          {chart.length === 0 ? <Empty title="No threat events in this window" /> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chart}>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="t" tickFormatter={(v: string) => new Date(v).toLocaleString([], hours > 24 ? { weekday: "short", hour: "2-digit" } : { hour: "2-digit", minute: "2-digit" })} stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} width={40} />
                <Tooltip labelFormatter={(v) => new Date(String(v)).toLocaleString()} contentStyle={{ background: "#0b1220", border: "1px solid rgba(255,255,255,0.1)", fontSize: 12 }} />
                {types.map((t, i) => <Bar key={t} dataKey={t} stackId="a" fill={PALETTE[i % PALETTE.length]} />)}
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
        {types.length > 0 ? (
          <div className="flex flex-wrap gap-3 px-5 pb-4 text-xs text-slate-400">
            {types.map((t, i) => <span key={t} className="inline-flex items-center gap-1"><i className="inline-block h-2 w-2 rounded-sm" style={{ background: PALETTE[i % PALETTE.length] }} />{t}</span>)}
          </div>
        ) : null}
      </Card>

      <Card>
        <CardHeader title="Findings" hint="Anomalies, brute-force, port-scan and threat-intel matches. Create alert rules for them under Alert Rules."
          right={<Button size="sm" variant="secondary" onClick={() => setShowAll(!showAll)}>{showAll ? "Open only" : "Show acknowledged"}</Button>} />
        {findings.length === 0 ? <p className="px-5 py-4 text-sm text-slate-500">No findings. Baseline detectors need about a week of history.</p> : (
          <div className="overflow-x-auto px-5 py-4">
            <table className="w-full text-left text-[13px]">
              <thead className="text-[11px] uppercase tracking-wider text-slate-500"><tr><th className="py-1 pr-3">Severity</th><th className="pr-3">Type</th><th className="pr-3">Subject</th><th className="pr-3">Detail</th><th className="pr-3">Last seen</th><th /></tr></thead>
              <tbody className="divide-y divide-white/[0.05]">
                {findings.map((f) => (
                  <tr key={f.id} className={f.acknowledged ? "opacity-50" : ""}>
                    <td className="py-1.5 pr-3"><Badge tone={SEV_TONE[f.severity]}>{f.severity}</Badge></td>
                    <td className="pr-3 text-slate-300">{KIND_LABEL[f.kind] ?? f.kind}</td>
                    <td className="max-w-[14rem] truncate pr-3 font-mono text-slate-200" title={f.subject}>{f.subject}</td>
                    <td className="pr-3 text-slate-400">{f.detail}</td>
                    <td className="whitespace-nowrap pr-3 text-slate-500">{new Date(f.last_seen).toLocaleString()}</td>
                    <td>{admin && !f.acknowledged ? <Button size="sm" variant="secondary" onClick={() => void ack(f.id)}>Acknowledge</Button> : null}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card><CardHeader title="Detection types" hint="IPS / ATP / anti-virus / WAF" /><RankTable rows={sum.types} empty="No threat events." /></Card>
        <Card><CardHeader title="Top threats" /><RankTable rows={sum.top_threats} empty="No named threats." /></Card>
        <Card><CardHeader title="Top attack sources" hint={sum.sources_masked ? "Hidden for this account" : undefined} /><RankTable rows={sum.top_sources} empty={sum.sources_masked ? "Source addresses are masked." : "No sources."} /></Card>
      </div>

      <Card>
        <CardHeader title="Destination map" hint="Where traffic is going, by destination country." />
        <div className="grid gap-4 px-5 py-4 lg:grid-cols-[2fr_1fr]">
          {sum.countries.length === 0 ? <Empty title="No country data yet" /> : <GeoMap rows={sum.countries} />}
          <div className="max-h-[22rem] overflow-auto"><RankTable rows={sum.countries.slice(0, 25)} empty="No countries." /></div>
        </div>
      </Card>

      <Intel canEdit={admin} />
    </div>
  );
}
