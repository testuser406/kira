import { useCallback, useEffect, useState } from "react";
import { fmtBytes, fmtNumber } from "../format";
import { Card, CardHeader, Empty } from "./ui";

type Cls = "productive" | "neutral" | "unproductive";
interface Summary {
  window_min: number;
  shares: Record<Cls, number>;
  sites: { key: string; events: number; minutes: number; bytes: number; class: Cls | null }[];
  browse_time: { key: string; minutes: number; events: number }[];
  categories: { key: string; events: number; class: Cls }[];
}
interface Guideline { kind: string; key: string; class: Cls }

const WINDOWS: [number, string][] = [[60, "1h"], [1440, "24h"], [10080, "7d"]];
const TONE: Record<Cls, string> = {
  productive: "bg-emerald-400/80",
  neutral: "bg-slate-400/60",
  unproductive: "bg-rose-400/80",
};

function mins(m: number): string {
  return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`;
}

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { credentials: "same-origin", ...init });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  if (!(res.headers.get("content-type") ?? "").includes("json"))
    throw new Error("API is outdated - stop, rebuild and start Kira");
  return (await res.json()) as T;
}

export function ProductivityPage({ tenant }: { tenant: string }) {
  const [win, setWin] = useState(1440);
  const [sum, setSum] = useState<Summary | null>(null);
  const [rules, setRules] = useState<Guideline[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [draft, setDraft] = useState<Guideline>({ kind: "category", key: "", class: "unproductive" });

  const load = useCallback(async () => {
    try {
      const t = encodeURIComponent(tenant);
      setSum(await json<Summary>(`/api/v1/productivity/summary?tenant=${t}&window=${win}`));
      setRules((await json<{ items: Guideline[] }>(`/api/v1/productivity/guidelines?tenant=${t}`)).items);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    }
  }, [tenant, win]);

  useEffect(() => {
    void load();
    const id = window.setInterval(() => { if (!document.hidden) void load(); }, 30_000);
    return () => window.clearInterval(id);
  }, [load]);

  const save = async (g: Guideline) => {
    if (!g.key.trim()) return;
    try {
      await json(`/api/v1/productivity/guidelines?tenant=${encodeURIComponent(tenant)}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(g),
      });
      setDraft({ ...draft, key: "" });
      await load();
    } catch (e) { setErr((e as Error).message); }
  };
  const remove = async (g: Guideline) => {
    const q = new URLSearchParams({ tenant, kind: g.kind, key: g.key });
    try { await json(`/api/v1/productivity/guidelines?${q}`, { method: "DELETE" }); await load(); }
    catch (e) { setErr((e as Error).message); }
  };

  const total = sum ? sum.shares.productive + sum.shares.neutral + sum.shares.unproductive : 0;
  const pct = (n: number) => (total ? (n / total) * 100 : 0);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-slate-500">
          Productivity from web activity · browse time = minutes with web activity
          {err ? <span className="ml-2 text-rose-300">({err})</span> : null}
        </p>
        <div className="flex gap-1">
          {WINDOWS.map(([w, l]) => (
            <button key={w} type="button" onClick={() => setWin(w)}
              className={`rounded-md border px-2.5 py-1 text-xs ${w === win
                ? "border-sky-400/40 bg-sky-400/10 text-sky-200" : "border-white/10 text-slate-400 hover:bg-white/5"}`}>
              {l}
            </button>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader title="Productivity split (web requests)" />
        <div className="space-y-3 px-5 pb-4 pt-3">
          <div className="flex h-3 overflow-hidden rounded-full bg-white/[0.05]">
            {(["productive", "neutral", "unproductive"] as Cls[]).map((c) => (
              <div key={c} className={TONE[c]} style={{ width: `${pct(sum?.shares[c] ?? 0)}%` }} />
            ))}
          </div>
          <div className="flex flex-wrap gap-4 text-xs text-slate-400">
            {(["productive", "neutral", "unproductive"] as Cls[]).map((c) => (
              <span key={c}>
                <span className={`mr-1.5 inline-block h-2 w-2 rounded-full ${TONE[c]}`} />
                {c} {pct(sum?.shares[c] ?? 0).toFixed(1)}% ({fmtNumber(sum?.shares[c] ?? 0)})
              </span>
            ))}
          </div>
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader title="Browse time per user" hint="distinct minutes with web activity" />
          <div className="px-5 pb-4 pt-3">
            {!sum || sum.browse_time.length === 0 ? <Empty title="No web activity" /> : (
              <table className="w-full text-[13px]"><tbody>
                {sum.browse_time.map((u) => (
                  <tr key={u.key} className="border-b border-white/[0.04]">
                    <td className="truncate py-1.5 text-slate-300">{u.key}</td>
                    <td className="tabular py-1.5 text-right text-slate-400">{mins(u.minutes)}</td>
                    <td className="tabular py-1.5 pl-3 text-right text-slate-500">{fmtNumber(u.events)} req</td>
                  </tr>))}
              </tbody></table>)}
          </div>
        </Card>
        <Card>
          <CardHeader title="Top sites (cleaned)" hint="subdomains merged; ads, trackers and CDNs removed" />
          <div className="px-5 pb-4 pt-3">
            {!sum || sum.sites.length === 0 ? <Empty title="No sites yet" /> : (
              <table className="w-full text-[13px]"><tbody>
                {sum.sites.map((s) => (
                  <tr key={s.key} className="border-b border-white/[0.04]">
                    <td className="truncate py-1.5 text-slate-300">
                      {s.key}{s.class ? <span className={`ml-2 inline-block h-1.5 w-1.5 rounded-full ${TONE[s.class]}`} /> : null}
                    </td>
                    <td className="tabular py-1.5 text-right text-slate-400">{mins(s.minutes)}</td>
                    <td className="tabular py-1.5 pl-3 text-right text-slate-500">{fmtNumber(s.events)} · {fmtBytes(s.bytes)}</td>
                  </tr>))}
              </tbody></table>)}
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader title="Productivity guidelines" hint="classify categories, applications or sites (admin)" />
        <div className="space-y-3 px-5 pb-4 pt-3">
          <div className="flex flex-wrap gap-2">
            <select value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value })}
              className="rounded-md border border-white/10 bg-black/30 px-2 py-1 text-sm text-slate-200">
              <option value="category">category</option><option value="site">site</option>
              <option value="application">application</option>
            </select>
            <input value={draft.key} onChange={(e) => setDraft({ ...draft, key: e.target.value })}
              placeholder="e.g. Social Networking or youtube.com"
              className="min-w-[220px] flex-1 rounded-md border border-white/10 bg-black/30 px-2 py-1 text-sm text-slate-200" />
            <select value={draft.class} onChange={(e) => setDraft({ ...draft, class: e.target.value as Cls })}
              className="rounded-md border border-white/10 bg-black/30 px-2 py-1 text-sm text-slate-200">
              <option value="productive">productive</option><option value="neutral">neutral</option>
              <option value="unproductive">unproductive</option>
            </select>
            <button type="button" onClick={() => void save(draft)}
              className="rounded-md border border-sky-400/40 bg-sky-400/10 px-3 py-1 text-sm text-sky-200">Save</button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {rules.map((g) => (
              <span key={`${g.kind}:${g.key}`} className="inline-flex items-center gap-1.5 rounded-full border border-white/10 px-2.5 py-1 text-xs text-slate-300">
                <span className={`h-1.5 w-1.5 rounded-full ${TONE[g.class]}`} />
                {g.key} <span className="text-slate-600">{g.kind}</span>
                <button type="button" title="Remove" onClick={() => void remove(g)} className="text-slate-500 hover:text-rose-300">×</button>
              </span>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}
