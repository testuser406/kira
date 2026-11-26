import { useEffect, useState } from "react";
import { fmtBytes, fmtNumber } from "../format";
import { Card, CardHeader } from "./ui";

interface Hint { severity: "error" | "warn" | "info"; title: string; detail: string; cli: string[]; gui: string[] }
interface Health {
  status: "ok" | "warn" | "error";
  database: { ok: boolean; size_bytes: number };
  last_event_at: string | null;
  last_event_age_secs: number | null;
  events_last_1m: number; events_last_5m: number; events_last_60m: number;
  ingest: Record<string, number> | null;
  diagnosis: Hint[];
}

const TONE = { ok: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200", warn: "border-amber-400/30 bg-amber-400/10 text-amber-200", error: "border-rose-400/30 bg-rose-400/10 text-rose-200" };
const LABEL = { ok: "Healthy - logs are arriving", warn: "Needs attention", error: "Problem detected" };

function age(s: number | null): string {
  if (s === null) return "never";
  if (s < 0) return "in the future";
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  return `${(s / 3600).toFixed(1)} h ago`;
}

function Steps({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="mt-2">
      <p className="text-[11px] uppercase tracking-wider text-slate-500">{title}</p>
      <ul className="mt-1 space-y-1">
        {items.map((c) => (
          <li key={c} className={`rounded px-2 py-1 text-[12.5px] ${title.startsWith("Command") ? "bg-black/40 font-mono text-sky-200" : "text-slate-300"}`}>{c}</li>
        ))}
      </ul>
    </div>
  );
}

function PrivacySetting() {
  const [mask, setMask] = useState<boolean | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    fetch("/api/v1/settings", { credentials: "same-origin" }).then((r) => r.json()).then((b) => setMask(!!b.mask_users)).catch(() => setMask(null));
  }, []);
  const save = async (v: boolean) => {
    const r = await fetch("/api/v1/settings", { method: "PUT", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ mask_users: v }) });
    if (r.ok) { setMask(v); setMsg("Saved"); } else setMsg(r.status === 403 ? "Administrator role required" : `HTTP ${r.status}`);
  };
  if (mask === null) return null;
  return (
    <Card>
      <CardHeader title="Privacy" />
      <div className="px-5 py-4">
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={mask} onChange={(e) => void save(e.target.checked)} />
          Hide user names and IPs from non-admin viewers (shown as user-xxxxxxxx)
        </label>
        {msg ? <p className="mt-1 text-xs text-slate-500">{msg}</p> : null}
      </div>
    </Card>
  );
}

export function SystemPage() {
  const [h, setH] = useState<Health | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let stop = false;
    const load = async () => {
      try {
        const res = await fetch("/api/v1/system/health", { credentials: "same-origin" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        if (!(res.headers.get("content-type") ?? "").includes("json")) throw new Error("API is outdated - stop, rebuild and start Kira");
        const body = (await res.json()) as Health;
        if (!stop) { setH(body); setErr(null); }
      } catch (e) { if (!stop) setErr((e as Error).message); }
    };
    void load();
    const id = window.setInterval(() => { if (!document.hidden) void load(); }, 10_000);
    return () => { stop = true; window.clearInterval(id); };
  }, []);

  const ing = h?.ingest;
  const counters: [string, string][] = ing
    ? [["Datagrams received", fmtNumber(ing.datagrams)], ["Parsed events", fmtNumber(ing.parsed)], ["Rejected lines", fmtNumber(ing.rejected)],
       ["Denied sources", fmtNumber(ing.denied_sources)], ["Written to DB", fmtNumber(ing.written)], ["DB errors", fmtNumber(ing.db_errors)],
       ["Dropped", fmtNumber(ing.dropped)], ["Spilled to disk", fmtNumber(ing.spilled ?? 0)], ["Replayed", fmtNumber(ing.replayed ?? 0)], ["Queue", `${Math.round(ing.queue_utilization_percent)}%`]]
    : [];
  return (
    <div className="space-y-4">
      {err ? <p className="text-sm text-rose-300">{err}</p> : null}
      {h ? (
        <>
          <div className={`rounded-lg border px-4 py-3 text-sm font-medium ${TONE[h.status]}`}>{LABEL[h.status]}</div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {[["Last event", age(h.last_event_age_secs)], ["Events, last minute", fmtNumber(h.events_last_1m)],
              ["Events, last 5 min", fmtNumber(h.events_last_5m)], ["Events, last hour", fmtNumber(h.events_last_60m)]].map(([l, v]) => (
              <div key={l} className="rounded-lg border border-white/[0.06] bg-black/20 p-3">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">{l}</p>
                <p className="mt-1 text-xl font-semibold text-slate-100">{v}</p>
              </div>
            ))}
          </div>
          {h.diagnosis.length ? h.diagnosis.map((d) => (
            <Card key={d.title}>
              <div className="px-5 py-4">
                <p className={`text-sm font-semibold ${d.severity === "error" ? "text-rose-300" : d.severity === "warn" ? "text-amber-300" : "text-sky-300"}`}>{d.title}</p>
                <p className="mt-1 text-[13px] text-slate-400">{d.detail}</p>
                <Steps title="Command line (PowerShell in the Kira folder)" items={d.cli} />
                <Steps title="Using the Windows / Sophos screens" items={d.gui} />
              </div>
            </Card>
          )) : null}
          <Card>
            <CardHeader title="Collector counters (since it started)" />
            {counters.length ? (
              <div className="grid grid-cols-2 gap-3 px-5 py-4 md:grid-cols-4">
                {counters.map(([l, v]) => (
                  <div key={l}><p className="text-[10px] uppercase tracking-wider text-slate-500">{l}</p><p className="text-lg text-slate-200">{v}</p></div>
                ))}
              </div>
            ) : <p className="px-5 py-4 text-sm text-slate-500">Collector is not reachable.</p>}
            <p className="px-5 pb-4 text-xs text-slate-500">Database size {fmtBytes(h.database.size_bytes)} · for a full automatic check run <code className="text-sky-200">.\scripts\windows\kira.ps1 doctor</code></p>
          </Card>
          <PrivacySetting />
        </>
      ) : !err ? <Card><div className="p-8 text-sm text-slate-500">Checking…</div></Card> : null}
    </div>
  );
}
