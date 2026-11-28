import { useCallback, useEffect, useRef, useState } from "react";
import { fmtBytes, fmtNumber } from "../format";
import { Badge, Button, Card, CardHeader, Empty } from "./ui";

interface Dest {
  ip: string; host: string | null; app: string | null; category: string | null; source: string | null;
  country: string | null; port: number | null; protocol: string | null; service: string | null;
  connections: number; bytes: number; users: number;
}

const WINDOWS: [number, string][] = [[15, "15 min"], [60, "1 hour"], [180, "3 hours"], [360, "6 hours"]];

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { credentials: "same-origin", ...init });
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try { const b = (await res.json()) as { error?: string }; if (b.error) msg = b.error; } catch { /* keep status */ }
    throw new Error(msg);
  }
  return (await res.json()) as T;
}

export function DestinationsPage({ tenant }: { tenant: string }) {
  const [minutes, setMinutes] = useState(60);
  const [onlyUnknown, setOnlyUnknown] = useState(true);
  const [rows, setRows] = useState<Dest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [appName, setAppName] = useState("");
  const [category, setCategory] = useState("");
  const abort = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abort.current?.abort();
    const ctl = new AbortController();
    abort.current = ctl;
    setError(null);
    try {
      const q = new URLSearchParams({ minutes: String(minutes), limit: "200", unclassified: String(onlyUnknown) });
      if (tenant) q.set("tenant", tenant);
      const r = await json<{ items: Dest[] }>(`/api/v1/traffic/destinations?${q}`, { signal: ctl.signal });
      setRows(r.items);
    } catch (err) {
      if ((err as Error).name !== "AbortError") setError((err as Error).message);
    }
  }, [minutes, onlyUnknown, tenant]);

  useEffect(() => { void load(); return () => abort.current?.abort(); }, [load]);

  const save = async (ip: string) => {
    if (!appName.trim()) { setError("Enter an application name."); return; }
    try {
      await json("/api/v1/traffic/labels", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, app: appName.trim(), category: category.trim() || undefined }),
      });
      setEditing(null); setAppName(""); setCategory("");
      await load();
    } catch (err) { setError((err as Error).message); }
  };
  const clear = async (ip: string) => {
    try { await json(`/api/v1/traffic/labels?ip=${encodeURIComponent(ip)}`, { method: "DELETE" }); await load(); }
    catch (err) { setError((err as Error).message); }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="Destinations"
          hint="Where traffic goes when the firewall does not name the application (DPI off). Names come from web-filter logs, reverse DNS and the port table; label the rest by hand."
          right={<Button size="sm" variant="secondary" onClick={() => void load()}>Refresh</Button>}
        />
        <div className="flex flex-wrap items-center gap-1.5 px-4 pb-3">
          {WINDOWS.map(([m, label]) => (
            <button key={m} type="button" aria-pressed={minutes === m} onClick={() => setMinutes(m)}
              className={`rounded-lg border px-3 py-1.5 text-xs ${minutes === m ? "border-emerald-400/60 bg-emerald-400/10 text-emerald-200" : "border-white/10 bg-white/[0.03] text-slate-300"}`}>{label}</button>
          ))}
          <label className="ml-2 flex items-center gap-1.5 text-xs text-slate-400">
            <input type="checkbox" checked={onlyUnknown} onChange={(e) => setOnlyUnknown(e.target.checked)} />
            Only unidentified
          </label>
        </div>
        {error ? <p role="alert" className="px-4 pb-3 text-xs text-rose-300">{error}</p> : null}
        {rows === null ? <Empty title="Loading..." /> : rows.length === 0 ? (
          <Empty title="Nothing to show" hint={onlyUnknown ? "Every busy destination in this window is already identified." : "No firewall traffic in this window."} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-[11px] uppercase tracking-wider text-slate-500">
                <tr><th className="px-4 py-2">Destination</th><th className="px-2">Identified as</th><th className="px-2">Port</th><th className="px-2">Country</th>
                  <th className="px-2 text-right">Traffic</th><th className="px-2 text-right">Conns</th><th className="px-2 text-right">Users</th><th className="px-4" /></tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const key = `${r.ip}:${r.port ?? ""}`;
                  return (
                    <tr key={key} className="border-t border-white/[0.05] align-top text-slate-300">
                      <td className="px-4 py-2"><div className="font-mono">{r.ip}</div>{r.host ? <div className="text-[11px] text-slate-500">{r.host}</div> : null}</td>
                      <td className="px-2 py-2">
                        {editing === r.ip ? (
                          <div className="flex flex-wrap gap-1.5">
                            <input value={appName} onChange={(e) => setAppName(e.target.value)} placeholder="Application" aria-label="Application"
                              onKeyDown={(e) => { if (e.key === "Enter") void save(r.ip); }}
                              className="w-32 rounded border border-white/10 bg-black/30 px-2 py-1 text-xs text-slate-200" />
                            <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Category" aria-label="Category"
                              onKeyDown={(e) => { if (e.key === "Enter") void save(r.ip); }}
                              className="w-32 rounded border border-white/10 bg-black/30 px-2 py-1 text-xs text-slate-200" />
                          </div>
                        ) : r.app ? (
                          <div><span className="text-slate-100">{r.app}</span> <Badge tone={r.source === "manual" ? "emerald" : "slate"}>{r.source}</Badge>
                            <div className="text-[11px] text-slate-500">{r.category}</div></div>
                        ) : <span className="text-slate-500">{r.service ? `${r.service} (port only)` : "unknown"}</span>}
                      </td>
                      <td className="px-2 py-2">{r.port ?? "-"}{r.protocol ? <span className="text-slate-500"> {r.protocol}</span> : null}</td>
                      <td className="px-2 py-2">{r.country ?? "-"}</td>
                      <td className="px-2 py-2 text-right">{fmtBytes(r.bytes)}</td>
                      <td className="px-2 py-2 text-right">{fmtNumber(r.connections)}</td>
                      <td className="px-2 py-2 text-right">{fmtNumber(r.users)}</td>
                      <td className="whitespace-nowrap px-4 py-2 text-right">
                        {editing === r.ip ? (
                          <><Button size="sm" onClick={() => void save(r.ip)}>Save</Button> <Button size="sm" variant="secondary" onClick={() => setEditing(null)}>Cancel</Button></>
                        ) : (
                          <><Button size="sm" variant="secondary" onClick={() => { setEditing(r.ip); setAppName(r.app ?? ""); setCategory(r.category ?? ""); }}>Label</Button>
                            {r.source === "manual" ? <> <Button size="sm" variant="danger" onClick={() => void clear(r.ip)}>Clear</Button></> : null}</>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
