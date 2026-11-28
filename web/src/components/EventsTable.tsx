import { useEffect, useState } from "react";
import { fmtBytes, fmtTime } from "../format";
import type { EventFilters, EventRow } from "../types";
import { api } from "../api";
import { ActionBadge, Badge, Card, Spinner } from "./ui";

const GROUPS = ["web", "threat", "firewall", "vpn", "auth", "system", "other"];

export function EventsTable({
  rows,
  loading,
  error,
  spanHours,
  rawRetentionHours,
  filters,
  onApply,
  action,
  onAction,
  group,
  onGroup,
  tenant,
  from,
  pageIndex,
  pageSize,
  hasMore,
  onPrev,
  onNext,
  onPageSize,
}: {
  rows: EventRow[];
  loading: boolean;
  error: string | null;
  spanHours: number;
  rawRetentionHours: number;
  filters: EventFilters;
  onApply: (value: EventFilters) => void;
  action: string;
  onAction: (value: string) => void;
  group: string;
  onGroup: (value: string) => void;
  tenant: string;
  from: string;
  pageIndex: number;
  pageSize: number;
  hasMore: boolean;
  onPrev: () => void;
  onNext: () => void;
  onPageSize: (value: number) => void;
}) {
  // Typing edits a draft; Enter (or Apply) sends it. Nothing is queried per keystroke.
  const [draft, setDraft] = useState<EventFilters>(filters);
  useEffect(() => { setDraft(filters); }, [filters]);
  const { q: query, user, category, device } = filters;
  const dirty = draft.q !== filters.q || draft.user !== filters.user || draft.category !== filters.category || draft.device !== filters.device;
  const apply = () => onApply({ q: draft.q.trim(), user: draft.user.trim(), category: draft.category.trim(), device: draft.device.trim() });
  const onEnter = (event: React.KeyboardEvent<HTMLInputElement>) => { if (event.key === "Enter") apply(); };
  const first = pageIndex * pageSize + 1;
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <Card>
        <div className="flex flex-wrap items-end justify-between gap-3 px-5 pt-4">
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-slate-100">Recent activity</h2>
            <p className="mt-0.5 text-xs text-slate-500">
              {rows.length === 0 ? "No" : `Entries ${first}-${first + rows.length - 1}`} · newest first · raw details retained {rawRetentionHours}h
              {loading ? " · loading" : ""}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 pb-1">
            <div className="relative">
              <svg
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <circle cx="11" cy="11" r="7" />
                <path d="m20 20-3.5-3.5" />
              </svg>
              <input
                type="search"
                value={draft.q}
                onChange={(event) => setDraft({ ...draft, q: event.target.value })}
                onKeyDown={onEnter}
                placeholder="User, domain, URL, IP, rule…"
                className="w-56 rounded-lg border border-white/10 bg-black/30 py-1.5 pl-8 pr-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-400/40 focus:outline-none"
              />
            </div>
            <input
              type="search"
              value={draft.user}
              onChange={(event) => setDraft({ ...draft, user: event.target.value })}
              onKeyDown={onEnter}
              placeholder="Filter user"
              className="w-36 rounded-lg border border-white/10 bg-black/30 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-400/40 focus:outline-none"
            />
            <input
              type="search"
              value={draft.category}
              onChange={(event) => setDraft({ ...draft, category: event.target.value })}
              onKeyDown={onEnter}
              placeholder="Filter category"
              className="w-40 rounded-lg border border-white/10 bg-black/30 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-400/40 focus:outline-none"
            />
            <input
              type="search"
              value={draft.device}
              onChange={(event) => setDraft({ ...draft, device: event.target.value })}
              onKeyDown={onEnter}
              placeholder="Filter device"
              className="w-36 rounded-lg border border-white/10 bg-black/30 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-400/40 focus:outline-none"
            />
            <select
              value={action}
              onChange={(event) => onAction(event.target.value)}
              className="rounded-lg border border-white/10 bg-[#0b1220] px-2 py-1.5 text-xs text-slate-300 focus:border-emerald-400/40 focus:outline-none"
            >
              <option value="">All decisions</option>
              <option value="allowed">Allowed</option>
              <option value="blocked">Blocked</option>
              <option value="warned">Warned</option>
            </select>
            <select
              value={group}
              onChange={(event) => onGroup(event.target.value)}
              className="rounded-lg border border-white/10 bg-[#0b1220] px-2 py-1.5 text-xs text-slate-300 focus:border-emerald-400/40 focus:outline-none"
            >
              <option value="">All log types</option>
              {GROUPS.map((option) => (
                <option key={option} value={option}>
                  {option[0].toUpperCase() + option.slice(1)}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={apply}
              className={`rounded-lg border px-2.5 py-1.5 text-xs ${dirty ? "border-emerald-400/50 bg-emerald-400/10 text-emerald-200" : "border-white/10 bg-white/[0.03] text-slate-300"} hover:text-slate-100`}
            >
              Search
            </button>
            <button
              type="button"
              onClick={async () => {
                try {
                  await api.exportEvents({
                    tenant,
                    from,
                    q: query || undefined,
                    action: action || undefined,
                    group: group || undefined,
                    user: user || undefined,
                    category: category || undefined,
                    device: device || undefined,
                  });
                } catch (err) {
                  alert(err instanceof Error ? err.message : "Export failed");
                }
              }}
              className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs text-slate-300 hover:text-slate-100"
            >
              Export CSV
            </button>
            <button
              type="button"
              onClick={async () => {
                try {
                  await api.downloadReportOnDemand({
                    format: "pdf",
                    tenant,
                    filters: {
                      from,
                      q: query || undefined,
                      action: action || undefined,
                      group: group || undefined,
                      user: user || undefined,
                      category: category || undefined,
                      device: device || undefined,
                    },
                  });
                } catch (err) {
                  alert(err instanceof Error ? err.message : "Download failed");
                }
              }}
              className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs text-slate-300 hover:text-slate-100"
            >
              Download PDF
            </button>
            {loading ? <Spinner /> : null}
          </div>
        </div>

      <div className="mt-3 overflow-x-auto">
        <table className="w-full min-w-[980px] border-collapse text-left">
          <thead>
            <tr className="border-y border-white/[0.06] bg-white/[0.015] text-[10px] uppercase tracking-wider text-slate-500">
              <th className="px-5 py-2 font-medium">Time</th>
              <th className="px-3 py-2 font-medium">Decision</th>
              <th className="px-3 py-2 font-medium">User</th>
              <th className="px-3 py-2 font-medium">Destination</th>
              <th className="px-3 py-2 font-medium">Category</th>
              <th className="px-3 py-2 text-right font-medium">Traffic</th>
              <th className="px-5 py-2 font-medium">Policy</th>
            </tr>
          </thead>
          <tbody className={loading ? "opacity-70 transition-opacity" : "transition-opacity"}>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-5 py-12 text-center text-sm text-slate-500">
                  {loading ? "Loading events…" : "No events match these filters."}
                </td>
              </tr>
            ) : (
              rows.map((row) => {
                const open = expanded === row.id;
                return (
                  <FragmentRow
                    key={row.id}
                    row={row}
                    open={open}
                    spanHours={spanHours}
                    onToggle={() => setExpanded(open ? null : row.id)}
                  />
                );
              })
            )}
          </tbody>
        </table>
      </div>
      {error ? <p role="alert" className="px-5 pt-3 text-xs text-rose-300">{error}</p> : null}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] px-5 py-3 text-xs text-slate-400">
        <span>
          Page {pageIndex + 1}
          {spanHours > rawRetentionHours ? ` · only the last ${rawRetentionHours}h of raw logs is stored; older traffic is in Search and the reports` : ""}
        </span>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5">
            Rows
            <select
              value={pageSize}
              onChange={(event) => onPageSize(Number(event.target.value))}
              className="rounded-lg border border-white/10 bg-[#0b1220] px-1.5 py-1 text-xs text-slate-300"
            >
              {[50, 100, 200, 500].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          <button type="button" onClick={onPrev} disabled={pageIndex === 0 || loading}
            className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1 text-slate-300 hover:text-slate-100 disabled:opacity-40">
            Newer
          </button>
          <button type="button" onClick={onNext} disabled={!hasMore || loading}
            className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1 text-slate-300 hover:text-slate-100 disabled:opacity-40">
            Older
          </button>
        </div>
      </div>
    </Card>
  );
}

function FragmentRow({
  row,
  open,
  spanHours,
  onToggle,
}: {
  row: EventRow;
  open: boolean;
  spanHours: number;
  onToggle: () => void;
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-b border-white/[0.04] text-xs transition-colors ${
          open ? "bg-white/[0.04]" : "hover:bg-white/[0.025]"
        }`}
      >
        <td className="tabular whitespace-nowrap px-5 py-2 text-slate-400">
          {fmtTime(row.ts)}
          {spanHours > 48 ? (
            <span className="ml-1 text-[10px] text-slate-600">
              {new Date(row.ts).toLocaleDateString([], { month: "short", day: "numeric" })}
            </span>
          ) : null}
        </td>
        <td className="px-3 py-2">
          <div className="flex flex-col items-start gap-1">
            <ActionBadge action={row.action} />
            <span className="text-[10px] text-slate-600">{row.group}</span>
          </div>
        </td>
        <td className="max-w-[160px] truncate px-3 py-2 text-slate-300" title={row.user ?? undefined}>
          {row.user ?? <span className="text-slate-600">unidentified</span>}
        </td>
        <td className="max-w-[320px] px-3 py-2">
          <div className="flex items-center gap-1.5">
            <span className="truncate font-medium text-slate-200" title={row.domain ?? row.dst_ip ?? ""}>
              {row.threat ?? row.domain ?? row.dst_ip ?? "—"}
            </span>
            {row.threat ? <Badge tone="rose">threat</Badge> : null}
          </div>
          <p className="mt-0.5 truncate text-[10px] text-slate-500" title={row.url ?? undefined}>
            {row.application ? `${row.application} · ` : ""}
            {row.url ?? row.log_component ?? row.log_type}
          </p>
        </td>
        <td
          className="max-w-[150px] truncate px-3 py-2 text-slate-400"
          title={[row.category, row.category_type].filter(Boolean).join(" · ") || undefined}
        >
          <div>{row.category ?? "—"}</div>
          {row.category_type ? (
            <div className="text-[10px] text-slate-600">{row.category_type}</div>
          ) : null}
        </td>
        <td className="tabular whitespace-nowrap px-3 py-2 text-right text-slate-400">
          <div>{row.bytes_down != null ? `↓ ${fmtBytes(row.bytes_down)}` : "—"}</div>
          <div className="text-[10px] text-slate-600">
            {row.bytes_up != null ? `↑ ${fmtBytes(row.bytes_up)}` : ""}
          </div>
        </td>
        <td className="max-w-[180px] truncate px-5 py-2 text-slate-400" title={row.rule ?? undefined}>
          {row.rule ?? "—"}
        </td>
      </tr>
      {open ? (
        <tr className="border-b border-white/[0.04] bg-[#0a101c]">
          <td colSpan={7} className="px-5 py-4">
            <div className="grid gap-x-8 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
              <Detail label="Logged" value={`${new Date(row.ts).toLocaleString()} · ${row.log_type}${row.log_component ? ` / ${row.log_component}` : ""}`} />
              <Detail
                label="Flow"
                value={
                  row.src_ip
                    ? `${row.src_ip}${row.src_port ? `:${row.src_port}` : ""} → ${row.dst_ip ?? "?"}${
                        row.dst_port ? `:${row.dst_port}` : ""
                      }`
                    : "—"
                }
              />
              <Detail label="Device" value={row.device_name ?? "—"} />
              <Detail label="Method / status" value={[row.method, row.status].filter(Boolean).join(" ") || "—"} />
              <Detail label="Application" value={row.application ?? "—"} />
              <Detail label="Policy" value={row.rule ?? "—"} />
              <div className="sm:col-span-2 lg:col-span-3">
                <Detail label="URL" value={row.url ?? "—"} breakAll />
              </div>
              {row.message ? (
                <div className="sm:col-span-2 lg:col-span-3">
                  <Detail label="Message" value={row.message} breakAll />
                </div>
              ) : null}
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function Detail({
  label,
  value,
  breakAll,
}: {
  label: string;
  value: string;
  breakAll?: boolean;
}) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider text-slate-600">{label}</p>
      <p className={`text-slate-300 ${breakAll ? "break-all" : ""}`}>{value}</p>
    </div>
  );
}
