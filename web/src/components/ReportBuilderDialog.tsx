import { useMemo, useState } from "react";
import type { CreateCustomReport, CustomReportResponse, ReportTemplateResponse } from "../types";
import { ReportFilterBuilder } from "./ReportFilterBuilder";
import { Button, Input } from "./ui";

const PERIODS: [string, string][] = [
  ["1h", "Last hour"],
  ["24h", "24 hours"],
  ["7d", "7 days"],
  ["30d", "30 days"],
  ["90d", "90 days"],
];
const FORMATS: [string, string][] = [["pdf", "PDF"], ["xlsx", "Excel"], ["csv", "CSV"]];
const TOPS = [10, 15, 25, 50, 100];
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CATEGORY_LABEL: Record<string, string> = {
  user_activity: "Users", department: "Departments", safeguarding: "Safeguarding", websites: "Websites",
  activity: "Activity", searches: "Searches", youtube: "YouTube", productivity: "Productivity", firewall: "Firewall",
  security: "Security", bandwidth: "Bandwidth", vpn: "VPN", network: "Network", web_filter: "Web filter", custom: "Custom",
};

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <div>
        <h4 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{title}</h4>
        {hint ? <p className="text-[11px] text-slate-500">{hint}</p> : null}
      </div>
      {children}
    </section>
  );
}

function Choice({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`rounded-lg border px-3 py-1.5 text-xs transition ${
        active ? "border-emerald-400/60 bg-emerald-400/10 text-emerald-200" : "border-white/10 bg-white/[0.03] text-slate-300 hover:text-slate-100"
      }`}
    >
      {children}
    </button>
  );
}

export function ReportBuilderDialog({
  templates,
  initial,
  onClose,
  onSubmit,
}: {
  templates: ReportTemplateResponse[];
  initial: CustomReportResponse | null;
  onClose: () => void;
  onSubmit: (payload: CreateCustomReport, runAfter: boolean, id?: string) => Promise<void>;
}) {
  const [templateId, setTemplateId] = useState<string>("");
  const [name, setName] = useState(initial?.name ?? "");
  const [nameTouched, setNameTouched] = useState(Boolean(initial));
  const [description, setDescription] = useState(initial?.description ?? "");
  const [filters, setFilters] = useState<Record<string, unknown>>(initial?.filters ?? { from: "24h", to: "now" });
  const [format, setFormat] = useState(initial?.format ?? "pdf");
  const [recipients, setRecipients] = useState<string[]>(initial?.recipients ?? []);
  const [recipientText, setRecipientText] = useState("");
  const [showMore, setShowMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const groups = useMemo(() => {
    const map = new Map<string, ReportTemplateResponse[]>();
    for (const t of templates) {
      const list = map.get(t.category) ?? [];
      list.push(t);
      map.set(t.category, list);
    }
    return Array.from(map.entries());
  }, [templates]);

  const pickTemplate = (t: ReportTemplateResponse | null) => {
    setTemplateId(t?.id ?? "");
    if (!t) {
      setFilters({ from: "24h", to: "now" });
      return;
    }
    setFilters({ to: "now", ...(t.default_filters as Record<string, unknown>) });
    if (!nameTouched || !name.trim()) setName(t.name);
    if (!description.trim() || templates.some((x) => x.description === description)) setDescription(t.description ?? "");
  };

  const set = (key: string, value: unknown) => {
    const next = { ...filters, [key]: value };
    if (value === "" || value === undefined) delete next[key];
    setFilters(next);
  };

  const addRecipients = (text: string) => {
    const parts = text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
    if (parts.length === 0) return;
    const bad = parts.filter((p) => !EMAIL.test(p));
    if (bad.length > 0) {
      setError(`Not an e-mail address: ${bad[0]}`);
      return;
    }
    setError(null);
    setRecipients(Array.from(new Set([...recipients, ...parts])));
    setRecipientText("");
  };

  const submit = async (runAfter: boolean) => {
    if (!name.trim()) {
      setError("Give the report a name.");
      return;
    }
    // A half-typed address in the box counts as entered.
    const pending = recipientText.split(/[\s,;]+/).filter(Boolean);
    if (pending.some((p) => !EMAIL.test(p))) {
      setError("Fix or clear the e-mail address you were typing.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onSubmit(
        {
          name: name.trim(),
          template_id: templateId || undefined,
          description: description.trim() || null,
          filters,
          format: format as CreateCustomReport["format"],
          recipients: Array.from(new Set([...recipients, ...pending])),
        },
        runAfter,
        initial?.id,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the report");
      setBusy(false);
    }
  };

  const period = String(filters.from ?? "24h");
  const top = Number(filters.top ?? 15);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-2 backdrop-blur-sm sm:p-4" role="dialog" aria-modal="true" aria-label={initial ? "Edit custom report" : "New custom report"}>
      <div className="my-auto flex max-h-[calc(100dvh-1rem)] w-full max-w-3xl flex-col rounded-xl border border-white/10 bg-[#0b1220] shadow-2xl sm:max-h-[calc(100dvh-2rem)]">
        <header className="shrink-0 border-b border-white/[0.06] px-5 py-4">
          <h3 className="text-lg font-semibold text-slate-100">{initial ? "Edit custom report" : "New custom report"}</h3>
          <p className="text-xs text-slate-500">Pick a starting point, adjust the basics, save. Advanced filters are optional.</p>
        </header>

        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-5 py-4">
          {!initial ? (
            <Section title="1. Start from" hint="A template fills in the report type and filters; you can change everything after.">
              <div className="max-h-44 space-y-2 overflow-y-auto pr-1">
                <Choice active={templateId === ""} onClick={() => pickTemplate(null)}>Blank report</Choice>
                {groups.map(([category, list]) => (
                  <div key={category} className="flex flex-wrap items-center gap-1.5">
                    <span className="w-24 shrink-0 text-[11px] text-slate-500">{CATEGORY_LABEL[category] ?? category}</span>
                    {list.map((t) => (
                      <Choice key={t.id} active={templateId === t.id} onClick={() => pickTemplate(t)}>{t.name}</Choice>
                    ))}
                  </div>
                ))}
              </div>
            </Section>
          ) : null}

          <Section title={initial ? "Report" : "2. Report"}>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] text-slate-500" htmlFor="rb-name">Name</label>
                <Input value={name} placeholder="e.g. Weekly user activity"
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => { setName(e.target.value); setNameTouched(true); }} />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-slate-500" htmlFor="rb-desc">Description (optional)</label>
                <Input value={description} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setDescription(e.target.value)} />
              </div>
            </div>
          </Section>

          <Section title={initial ? "Period and detail" : "3. Period and detail"}>
            <div className="flex flex-wrap items-center gap-1.5">
              {PERIODS.map(([value, label]) => (
                <Choice key={value} active={period === value} onClick={() => { set("from", value); set("to", "now"); }}>{label}</Choice>
              ))}
              {!PERIODS.some(([v]) => v === period) ? <span className="text-[11px] text-slate-500">custom: {period} to {String(filters.to ?? "now")}</span> : null}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] text-slate-500">Rows per section</label>
                <div className="flex flex-wrap gap-1.5">
                  {TOPS.map((n) => <Choice key={n} active={top === n} onClick={() => set("top", n)}>{n}</Choice>)}
                </div>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-slate-500" htmlFor="rb-user">Only this user (optional)</label>
                <Input value={String(filters.user ?? "")} placeholder="user name"
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => set("user", e.target.value.trim())} />
              </div>
            </div>
          </Section>

          <Section title={initial ? "Output" : "4. Output"} hint="Press Enter after an address to add it. Recipients get the report by e-mail when it runs.">
            <div className="flex flex-wrap gap-1.5">
              {FORMATS.map(([value, label]) => <Choice key={value} active={format === value} onClick={() => setFormat(value)}>{label}</Choice>)}
            </div>
            <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-white/10 bg-black/25 p-1.5">
              {recipients.map((r) => (
                <span key={r} className="inline-flex items-center gap-1 rounded-md bg-white/[0.06] px-2 py-0.5 text-xs text-slate-200">
                  {r}
                  <button type="button" className="text-slate-500 hover:text-rose-300" aria-label={`Remove ${r}`} onClick={() => setRecipients(recipients.filter((x) => x !== r))}>x</button>
                </span>
              ))}
              <input
                value={recipientText}
                onChange={(e) => setRecipientText(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === "," || e.key === " ") { e.preventDefault(); addRecipients(recipientText); } }}
                onBlur={() => addRecipients(recipientText)}
                placeholder={recipients.length ? "add another" : "name@company.com"}
                className="min-w-[10rem] flex-1 bg-transparent px-1.5 py-1 text-xs text-slate-200 outline-none placeholder:text-slate-600"
              />
            </div>
          </Section>

          <section>
            <button type="button" onClick={() => setShowMore(!showMore)} className="text-xs text-sky-300 hover:text-sky-200" aria-expanded={showMore}>
              {showMore ? "Hide" : "Show"} advanced filters (action, log type, category, device, ...)
            </button>
            {showMore ? (
              <div className="mt-2">
                <ReportFilterBuilder filters={filters} onChange={setFilters} />
              </div>
            ) : null}
          </section>
        </div>

        <footer className="shrink-0 border-t border-white/[0.06] px-5 py-3">
          {error ? <p role="alert" className="mb-2 text-xs text-rose-300">{error}</p> : null}
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Button type="button" variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
            <Button type="button" variant="secondary" onClick={() => void submit(false)} disabled={busy}>Save</Button>
            <Button type="button" onClick={() => void submit(true)} disabled={busy}>{busy ? "Working..." : "Save and run now"}</Button>
          </div>
        </footer>
      </div>
    </div>
  );
}
