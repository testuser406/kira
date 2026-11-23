import { useMemo } from "react";
import { Button, Card, Input, Select } from "./ui";


export type ReportFilters = {
  q?: string;
  from?: string;
  to?: string;
  action?: string;
  group?: string;
  user?: string;
  category?: string;
  device?: string;
  dimension?: string;
  limit?: number;
  offset?: number;
  // Advanced
  category_type?: string;
  application?: string;
  threat?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  src_country?: string;
  dst_country?: string;
  src_zone?: string;
  dst_zone?: string;
  user_group?: string;
  policy_type?: string;
  fw_rule_id?: string;
  fw_rule_name?: string;
  sent_bytes_min?: number;
  sent_bytes_max?: number;
  recv_bytes_min?: number;
  recv_bytes_max?: number;
  threat_name?: string;
  message_contains?: string;
  url_contains?: string;
  domain_contains?: string;
  vpn_user?: string;
  vpn_tunnel?: string;
};

export function ReportFilterBuilder({
  filters,
  onChange,
  showAdvanced = true,
}: {
  filters: ReportFilters;
  onChange: (filters: ReportFilters) => void;
  compact?: boolean;
  showAdvanced?: boolean;
}) {
  const handleChange = (key: keyof ReportFilters, value: any) => {
    const next = { ...filters, [key]: value || undefined };
    Object.keys(next).forEach((k) => (next as Record<string, unknown>)[k] === undefined && delete (next as Record<string, unknown>)[k]);
    onChange(next as ReportFilters);
  };

  const resetFilters = () => {
    onChange({ from: "24h", to: "now", limit: 10000 });
  };

  const hasActiveFilters = useMemo(() => {
    return Object.entries(filters).some(([k, v]) => {
      if (k === "from" && v === "24h") return false;
      if (k === "to" && v === "now") return false;
      if (k === "limit" && v === 10000) return false;
      return v != null && v !== "";
    });
  }, [filters]);

  return (
    <Card className="overflow-hidden">
      <div className="px-4 py-3 border-b border-white/[0.06] flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-slate-100">Report Filters</h3>
        <div className="flex items-center gap-2">
          {hasActiveFilters && (
            <Button variant="secondary" size="sm" onClick={resetFilters}>
              Clear all
            </Button>
          )}
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Row 1: Time range + Search */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <label className="block text-xs text-slate-500 mb-1">From</label>
            <Select
              value={filters.from || "24h"}
              onChange={(e) => handleChange("from", e.target.value)}
            >
              <option value="1h">Last 1 hour</option>
              <option value="6h">Last 6 hours</option>
              <option value="12h">Last 12 hours</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="90d">Last 90 days</option>
            </Select>
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">To</label>
            <Select
              value={filters.to || "now"}
              onChange={(e) => handleChange("to", e.target.value)}
            >
              <option value="now">Now</option>
              <option value="1h">1 hour ago</option>
              <option value="6h">6 hours ago</option>
              <option value="12h">12 hours ago</option>
              <option value="24h">24 hours ago</option>
              <option value="7d">7 days ago</option>
              <option value="30d">30 days ago</option>
            </Select>
          </div>
          <div className="lg:col-span-2">
            <label className="block text-xs text-slate-500 mb-1">Search (user, domain, URL, IP, rule, threat...)</label>
            <Input
              placeholder="Search..."
              value={filters.q || ""}
              onChange={(e) => handleChange("q", e.target.value)}
            />
          </div>
        </div>

        {/* Row 2: Core filters */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Action</label>
            <Select
              value={filters.action || ""}
              onChange={(e) => handleChange("action", e.target.value || undefined)}
            >
              <option value="">All</option>
              {["allowed", "blocked", "warned"].map((a) => <option key={a} value={a}>{a}</option>)}
            </Select>
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Log Type</label>
            <Select
              value={filters.group || ""}
              onChange={(e) => handleChange("group", e.target.value || undefined)}
            >
              <option value="">All</option>
              {["web", "threat", "firewall", "auth", "vpn", "system", "other"].map((g) => <option key={g} value={g}>{g}</option>)}
            </Select>
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">User</label>
            <Input
              placeholder="Filter user..."
              value={filters.user || ""}
              onChange={(e) => handleChange("user", e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Category</label>
            <Input
              placeholder="Filter category..."
              value={filters.category || ""}
              onChange={(e) => handleChange("category", e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Device</label>
            <Input
              placeholder="Filter device..."
              value={filters.device || ""}
              onChange={(e) => handleChange("device", e.target.value)}
            />
          </div>
        </div>

        {showAdvanced && (
          <>
            <hr className="border-white/[0.06]" />
            <p className="text-xs font-medium text-slate-400">Advanced Filters</p>

            {/* Row 3: Network filters */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
              <div>
                <label className="block text-xs text-slate-500 mb-1">Source IP</label>
                <Input
                  placeholder="192.168.x.x"
                  value={filters.src_ip || ""}
                  onChange={(e) => handleChange("src_ip", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Dest IP</label>
                <Input
                  placeholder="8.8.8.8"
                  value={filters.dst_ip || ""}
                  onChange={(e) => handleChange("dst_ip", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Source Port</label>
                <Input
                  type="number"
                  placeholder="51234"
                  value={filters.src_port?.toString() || ""}
                  onChange={(e) => handleChange("src_port", e.target.value ? parseInt(e.target.value) : undefined)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Dest Port</label>
                <Input
                  type="number"
                  placeholder="443"
                  value={filters.dst_port?.toString() || ""}
                  onChange={(e) => handleChange("dst_port", e.target.value ? parseInt(e.target.value) : undefined)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Protocol</label>
                <Select
                  value={filters.protocol || ""}
                  onChange={(e) => handleChange("protocol", e.target.value || undefined)}
                >
                  <option value="">All</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                </Select>
              </div>
            </div>

            {/* Row 4: Geo & Content filters */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
              <div>
                <label className="block text-xs text-slate-500 mb-1">Source Country</label>
                <Input
                  placeholder="US, CN, etc."
                  value={filters.src_country || ""}
                  onChange={(e) => handleChange("src_country", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Dest Country</label>
                <Input
                  placeholder="US, CN, etc."
                  value={filters.dst_country || ""}
                  onChange={(e) => handleChange("dst_country", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Application</label>
                <Input
                  placeholder="Chrome, YouTube, etc."
                  value={filters.application || ""}
                  onChange={(e) => handleChange("application", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Category Type</label>
                <Input
                  placeholder="Acceptable, Unacceptable..."
                  value={filters.category_type || ""}
                  onChange={(e) => handleChange("category_type", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Threat Name</label>
                <Input
                  placeholder="EICAR, malware name..."
                  value={filters.threat_name || ""}
                  onChange={(e) => handleChange("threat_name", e.target.value)}
                />
              </div>
            </div>

            {/* Row 5: Bytes & Policy filters */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
              <div>
                <label className="block text-xs text-slate-500 mb-1">Sent Bytes Min</label>
                <Input
                  type="number"
                  placeholder="0"
                  value={filters.sent_bytes_min?.toString() || ""}
                  onChange={(e) => handleChange("sent_bytes_min", e.target.value ? parseInt(e.target.value) : undefined)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Sent Bytes Max</label>
                <Input
                  type="number"
                  placeholder="1000000"
                  value={filters.sent_bytes_max?.toString() || ""}
                  onChange={(e) => handleChange("sent_bytes_max", e.target.value ? parseInt(e.target.value) : undefined)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Recv Bytes Min</label>
                <Input
                  type="number"
                  placeholder="0"
                  value={filters.recv_bytes_min?.toString() || ""}
                  onChange={(e) => handleChange("recv_bytes_min", e.target.value ? parseInt(e.target.value) : undefined)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Recv Bytes Max</label>
                <Input
                  type="number"
                  placeholder="1000000"
                  value={filters.recv_bytes_max?.toString() || ""}
                  onChange={(e) => handleChange("recv_bytes_max", e.target.value ? parseInt(e.target.value) : undefined)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Firewall Rule</label>
                <Input
                  placeholder="Rule name or ID"
                  value={filters.fw_rule_name || ""}
                  onChange={(e) => handleChange("fw_rule_name", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Policy Type</label>
                <Input
                  placeholder="Web, Firewall..."
                  value={filters.policy_type || ""}
                  onChange={(e) => handleChange("policy_type", e.target.value)}
                />
              </div>
            </div>

            {/* Row 6: VPN & Threat filters */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <label className="block text-xs text-slate-500 mb-1">VPN User</label>
                <Input
                  placeholder="vpn_user"
                  value={filters.vpn_user || ""}
                  onChange={(e) => handleChange("vpn_user", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">VPN Tunnel</label>
                <Input
                  placeholder="tunnel_name"
                  value={filters.vpn_tunnel || ""}
                  onChange={(e) => handleChange("vpn_tunnel", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Message Contains</label>
                <Input
                  placeholder="Error, denied, timeout..."
                  value={filters.message_contains || ""}
                  onChange={(e) => handleChange("message_contains", e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">URL Contains</label>
                <Input
                  placeholder="/path?query=value"
                  value={filters.url_contains || ""}
                  onChange={(e) => handleChange("url_contains", e.target.value)}
                />
              </div>
            </div>
          </>
        )}
      </div>

      <div className="px-4 py-3 border-t border-white/[0.06] flex justify-end gap-2">
        <Button variant="secondary" onClick={resetFilters} disabled={!hasActiveFilters}>
          Reset Filters
        </Button>
        <Button onClick={() => onChange({ ...filters, _applied: true } as any)}>
          Apply Filters
        </Button>
      </div>
    </Card>
  );
}
