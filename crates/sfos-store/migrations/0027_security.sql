-- v1.5.0: security analytics (findings from anomaly / brute-force / port-scan / threat-intel detectors).
CREATE TABLE IF NOT EXISTS security_findings (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind         text NOT NULL,
    severity     text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    subject      text NOT NULL,
    detail       text NOT NULL DEFAULT '',
    day          date NOT NULL,
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    count        bigint NOT NULL DEFAULT 1,
    acknowledged boolean NOT NULL DEFAULT false,
    UNIQUE (tenant_id, kind, subject, day)
);
CREATE INDEX IF NOT EXISTS security_findings_recent_idx ON security_findings (tenant_id, last_seen DESC);

-- Threat-intel indicators (IP or domain) imported by the admin; matched against recent events.
CREATE TABLE IF NOT EXISTS threat_intel (
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    indicator text NOT NULL,
    kind      text NOT NULL CHECK (kind IN ('ip', 'domain')),
    source    text NOT NULL DEFAULT 'manual',
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, indicator)
);

ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_condition_type_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_condition_type_check CHECK (
    condition_type IN ('threat', 'blocked_category', 'large_transfer', 'user_bandwidth', 'site_visits', 'no_logs',
                       'anomaly', 'bruteforce', 'portscan', 'intel_match')
);
