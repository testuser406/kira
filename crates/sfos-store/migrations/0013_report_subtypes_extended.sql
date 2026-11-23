-- 0012 added report_schedules.report_subtype (plain text). Constrain it to the 13 report types.
ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS report_subtype text;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'report_schedules_report_subtype_check') THEN
        ALTER TABLE report_schedules ADD CONSTRAINT report_schedules_report_subtype_check
        CHECK (report_subtype IS NULL OR report_subtype IN (
            'user', 'department', 'safeguarding', 'websites_allowed_blocked',
            'activity_timeline', 'internet_searches', 'youtube_videos',
            'online_productivity', 'firewall_policy', 'security_threat',
            'network_bandwidth', 'vpn_connections', 'subnet'
        )) NOT VALID;
    END IF;
END $$;

-- Index for filtering
CREATE INDEX IF NOT EXISTS report_schedules_report_subtype_idx 
ON report_schedules (report_subtype) WHERE report_subtype IS NOT NULL;

-- Also add report_subtype to report_results for filtering by type
ALTER TABLE report_results 
ADD COLUMN IF NOT EXISTS report_subtype text;

-- Add department mapping table for user->department mapping (for department reports)
CREATE TABLE IF NOT EXISTS user_department_map (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_identifier text NOT NULL,  -- username or IP pattern
    department text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_department_map_tenant_id_idx ON user_department_map (tenant_id);
CREATE INDEX IF NOT EXISTS user_department_map_user_identifier_idx ON user_department_map (user_identifier);

-- Insert default templates for the new report subtypes
INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'User Activity Report', 'Activity summary by user', 'user_activity',
       '{"from": "24h", "to": "now", "group": "user", "report_subtype": "user"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Department Activity Report', 'Activity by department/OU', 'department',
       '{"from": "24h", "to": "now", "report_subtype": "department"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Student Safeguarding Report', 'Search terms, YouTube, social media access', 'safeguarding',
       '{"from": "24h", "to": "now", "report_subtype": "safeguarding"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Allowed/Blocked Websites', 'Web destinations by action', 'websites',
       '{"from": "24h", "to": "now", "report_subtype": "websites_allowed_blocked"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Activity Timeline', 'User activity over time', 'activity',
       '{"from": "24h", "to": "now", "report_subtype": "activity_timeline"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Internet Searches', 'Search engine queries', 'searches',
       '{"from": "24h", "to": "now", "report_subtype": "internet_searches"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'YouTube Videos', 'YouTube video views and searches', 'youtube',
       '{"from": "24h", "to": "now", "report_subtype": "youtube_videos"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Online Productivity', 'Productive vs non-productive time', 'productivity',
       '{"from": "24h", "to": "now", "report_subtype": "online_productivity"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Firewall Policy Report', 'Policy usage and hits', 'firewall',
       '{"from": "24h", "to": "now", "report_subtype": "firewall_policy"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Security & Threat Report', 'Threats, blocks, anomalies', 'security',
       '{"from": "24h", "to": "now", "report_subtype": "security_threat"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Network Bandwidth Report', 'Bandwidth by user/app/category', 'bandwidth',
       '{"from": "24h", "to": "now", "report_subtype": "network_bandwidth"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'VPN Connections Report', 'VPN session details', 'vpn',
       '{"from": "24h", "to": "now", "report_subtype": "vpn_connections"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;

INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
SELECT t.id, 'Subnet Report', 'Traffic by source/destination subnet', 'network',
       '{"from": "24h", "to": "now", "report_subtype": "subnet"}'::jsonb
FROM tenants t WHERE t.slug = 'default'
ON CONFLICT DO NOTHING;
