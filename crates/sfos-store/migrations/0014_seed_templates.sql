-- Seed the default report templates for a tenant. Earlier migrations seeded only the
-- 'default' tenant if it already existed, which is never true on a fresh database
-- (tenants are created after migrations run). ensure_tenant() now calls this.
CREATE OR REPLACE FUNCTION seed_default_report_templates(p_tenant uuid) RETURNS void AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM report_templates WHERE tenant_id = p_tenant) THEN
        RETURN;
    END IF;
    INSERT INTO report_templates (tenant_id, name, description, category, default_filters)
    SELECT p_tenant, v.name, v.description, v.category, v.filters
    FROM (VALUES
        ('Top Blocked Sites', 'Most frequently blocked web destinations', 'web_filter', '{"action": "blocked", "group": "destination", "from": "24h", "to": "now"}'::jsonb),
        ('Top Threat Events', 'Highest severity threat detections', 'security', '{"category_group": "threat", "from": "24h", "to": "now"}'::jsonb),
        ('User Activity Summary', 'Activity by user over the last 7 days', 'user_activity', '{"from": "7d", "to": "now", "group": "user"}'::jsonb),
        ('Bandwidth by Category', 'Data transfer volume by web category', 'bandwidth', '{"from": "24h", "to": "now", "group": "category"}'::jsonb),
        ('User Activity Report', 'Activity summary by user', 'user_activity', '{"from": "24h", "to": "now", "group": "user", "report_subtype": "user"}'::jsonb),
        ('Department Activity Report', 'Activity by department/OU', 'department', '{"from": "24h", "to": "now", "report_subtype": "department"}'::jsonb),
        ('Student Safeguarding Report', 'Search terms, YouTube, social media access', 'safeguarding', '{"from": "24h", "to": "now", "report_subtype": "safeguarding"}'::jsonb),
        ('Allowed/Blocked Websites', 'Web destinations by action', 'websites', '{"from": "24h", "to": "now", "report_subtype": "websites_allowed_blocked"}'::jsonb),
        ('Activity Timeline', 'User activity over time', 'activity', '{"from": "24h", "to": "now", "report_subtype": "activity_timeline"}'::jsonb),
        ('Internet Searches', 'Search engine queries', 'searches', '{"from": "24h", "to": "now", "report_subtype": "internet_searches"}'::jsonb),
        ('YouTube Videos', 'YouTube video views and searches', 'youtube', '{"from": "24h", "to": "now", "report_subtype": "youtube_videos"}'::jsonb),
        ('Online Productivity', 'Productive vs non-productive time', 'productivity', '{"from": "24h", "to": "now", "report_subtype": "online_productivity"}'::jsonb),
        ('Firewall Policy Report', 'Policy usage and hits', 'firewall', '{"from": "24h", "to": "now", "report_subtype": "firewall_policy"}'::jsonb),
        ('Security & Threat Report', 'Threats, blocks, anomalies', 'security', '{"from": "24h", "to": "now", "report_subtype": "security_threat"}'::jsonb),
        ('Network Bandwidth Report', 'Bandwidth by user/app/category', 'bandwidth', '{"from": "24h", "to": "now", "report_subtype": "network_bandwidth"}'::jsonb),
        ('VPN Connections Report', 'VPN session details', 'vpn', '{"from": "24h", "to": "now", "report_subtype": "vpn_connections"}'::jsonb),
        ('Subnet Report', 'Traffic by source/destination subnet', 'network', '{"from": "24h", "to": "now", "report_subtype": "subnet"}'::jsonb)
    ) AS v(name, description, category, filters);
END;
$$ LANGUAGE plpgsql;

-- Backfill existing tenants that have no templates.
SELECT seed_default_report_templates(id) FROM tenants;
