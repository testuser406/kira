-- v1.6.0: one ready-to-run custom report per report template, created once per tenant.
-- Reports are saved definitions (not scheduled); delete or edit them freely, they are not re-created.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS custom_reports_seeded boolean NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION seed_default_custom_reports(p_tenant uuid) RETURNS void AS $$
BEGIN
    IF (SELECT custom_reports_seeded FROM tenants WHERE id = p_tenant) THEN
        RETURN;
    END IF;
    PERFORM seed_default_report_templates(p_tenant);
    INSERT INTO report_schedules (tenant_id, name, description, cron_schedule, format, recipients, filters,
                                  report_type, report_subtype, enabled)
    SELECT p_tenant, t.name, t.description, '', 'pdf', '[]'::jsonb,
           t.default_filters || '{"top": 15}'::jsonb,
           'custom', t.default_filters ->> 'report_subtype', false
    FROM report_templates t
    WHERE t.tenant_id = p_tenant
      AND NOT EXISTS (SELECT 1 FROM report_schedules r
                      WHERE r.tenant_id = p_tenant AND r.report_type = 'custom' AND r.name = t.name)
    ORDER BY t.created_at, t.name;
    UPDATE tenants SET custom_reports_seeded = true WHERE id = p_tenant;
END;
$$ LANGUAGE plpgsql;

SELECT seed_default_custom_reports(id) FROM tenants;
