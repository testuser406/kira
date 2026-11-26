-- v0.7.0: allow the new alert condition types.
ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_condition_type_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_condition_type_check CHECK (
    condition_type IN ('threat', 'blocked_category', 'large_transfer', 'user_bandwidth', 'site_visits', 'no_logs')
);
