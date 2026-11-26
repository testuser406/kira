-- v0.7.0: per-rule e-mail recipients and webhook format (json | text for Zulip/Slack/Mattermost).
CREATE TABLE IF NOT EXISTS alert_notify (
    rule_id        uuid PRIMARY KEY REFERENCES alert_rules (id) ON DELETE CASCADE,
    email_to       text NOT NULL DEFAULT '',
    webhook_format text NOT NULL DEFAULT 'json' CHECK (webhook_format IN ('json', 'text'))
);
