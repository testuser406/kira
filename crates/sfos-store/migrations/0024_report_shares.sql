-- v1.0.0: expiring share links for rendered reports.
CREATE TABLE IF NOT EXISTS report_shares (
    token       text PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    report_type text NOT NULL,
    from_ts     timestamptz NOT NULL,
    to_ts       timestamptz NOT NULL,
    user_key    text,
    top_n       integer NOT NULL DEFAULT 15,
    format      text NOT NULL CHECK (format IN ('pdf', 'csv')),
    masked      boolean NOT NULL DEFAULT false,
    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS report_shares_exp_idx ON report_shares (expires_at);
