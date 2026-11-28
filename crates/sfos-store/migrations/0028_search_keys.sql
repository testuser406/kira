-- v1.5.1: small dictionary of every searchable key, so global search does not scan hourly_activity.
-- Filled by roll_hourly (new keys) and by a one-time background backfill (see store::prepare_search).
CREATE TABLE IF NOT EXISTS search_keys (
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    dimension text NOT NULL,
    key       text NOT NULL,
    last_seen timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, dimension, key)
);
CREATE INDEX IF NOT EXISTS search_keys_seen_idx ON search_keys (tenant_id, last_seen);
