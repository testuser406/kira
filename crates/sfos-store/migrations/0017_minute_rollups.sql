-- Per-minute rollups powering the live dashboards (kept ~7 days).
CREATE TABLE IF NOT EXISTS minute_rollups (
    tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    bucket       timestamptz NOT NULL,
    dimension    text NOT NULL,
    key          text NOT NULL,
    events       bigint NOT NULL DEFAULT 0,
    allowed      bigint NOT NULL DEFAULT 0,
    blocked      bigint NOT NULL DEFAULT 0,
    bytes_up     bigint NOT NULL DEFAULT 0,
    bytes_down   bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, bucket, dimension, key)
);

CREATE INDEX IF NOT EXISTS minute_rollups_dim_idx
    ON minute_rollups (tenant_id, dimension, bucket);
