-- v0.5.0: long-term hourly activity (report source), rolled up from minute_rollups.
CREATE TABLE IF NOT EXISTS hourly_activity (
    tenant_id  uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    hour       timestamptz NOT NULL,
    dimension  text NOT NULL,
    key        text NOT NULL,
    events     bigint NOT NULL DEFAULT 0,
    allowed    bigint NOT NULL DEFAULT 0,
    blocked    bigint NOT NULL DEFAULT 0,
    bytes_up   bigint NOT NULL DEFAULT 0,
    bytes_down bigint NOT NULL DEFAULT 0,
    minutes    bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, hour, dimension, key)
);
CREATE INDEX IF NOT EXISTS hourly_activity_dim_idx ON hourly_activity (tenant_id, dimension, hour);

-- Recompute whole hours from minute data. Idempotent: values are replaced, not added.
CREATE OR REPLACE FUNCTION sfos_roll_hours(p_from timestamptz, p_to timestamptz) RETURNS bigint
LANGUAGE sql AS $$
    WITH ins AS (
        INSERT INTO hourly_activity
            (tenant_id, hour, dimension, key, events, allowed, blocked, bytes_up, bytes_down, minutes)
        SELECT tenant_id, date_trunc('hour', bucket), dimension, key,
               sum(events), sum(allowed), sum(blocked), sum(bytes_up), sum(bytes_down),
               count(DISTINCT bucket)
        FROM minute_rollups
        WHERE bucket >= date_trunc('hour', p_from) AND bucket < p_to
        GROUP BY 1, 2, 3, 4
        ON CONFLICT (tenant_id, hour, dimension, key) DO UPDATE SET
            events = EXCLUDED.events, allowed = EXCLUDED.allowed, blocked = EXCLUDED.blocked,
            bytes_up = EXCLUDED.bytes_up, bytes_down = EXCLUDED.bytes_down, minutes = EXCLUDED.minutes
        RETURNING 1)
    SELECT count(*) FROM ins
$$;
