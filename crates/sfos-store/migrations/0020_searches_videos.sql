-- v0.6.0: internet searches and YouTube videos extracted from web-filter URLs.
CREATE TABLE IF NOT EXISTS web_searches (
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    ts        timestamptz NOT NULL,
    user_key  text NOT NULL,
    engine    text NOT NULL,
    term      text NOT NULL,
    blocked   boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS web_searches_ts_idx ON web_searches (tenant_id, ts DESC);

CREATE TABLE IF NOT EXISTS web_videos (
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    ts        timestamptz NOT NULL,
    user_key  text NOT NULL,
    video_id  text NOT NULL,
    blocked   boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS web_videos_ts_idx ON web_videos (tenant_id, ts DESC);
