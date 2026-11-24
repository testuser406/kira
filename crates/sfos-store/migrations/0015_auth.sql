-- Dashboard authentication: local users, server-side sessions and an audit trail.
CREATE TABLE IF NOT EXISTS app_users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text NOT NULL,
    password_hash text NOT NULL,
    role          text NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')),
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS app_users_username_lower_idx ON app_users (lower(username));

-- Only a SHA-256 of the session token is stored, never the token itself.
CREATE TABLE IF NOT EXISTS app_sessions (
    token_hash text PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES app_users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    ip         text,
    user_agent text
);
CREATE INDEX IF NOT EXISTS app_sessions_user_idx ON app_sessions (user_id);
CREATE INDEX IF NOT EXISTS app_sessions_expires_idx ON app_sessions (expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id       bigserial PRIMARY KEY,
    ts       timestamptz NOT NULL DEFAULT now(),
    username text,
    action   text NOT NULL,
    detail   text,
    ip       text
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);
