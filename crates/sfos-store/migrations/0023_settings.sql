-- v0.8.0: small key/value runtime settings (admin-editable).
CREATE TABLE IF NOT EXISTS app_settings (
    key   text PRIMARY KEY,
    value text NOT NULL
);
