-- Destination labels for traffic classification without DPI. Learned from web-filter logs,
-- reverse DNS and the built-in port/host tables; `manual` rows are set by an admin and never
-- overwritten by the learners.
CREATE TABLE IF NOT EXISTS ip_labels (
    ip          text PRIMARY KEY,
    host        text,
    app         text NOT NULL,
    category    text NOT NULL,
    source      text NOT NULL CHECK (source IN ('web', 'ptr', 'manual')),
    seen_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ip_labels_seen_idx ON ip_labels (seen_at);
