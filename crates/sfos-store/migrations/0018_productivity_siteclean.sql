-- v0.4.0: Site Clean helpers, productivity guidelines.

-- Registrable site for a host name (api.cdn.example.co.uk -> example.co.uk).
CREATE OR REPLACE FUNCTION sfos_site(d text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN d IS NULL OR btrim(d) = '' THEN NULL
        WHEN d ~ '^[0-9.]+$' OR position(':' IN d) > 0 THEN d
        ELSE (
            SELECT CASE
                WHEN n <= 2 THEN array_to_string(p, '.')
                WHEN array_to_string(p[n-1:n], '.') = ANY (ARRAY[
                    'co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.in','com.pk',
                    'net.pk','org.pk','edu.pk','gov.pk','com.br','co.jp','com.tr','com.sa','com.eg',
                    'co.za','com.cn','com.sg','com.my','co.nz','com.hk','com.mx','co.id'])
                    THEN array_to_string(p[n-2:n], '.')
                ELSE array_to_string(p[n-1:n], '.')
            END
            FROM (SELECT string_to_array(lower(rtrim(btrim(d), '.')), '.') AS p) s,
                 LATERAL (SELECT COALESCE(array_length(p, 1), 0) AS n) c
        )
    END
$$;

-- Ads, trackers, CDNs and OS plumbing that are not deliberate browsing.
CREATE OR REPLACE FUNCTION sfos_is_noise_site(site text) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT site = ANY (ARRAY[
        'doubleclick.net','googlesyndication.com','googleadservices.com','google-analytics.com',
        'googletagmanager.com','googletagservices.com','gstatic.com','googleapis.com','gvt1.com',
        'akamaihd.net','akamaized.net','akamai.net','edgekey.net','edgesuite.net','cloudfront.net',
        'fastly.net','fastlylb.net','azureedge.net','trafficmanager.net','msftncsi.com',
        'windowsupdate.com','digicert.com','symcb.com','symcd.com','ocsp.pki.goog','pki.goog',
        'letsencrypt.org','adnxs.com','scorecardresearch.com','criteo.com','taboola.com',
        'outbrain.com','demdex.net','omtrdc.net','2mdn.net','adsrvr.org','amazon-adsystem.com',
        'sophos.com','sophosxl.net','sophosupd.com','cloudflare.com','cloudflare-dns.com'])
$$;

CREATE TABLE IF NOT EXISTS productivity_guidelines (
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind      text NOT NULL CHECK (kind IN ('category', 'application', 'site')),
    key       text NOT NULL,
    class     text NOT NULL CHECK (class IN ('productive', 'neutral', 'unproductive')),
    PRIMARY KEY (tenant_id, kind, key)
);

CREATE OR REPLACE FUNCTION seed_default_productivity(p_tenant uuid) RETURNS void
LANGUAGE sql AS $$
    INSERT INTO productivity_guidelines (tenant_id, kind, key, class)
    SELECT p_tenant, 'category', v.key, v.class FROM (VALUES
        ('Business', 'productive'), ('Information Technology', 'productive'),
        ('Education', 'productive'), ('Search Engines', 'productive'),
        ('Software Updates', 'productive'), ('Web E-Mail', 'productive'),
        ('Government', 'productive'), ('Finance', 'productive'),
        ('Social Networking', 'unproductive'), ('Games', 'unproductive'),
        ('Streaming Media', 'unproductive'), ('Online Shopping', 'unproductive'),
        ('Entertainment', 'unproductive'), ('Gambling', 'unproductive'),
        ('Pornography', 'unproductive'), ('Sports', 'unproductive'),
        ('Peer to Peer', 'unproductive'), ('Hobbies', 'unproductive'),
        ('Instant Messenger', 'neutral'), ('News', 'neutral'), ('Travel', 'neutral')
    ) AS v(key, class)
    ON CONFLICT DO NOTHING
$$;

SELECT seed_default_productivity(id) FROM tenants;
