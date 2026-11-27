-- Add more real Sophos web categories to the default productivity guidelines.
CREATE OR REPLACE FUNCTION seed_default_productivity(p_tenant uuid) RETURNS void
LANGUAGE sql AS $$
    INSERT INTO productivity_guidelines (tenant_id, kind, key, class)
    SELECT p_tenant, 'category', v.key, v.class FROM (VALUES
        ('Business', 'productive'), ('General Business', 'productive'),
        ('Information Technology', 'productive'), ('Computing & Internet', 'productive'),
        ('Education', 'productive'), ('Search Engines', 'productive'),
        ('Software Updates', 'productive'), ('Web E-Mail', 'productive'),
        ('Government', 'productive'), ('Finance', 'productive'),
        ('Web Hosting', 'productive'), ('Reference', 'productive'),
        ('Social Networking', 'unproductive'), ('Games', 'unproductive'),
        ('Streaming Media', 'unproductive'), ('Online Shopping', 'unproductive'),
        ('Entertainment', 'unproductive'), ('Gambling', 'unproductive'),
        ('Pornography', 'unproductive'), ('Sports', 'unproductive'),
        ('Peer to Peer', 'unproductive'), ('Hobbies', 'unproductive'),
        ('Instant Messenger', 'neutral'), ('News', 'neutral'), ('Travel', 'neutral'),
        ('Content Delivery Networks', 'neutral'), ('Advertisements', 'neutral')
    ) AS v(key, class)
    ON CONFLICT DO NOTHING
$$;

SELECT seed_default_productivity(id) FROM tenants;
