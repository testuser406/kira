//! Database integration test. Runs only when `TEST_DATABASE_URL` points at a
//! throwaway Postgres (CI provides one); otherwise it is skipped.
use sfos_store::Store;

#[tokio::test]
async fn migrations_apply_twice_and_seed_templates() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping");
        return;
    };
    let store = Store::connect(&url, 4).expect("connect");
    store.migrate().await.expect("first migrate");
    store.migrate().await.expect("second migrate is a no-op");
    let tenant = store
        .ensure_tenant("default", "Test")
        .await
        .expect("tenant");
    store
        .ensure_tenant("default", "Test")
        .await
        .expect("idempotent");
    let templates = store
        .list_report_templates(tenant.id)
        .await
        .expect("templates");
    assert_eq!(templates.len(), 17, "4 original + 13 report-type templates");

    // Site Clean helpers and default productivity guidelines.
    let client = store.pool().get().await.expect("client");
    let site = |d: &'static str| {
        let client = &client;
        async move {
            client
                .query_one("SELECT sfos_site($1)", &[&d])
                .await
                .expect("site")
                .get::<_, Option<String>>(0)
        }
    };
    assert_eq!(
        site("a.b.example.com").await.as_deref(),
        Some("example.com")
    );
    assert_eq!(site("www.bbc.co.uk").await.as_deref(), Some("bbc.co.uk"));
    assert_eq!(site("10.1.2.3").await.as_deref(), Some("10.1.2.3"));
    assert_eq!(site("localhost").await.as_deref(), Some("localhost"));
    let noise: bool = client
        .query_one("SELECT sfos_is_noise_site('doubleclick.net')", &[])
        .await
        .expect("noise")
        .get(0);
    assert!(noise);
    let seeded: i64 = client
        .query_one(
            "SELECT count(*) FROM productivity_guidelines WHERE tenant_id = $1",
            &[&tenant.id],
        )
        .await
        .expect("count")
        .get(0);
    assert!(seeded >= 15, "default guidelines seeded, got {seeded}");

    // Searches and YouTube views are extracted from URLs during the batch write.
    store.ensure_partitions(2).await.expect("partitions");
    let mk = |url: &str, action| sfos_core::model::Event {
        ts: chrono::Utc::now(),
        user_name: Some("e2e-user".into()),
        src_ip: Some("10.9.9.9".into()),
        url: Some(url.into()),
        action: Some(action),
        ..Default::default()
    };
    let events = vec![
        mk(
            "http://www.google.com/search?q=rust+axum",
            sfos_core::model::Action::Allowed,
        ),
        mk(
            "http://www.youtube.com/watch?v=dQw4w9WgXcQ",
            sfos_core::model::Action::Blocked,
        ),
        mk("http://example.com/", sfos_core::model::Action::Allowed),
    ];
    store
        .copy_events(tenant.id, &events)
        .await
        .expect("copy events");
    let n: i64 = client
        .query_one(
            "SELECT count(*) FROM web_searches WHERE term = 'rust axum' AND user_key = 'e2e-user'",
            &[],
        )
        .await
        .expect("searches")
        .get(0);
    assert_eq!(n, 1);
    let v: i64 = client
        .query_one(
            "SELECT count(*) FROM web_videos WHERE video_id = 'dQw4w9WgXcQ' AND blocked",
            &[],
        )
        .await
        .expect("videos")
        .get(0);
    assert_eq!(v, 1);
}
