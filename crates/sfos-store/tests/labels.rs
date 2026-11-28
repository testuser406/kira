//! Runs only when `TEST_DATABASE_URL` points at a throwaway Postgres.
use sfos_store::Store;

#[tokio::test]
async fn labels_learn_from_web_and_report_destinations() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping");
        return;
    };
    let store = Store::connect(&url, 4).expect("connect");
    store.migrate().await.expect("migrate");
    store.ensure_partitions(2).await.expect("partitions");
    let t = store
        .ensure_tenant("labels-test", "Labels test")
        .await
        .expect("tenant");
    let c = store.pool().get().await.expect("client");
    c.execute("DELETE FROM ip_labels", &[])
        .await
        .expect("clean");
    c.execute("DELETE FROM events WHERE tenant_id = $1", &[&t.id])
        .await
        .expect("clean events");
    c.execute(
        "INSERT INTO events (tenant_id, ts, log_type, category_group, dst_ip, dst_port, protocol,
                             domain, category, sent_bytes, recv_bytes, user_name)
         VALUES
          ($1, now(), 'Content Filtering', 'Web', '203.0.113.7', 443, 'TCP', 'rr1.googlevideo.com', NULL, 0, 0, 'alice'),
          ($1, now(), 'Content Filtering', 'Web', '198.51.100.9', 443, 'TCP', 'www.shop.example.co.uk', 'Shopping', 0, 0, 'bob'),
          ($1, now(), 'Content Filtering', 'Web', '10.0.0.8', 80, 'TCP', 'intranet.local', NULL, 0, 0, 'bob'),
          ($1, now(), 'Firewall', 'Firewall', '203.0.113.7', 443, 'TCP', NULL, NULL, 100, 900, 'alice'),
          ($1, now(), 'Firewall', 'Firewall', '192.0.2.50', 4443, 'TCP', NULL, NULL, 10, 20, 'alice'),
          ($1, now(), 'Firewall', 'Firewall', '192.0.2.50', 4443, 'TCP', NULL, NULL, 10, 20, 'bob')",
        &[&t.id],
    )
    .await
    .expect("seed events");

    let learned = store.learn_ip_labels_from_web(20).await.expect("learn");
    assert_eq!(learned, 2, "private destinations are skipped");
    let labels = store.load_ip_labels().await.expect("labels");
    let get = |ip: &str| labels.iter().find(|l| l.0 == ip).cloned();
    assert_eq!(
        get("203.0.113.7").map(|l| (l.1, l.2)),
        Some(("YouTube".into(), "Streaming Media".into()))
    );
    // Unknown host: registrable domain as the application, the firewall's web category kept.
    assert_eq!(
        get("198.51.100.9").map(|l| (l.1, l.2)),
        Some(("example.co.uk".into(), "Shopping".into()))
    );

    // Only the still-unlabelled address is queued for lookup.
    let todo = store.unlabelled_destinations(30, 10).await.expect("todo");
    assert_eq!(todo, vec!["192.0.2.50".to_string()]);

    // Manual labels win over learners.
    store
        .save_ip_label("192.0.2.50", None, "Payroll", "Business", "manual")
        .await
        .expect("manual");
    store
        .save_ip_label("192.0.2.50", Some("x.test"), "Other", "Other", "ptr")
        .await
        .expect("learner");
    let labels = store.load_ip_labels().await.expect("labels");
    assert_eq!(
        labels
            .iter()
            .find(|l| l.0 == "192.0.2.50")
            .map(|l| l.1.clone()),
        Some("Payroll".to_string())
    );

    let all = store
        .top_destinations(t.id, 60, 50, false)
        .await
        .expect("all");
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].ip, "203.0.113.7");
    assert_eq!(all[0].bytes, 1000);
    assert_eq!(all[1].users, 2);
    assert_eq!(all[1].service, None);
    let unknown = store
        .top_destinations(t.id, 60, 50, true)
        .await
        .expect("unknown");
    assert!(unknown.is_empty(), "everything is labelled now");
    assert_eq!(store.delete_ip_label("192.0.2.50").await.expect("del"), 1);
    let unknown = store
        .top_destinations(t.id, 60, 50, true)
        .await
        .expect("unknown");
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].ip, "192.0.2.50");
}

#[tokio::test]
async fn default_custom_reports_are_seeded_once() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping");
        return;
    };
    let store = Store::connect(&url, 4).expect("connect");
    store.migrate().await.expect("migrate");
    let slug = format!("seed-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let t = store
        .ensure_tenant(&slug, "Seed test")
        .await
        .expect("tenant");
    let c = store.pool().get().await.expect("client");
    let templates: i64 = c
        .query_one(
            "SELECT count(*)::bigint FROM report_templates WHERE tenant_id = $1",
            &[&t.id],
        )
        .await
        .expect("templates")
        .get(0);
    assert!(templates > 0);
    assert_eq!(count(&c, t.id).await, templates);
    // Re-running ensure_tenant must not duplicate them, and deleting one must not bring it back.
    store
        .ensure_tenant("seed-test", "Seed test")
        .await
        .expect("again");
    assert_eq!(count(&c, t.id).await, templates);
    let disabled: i64 = c
        .query_one(
            "SELECT count(*)::bigint FROM report_schedules
             WHERE tenant_id = $1 AND report_type = 'custom' AND enabled = false AND cron_schedule = ''",
            &[&t.id],
        )
        .await
        .expect("disabled")
        .get(0);
    assert_eq!(
        disabled, templates,
        "seeded reports never schedule themselves"
    );
    c.execute(
        "DELETE FROM report_schedules WHERE id = (SELECT id FROM report_schedules
         WHERE tenant_id = $1 AND report_type = 'custom' LIMIT 1)",
        &[&t.id],
    )
    .await
    .expect("delete one");
    store
        .ensure_tenant("seed-test", "Seed test")
        .await
        .expect("again 2");
    assert_eq!(count(&c, t.id).await, templates - 1);
}

async fn count(c: &deadpool_postgres::Client, tenant: uuid::Uuid) -> i64 {
    c.query_one(
        "SELECT count(*)::bigint FROM report_schedules
         WHERE tenant_id = $1 AND report_type = 'custom'",
        &[&tenant],
    )
    .await
    .expect("count")
    .get(0)
}
